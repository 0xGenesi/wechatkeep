#!/usr/bin/env python3
"""
backfill_expected.py — 为隔离区条目（缺 expected 溯源字节）回填原始字节。

隔离条目默认被引擎拒写（quarantine）。回填来源：zsbai/wechat-versions 归档的
官方 dmg → 提取 wechat.dylib → 按条目 (arch, addr) 现场读取原始字节。

用法:
  python3 tools/backfill_expected.py --config config.json --limit 3 [--dry-run]
  python3 tools/backfill_expected.py --config config.json --dylib <本地dylib> --version <构建号>
                                     # 后者用于本地验证逻辑（跳过下载）

安全: 只读官方归档与本地 dylib；写回前自动备份 config。
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ARCH_CPU = {"arm64": ["-arch", "arm64"], "x86_64": ["-arch", "x86_64"]}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def read_bytes_at(dylib, arch, addr_hex, count):
    """lipo -thin 抽 slice 后按 VA==offset 读 count 字节（本镜像族恒等）。"""
    with tempfile.NamedTemporaryFile(suffix=".thin", delete=False) as f:
        thin = f.name
    try:
        r = run(["/usr/bin/lipo", "-thin", arch, dylib, "-output", thin])
        if r.returncode != 0:
            return None
        data = open(thin, "rb").read()
        offset = int(addr_hex, 16)
        if offset + count > len(data):
            return None
        return data[offset:offset + count]
    finally:
        os.unlink(thin)


def archive_releases():
    """zsbai 归档全部 release（tag 是展示版本号，body 无构建号——构建号
    只能挂载 dmg 读 CFBundleVersion）。返回 [(tag, dmg_url), ...] 从新到旧。"""
    out = []
    for page in (1, 2, 3):
        url = (f"https://api.github.com/repos/zsbai/wechat-versions/releases"
               f"?per_page=100&page={page}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wxkeep-backfill"})
            with urllib.request.urlopen(req, timeout=30) as r:
                rels = json.load(r)
        except Exception as e:
            print(f"  归档列表拉取失败(page {page}): {e}")
            break
        if not rels:
            break
        for rel in rels:
            for a in rel.get("assets", []):
                if a["name"].endswith(".dmg"):
                    out.append((rel["tag_name"], a["browser_download_url"]))
    return out


def mount_read_build_and_extract(dmg_path):
    """挂载 dmg → 读 WeChat.app 的 CFBundleVersion（构建号）→ 拷出 wechat.dylib。
    返回 (dylib_path, build) 或 (None, build) 或 (None, None)。"""
    mount = tempfile.mkdtemp(prefix="wxkeep-mount-")
    r = run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly",
             "-mountpoint", mount, dmg_path])
    if r.returncode != 0:
        shutil.rmtree(mount, ignore_errors=True)
        return None, None
    try:
        app = None
        dylib = None
        for root, dirs, files in os.walk(mount):
            if "Info.plist" in files and root.endswith(".app/Contents"):
                app = os.path.dirname(root)
            if "wechat.dylib" in files:
                dylib = os.path.join(root, "wechat.dylib")
        build = None
        if app:
            b = run(["/usr/bin/defaults", "read",
                     os.path.join(app, "Info.plist"), "CFBundleVersion"])
            if b.returncode == 0:
                build = b.stdout.strip()
        if not dylib:
            return None, build
        out = tempfile.NamedTemporaryFile(prefix="wxkeep-dylib-", delete=False)
        out.close()
        shutil.copy2(dylib, out.name)
        return out.name, build
    finally:
        run(["/usr/bin/hdiutil", "detach", mount, "-force"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--limit", type=int, default=3, help="本次最多处理的构建号数")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dylib", help="本地 dylib（跳过下载，逻辑验证用）")
    ap.add_argument("--version", help="配合 --dylib 指定构建号")
    args = ap.parse_args()

    cfg = json.load(open(args.config))

    # 收集隔离条目: version -> [(target_idx, entry_idx, arch, addr, asm_len)]
    quarantined = {}
    for vi, v in enumerate(cfg):
        for ti, t in enumerate(v["targets"]):
            for ei, e in enumerate(t["entries"]):
                if not e.get("expected"):
                    quarantined.setdefault(v["version"], []).append((vi, ti, ei, e))

    if not quarantined:
        print("隔离区为空，无需回填")
        return

    print(f"隔离区: {len(quarantined)} 个构建号, "
          f"{sum(len(x) for x in quarantined.values())} 条 entry")

    todo = {}
    if args.dylib and args.version:
        todo[args.version] = args.dylib
    else:
        releases = archive_releases()
        print(f"  归档 release: {len(releases)} 个")
        # tag→build 缓存（.wxkeep-tagmap.json），一次探明终身受用
        cachepath = os.path.join(os.path.dirname(os.path.abspath(args.config)),
                                 ".wxkeep-tagmap.json")
        tagmap = {}
        if os.path.exists(cachepath):
            try:
                tagmap = json.load(open(cachepath))
            except Exception:
                tagmap = {}
        for version in sorted(quarantined, key=lambda x: int(x) if x.isdigit() else 0,
                              reverse=True)[:args.limit]:
            # 候选：缓存命中的 tag 优先，其余按归档顺序（新→旧）
            hit_tag = next((t for t, b in tagmap.items() if b == version), None)
            candidates = ([hit_tag] if hit_tag else []) + \
                         [t for t, _ in releases if t != hit_tag]
            done = False
            for tag in candidates:
                url = next((u for t, u in releases if t == tag), None)
                if not url:
                    continue
                if tag in tagmap and tagmap[tag] != version and hit_tag is None:
                    continue  # 已知不匹配且非命中项
                dmg = tempfile.NamedTemporaryFile(prefix="wxkeep-", suffix=".dmg", delete=False)
                dmg.close()
                print(f"  [{version}] 尝试 {tag} …")
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "wxkeep-backfill"})
                    with urllib.request.urlopen(req, timeout=900) as r, open(dmg.name, "wb") as f:
                        shutil.copyfileobj(r, f)
                    dylib, build = mount_read_build_and_extract(dmg.name)
                finally:
                    os.unlink(dmg.name)
                if build:
                    tagmap[tag] = build
                    json.dump(tagmap, open(cachepath, "w"))
                if build == version and dylib:
                    todo[version] = dylib
                    done = True
                    break
                if dylib:
                    os.unlink(dylib)
            if not done:
                print(f"  [{version}] 归档中未找到匹配构建号")

    if args.dry_run:
        print("dry-run: 不写回")
        return

    filled = missed = 0
    for version, dylib in todo.items():
        entries = quarantined[version]
        cache = {}
        for vi, ti, ei, e in entries:
            count = len(bytes.fromhex(e["asm"]))
            key = e["arch"]
            if key not in cache:
                # 同一 arch 的 slice 只抽一次：临时文件按 arch 缓存
                cache[key] = dylib
            raw = read_bytes_at(dylib, e["arch"], e["addr"], count)
            if raw is None:
                print(f"  [{version}] {e['arch']}@{e['addr']}: 读取失败")
                missed += 1
                continue
            cfg[vi]["targets"][ti]["entries"][ei]["expected"] = [raw.hex().upper()]
            # 回填后去掉隔离 note 里这一条的影响（note 保留，版本级重算由 merge 脚本管）
            filled += 1
        os.unlink(dylib)
        print(f"  [{version}] 回填完成")

    bak = args.config + ".bak." + time.strftime("%Y%m%d%H%M%S")
    shutil.copy(args.config, bak)
    json.dump(cfg, open(args.config, "w"), indent=2, ensure_ascii=False)
    print(f"回填 {filled} 条, 失败 {missed} 条; 备份 {bak}")


if __name__ == "__main__":
    main()
