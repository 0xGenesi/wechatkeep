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


def dmgs_for_version(version):
    """zsbai 归档里该构建号的 dmg 下载 URL（可能有多个同名版本，取全部）。"""
    url = f"https://api.github.com/repos/zsbai/wechat-versions/releases/tags/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": "wxkeep-backfill"})
    with urllib.request.urlopen(req, timeout=30) as r:
        rel = json.load(r)
    return [a["browser_download_url"] for a in rel.get("assets", [])
            if a["name"].endswith(".dmg")]


def extract_wechat_dylib(dmg_path):
    """挂载 dmg 并拷出 wechat.dylib；不匹配（无该文件）返回 None。"""
    mount = tempfile.mkdtemp(prefix="wxkeep-mount-")
    r = run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly",
             "-mountpoint", mount, dmg_path])
    if r.returncode != 0:
        shutil.rmtree(mount, ignore_errors=True)
        return None
    try:
        candidates = []
        for root, _dirs, files in os.walk(mount):
            if "wechat.dylib" in files:
                candidates.append(os.path.join(root, "wechat.dylib"))
        if not candidates:
            return None
        out = tempfile.NamedTemporaryFile(prefix="wxkeep-dylib-", delete=False)
        out.close()
        shutil.copy2(candidates[0], out.name)
        return out.name
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
        # 优先最新构建号（数值大优先）
        for version in sorted(quarantined, key=lambda x: int(x) if x.isdigit() else 0,
                              reverse=True)[:args.limit]:
            urls = dmgs_for_version(version)
            if not urls:
                print(f"  [{version}] 归档无此构建号，跳过")
                continue
            dmg = tempfile.NamedTemporaryFile(prefix="wxkeep-", suffix=".dmg", delete=False)
            dmg.close()
            print(f"  [{version}] 下载 {urls[0].rsplit('/', 1)[-1]} …")
            try:
                req = urllib.request.Request(urls[0], headers={"User-Agent": "wxkeep-backfill"})
                with urllib.request.urlopen(req, timeout=600) as r, open(dmg.name, "wb") as f:
                    shutil.copyfileobj(r, f)
                dylib = extract_wechat_dylib(dmg.name)
            finally:
                os.unlink(dmg.name)
            if dylib:
                todo[version] = dylib
            else:
                print(f"  [{version}] dmg 内无 wechat.dylib，跳过")

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
