#!/usr/bin/env python3
"""
derive_from_zsbai.py — zsbai 归档构建 → 切片抽取 + 全条目官方字节交叉验证 + 派生。

2026-09-19 全版本一致性轮的 4.1.9–4.1.12 时代驱动脚本（ ROADMAP ㉛）：
catalog 该段构建的条目全部来自社区导入（zengtianli arm64 / tanranv5 x64），
此前从未对官方原版字节做过机器校验——⑭ 轮「zsbai 均无归档」的结论下早了
（archive_index 里 4.1.9-4.1.12 全线在档，只是从未逐 tag 探明映射）。

对每个 tag：
  1. 下载 dmg（XZ 重压缩）→ 解压 → 挂载 → 读 CFBundleVersion（构建号）
  2. 构建号命中 catalog（268xxx-269xxx 段）→ 抽 thin 切片入 var/wxarm
  3. 全条目官方字节交叉验证：读 (arch, addr) 处字节 vs expected 变体
     —— 社区导入数据的首次官方归档级审计
  4. 隔离条目回填：缺 expected 者（tanranv5 x64）按实读字节补
  5. x64 派生：update 8 点（locate_update_x64）+ parse guard + keeptip store
  6. tag→build 映射写 .wxkeep-tagmap.json（一次探明终身受用）

用法: python3 tools/derive_from_zsbai.py [--tags 4.1.12.53,...] [--keep-slices]
安全: 只读官方/社区归档与本地切片；产物写 var/staging/zsbai_<build>.json，
不直接改 config.json（合并与 manifest 重签由收尾轮统一做）。
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil  # noqa: E402
from backfill_expected import (  # noqa: E402
    BUILD_TO_TAG_HINTS, decompress_if_xz, run)

X64, ARM64 = machutil.CPU_X86_64, machutil.CPU_ARM64
ARCH_CPU = {"x86_64": X64, "arm64": ARM64}

# 19 个 tag：覆盖 hints 全部 4.x 映射 + 邻近 tag 消歧（268575/268596 同指
# 4.1.9.26 一类冲突靠实测构建号解决）
DEFAULT_TAGS = [
    "4.1.9.26", "4.1.9.27", "4.1.9.31", "4.1.9.57", "4.1.9.58",
    "4.1.10.24", "4.1.10.31", "4.1.10.53",
    "4.1.11.51", "4.1.11.52", "4.1.11.53", "4.1.11.54", "4.1.11.55",
    "4.1.12.25", "4.1.12.26", "4.1.12.27", "4.1.12.28", "4.1.12.29",
    "4.1.12.53",
]
ASSET_FMT = ("https://github.com/zsbai/wechat-versions/releases/download/"
             "{tag}/WeChatMac-{tag}.dmg")

# catalog 里关心的 4.x 构建号区间（3.x 条目目标主程序非 wechat.dylib，不在本轮）
BUILD_LO, BUILD_HI = 268000, 270100


GH_PROXIES = ("", "https://gh-proxy.com/")   # 直连优先，gh-proxy 镜像回落（④ 轮实证直连常超时）


def asset_digest(tag):
    """GitHub API 的权威 size + sha256 digest（镜像的 content-length 不可信
    ——gh-proxy 实测报错值且大文件偶发损坏，2026-09-19 两度实证）。"""
    import subprocess as sp
    import urllib.request
    url = (f"https://api.github.com/repos/zsbai/wechat-versions/releases/tags/{tag}")
    req = urllib.request.Request(url, headers={"User-Agent": "wxkeep-zsbai"})
    with urllib.request.urlopen(req, timeout=30) as r:
        rel = json.load(r)
    for a in rel.get("assets", []):
        if a["name"].endswith(".dmg"):
            return a["size"], a.get("digest", "")
    return None, None


def download(tag, dest):
    """逐源整文件下载（不做跨源断点续传——直连残留 + 镜像续写会拼出损坏
    XZ），下完对 GitHub API 权威 size + sha256 digest 双校验。"""
    import hashlib
    import subprocess as sp
    url = ASSET_FMT.format(tag=tag)
    want_len, digest = asset_digest(tag)
    for proxy in GH_PROXIES:
        r = sp.run(["curl", "-sL", "--retry", "2",
                    "--connect-timeout", "15", "--speed-time", "60",
                    "--speed-limit", "10240",
                    "--max-time", "240" if not proxy else "3600",
                    "-o", dest, proxy + url])
        ok = r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0
        if ok and want_len and os.path.getsize(dest) != want_len:
            print(f"    长度不符 {os.path.getsize(dest)}≠{want_len}")
            ok = False
        if ok and digest:
            h = hashlib.sha256()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if f"sha256:{h.hexdigest()}" != digest:
                print("    sha256 digest 不符（下载损坏）")
                ok = False
        if ok:
            return True
        try:
            os.unlink(dest)
        except FileNotFoundError:
            pass
        print(f"    下载失败（{'直连' if not proxy else 'gh-proxy'}），"
              f"{'换回落' if not proxy else '放弃'}")
    return False


def mount_extract(dmg_path):
    """→ (fat_dylib_temp, build) ；失败 (None, None)。"""
    dmg_path = decompress_if_xz(dmg_path)
    mount = tempfile.mkdtemp(prefix="wxkeep-zsbai-")
    r = run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly",
             "-mountpoint", mount, dmg_path])
    if r.returncode != 0:
        print(f"    hdiutil 挂载失败: {r.stderr.strip()[:100]}")
        shutil.rmtree(mount, ignore_errors=True)
        return None, None
    try:
        app = dylib = None
        for root, _dirs, files in os.walk(mount):
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
        out = tempfile.NamedTemporaryFile(prefix="wxkeep-fat-", delete=False)
        out.close()
        shutil.copy2(dylib, out.name)
        return out.name, build
    finally:
        run(["/usr/bin/hdiutil", "detach", mount, "-force"])
        try:
            os.unlink(dmg_path)
        except FileNotFoundError:
            pass


def entry_bytes(slice_bytes, addr_hex, n):
    off = machutil.va2off(slice_bytes, int(addr_hex, 16))
    if off is None or off + n > len(slice_bytes):
        return None
    return slice_bytes[off:off + n]


def audit_build(cfg_build, slices):
    """全条目官方字节审计 + 隔离回填。→ (report_rows, backfilled)。"""
    rows, backfilled = [], []
    for t in cfg_build["targets"]:
        for e in t["entries"]:
            cpu = ARCH_CPU.get(e["arch"])
            sb = slices.get(cpu)
            if sb is None:
                rows.append({"id": t["identifier"], "arch": e["arch"],
                             "addr": e["addr"], "verdict": "no-slice"})
                continue
            if e.get("expected"):
                n = max(len(bytes.fromhex(x)) for x in e["expected"])
                raw = entry_bytes(sb, e["addr"], n)
                verdict = "match" if raw and raw.hex().upper() in e["expected"] \
                    else "MISMATCH"
                rows.append({"id": t["identifier"], "arch": e["arch"],
                             "addr": e["addr"], "verdict": verdict,
                             "actual": raw.hex().upper() if raw else None})
            else:
                n = len(bytes.fromhex(e["asm"]))
                raw = entry_bytes(sb, e["addr"], n)
                if raw and len(raw) == n:
                    backfilled.append({"identifier": t["identifier"],
                                       "entry": e,
                                       "expected": [raw.hex().upper()]})
                    rows.append({"id": t["identifier"], "arch": e["arch"],
                                 "addr": e["addr"], "verdict": "backfilled",
                                 "actual": raw.hex().upper()})
                else:
                    rows.append({"id": t["identifier"], "arch": e["arch"],
                                 "addr": e["addr"], "verdict": "read-fail"})
    return rows, backfilled


def derive_x64(x64thin):
    """update 8 点 + guard + keeptip store（老构建类/结构缺失时诚实跳过）。"""
    out = {}
    r = run(["python3", os.path.join(HERE, "locate_update_x64.py"), x64thin])
    if r.returncode == 0:
        m = re.search(r"(\{.*\"identifier\": \"update\".*\})",
                      r.stdout, re.S)
        if m:
            out["update"] = json.loads(m.group(1))
    else:
        out["update_error"] = (r.stdout + r.stderr).strip()[-300:]

    r = run(["python3", os.path.join(HERE, "locate_x64_parse_guard.py"),
             x64thin])
    m = re.search(r"addr=([0-9a-f]+)", r.stdout)
    if m:
        out["guard_addr"] = m.group(1)
        g = int(m.group(1), 16)
        d = machutil.load_slice(x64thin, X64)
        funcs = machutil.function_starts(d)
        pe = max((f for f in funcs if f <= g), default=None)
        if pe:
            out["parse_entry"] = format(pe, "x")
            nxt = min((f for f in funcs if f > pe), default=None)
            off = machutil.va2off(d, pe)
            end = machutil.va2off(d, nxt) if nxt else off + 0x2000
            hits = []
            o = off
            while o + 12 <= end:
                if d[o] == 0xE8 and d[o+5:o+12] == b"\x48\x89\x83\xc8\x01\x00\x00":
                    hits.append(pe + (o - off))
                o += 1
            out["keeptip_store_hits"] = [format(h, "x") for h in hits]
    else:
        out["guard_error"] = (r.stdout + r.stderr).strip()[-300:]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", help="逗号分隔，缺省 DEFAULT_TAGS")
    ap.add_argument("--keep-slices", action="store_true",
                    help="保留 thin 切片（默认：非隔离构建用后即删省磁盘）")
    args = ap.parse_args()
    tags = args.tags.split(",") if args.tags else DEFAULT_TAGS

    cfg = json.load(open(os.path.join(ROOT, "config.json")))
    by_build = {v["version"]: v for v in cfg}
    tagmap_path = os.path.join(ROOT, ".wxkeep-tagmap.json")
    tagmap = {}
    if os.path.exists(tagmap_path):
        tagmap = json.load(open(tagmap_path))

    os.makedirs(os.path.join(ROOT, "var/staging"), exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="wxkeep-zsbai-dl-")

    for tag in tags:
        print(f"=== {tag}", flush=True)
        try:
            process_tag(tag, cfg, by_build, tagmap, workdir, args)
        except Exception as e:   # 单 tag 故障隔离（⑯ 同哲学：源损坏/挂载失败
            # 不杀整轮——zsbai 个别 asset 在源头就是坏的，2026-09-19 实证）
            print(f"    ✗ tag 故障隔离: {type(e).__name__}: {str(e)[:160]}", flush=True)
            for leftover in glob.glob(os.path.join(workdir, f"*{tag}*")):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass

    shutil.rmtree(workdir, ignore_errors=True)
    print("DONE")


def process_tag(tag, cfg, by_build, tagmap, workdir, args):
    dest = os.path.join(workdir, f"WeChatMac-{tag}.dmg")
    if not download(tag, dest):
        print("    下载失败，跳过")
        return
    fat, build = mount_extract(dest)
    if build:
        tagmap[tag] = build
        json.dump(tagmap, open(os.path.join(ROOT, ".wxkeep-tagmap.json"), "w"),
                  indent=1, sort_keys=True)
    if fat is None:
        print(f"    构建 {build}：无 wechat.dylib，跳过")
        return
    print(f"    构建 {build}")
    if not (build and build.isdigit()
            and BUILD_LO <= int(build) <= BUILD_HI
            and build in by_build):
        print("    不在 catalog 关心区间，跳过")
        os.unlink(fat)
        return

    # thin 切片
    slices = machutil.load_slices(fat)
    thins = {}
    for cpu, name in ((X64, "x64"), (ARM64, "arm64")):
        if cpu in slices:
            p = os.path.join(ROOT, "var/wxarm", f"{build}_{name}.dylib")
            open(p, "wb").write(slices[cpu])
            thins[name] = p
    os.unlink(fat)

    report = {"tag": tag, "build": build, "thins": thins}
    rows, backfilled = audit_build(by_build[build], slices)
    report["audit"] = rows
    report["backfill"] = backfilled
    report["derive_x64"] = derive_x64(thins["x64"]) if "x64" in thins else {}

    out = os.path.join(ROOT, "var/staging", f"zsbai_{build}.json")
    json.dump(report, open(out, "w"), indent=1, ensure_ascii=False)
    mism = sum(1 for r in rows if r["verdict"] == "MISMATCH")
    bf = sum(1 for r in rows if r["verdict"] == "backfilled")
    print(f"    审计 {len(rows)} 条: match={len(rows)-mism-bf} "
          f"mismatch={mism} backfilled={bf} → {out}")

    # 磁盘纪律：审计结论已在 report 内落盘，arm64 切片一律用后即删；
    # x64 切片仅隔离回填需求构建保留（4.x 隔离条目全在 x86_64 侧——
    # 后续引擎级往返验证需要）
    if not args.keep_slices:
        if "arm64" in thins:
            try:
                os.unlink(thins["arm64"])
            except FileNotFoundError:
                pass
            report["thins"] = {k: v for k, v in thins.items() if k != "arm64"}
        if not backfilled and "x64" in thins:
            try:
                os.unlink(thins["x64"])
            except FileNotFoundError:
                pass
            report["thins"] = {}


if __name__ == "__main__":
    main()
