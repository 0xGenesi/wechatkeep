#!/usr/bin/env python3
"""
fetch_zsbai_full.py — zsbai 归档全量拉取（3.x + 4.x 缺口）→ 布局探测 → 切片入库。

2026-10-29「适配 3 和 4 所有版本」轮的素材管线。与 derive_from_zsbai.py
（4.1.9-4.1.12 时代、目录内构建审计）互补，本脚本面向：
  - 目录外新构建（4.2.0.x / 4.1.15.22 等）
  - 主程序时代（3.5.5-3.8.9 与 4.1.0-4.1.6 夹缝：revoke 在 MacOS/WeChat）
  - Frameworks/wechat.dylib 时代（4.1.7-4.1.8 tanranv5 隔离条目）

每 tag：
  1. 并行分块下载（ghfast 16 路 Range；直连整文件回落）+ sha256 校验
  2. 挂载 → Info.plist（CFBundleVersion/WeChatBundleVersion/ShortVersion）
  3. 布局探测：Resources/wechat.dylib / Frameworks/wechat.dylib /
     MacOS/WeChat 何者在场（尺寸+架构）
  4. thin 切片入库 var/wxarm：
       {build}_{x64,arm64}.dylib       = Resources/wechat.dylib（4.x 主形态）
       {build}_fw_{x64,arm64}.dylib    = Frameworks/wechat.dylib（4.1.7-8）
       {build}_main_{x64,arm64}        = MacOS/WeChat（3.x / 夹缝代）
  5. 布局+tag→build 映射写 var/staging/zsbai_full_log.json（增量合并）
  6. dmg 用后即删（磁盘纪律）

用法: python3 tools/fetch_zsbai_full.py [--tags a,b,...] [--keep-dmg]
安全: 只读社区归档与本地磁盘；不动 config.json。
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil  # noqa: E402
from backfill_expected import decompress_if_xz, run  # noqa: E402

ASSET_FMT = ("https://github.com/zsbai/wechat-versions/releases/download/"
             "{tag}/WeChatMac-{tag}.dmg")   # 仅适用于无前缀点分 tag；其余走 API 真实 URL
GHFAST = "https://ghfast.top/"
# gh-proxy 优先：ghfast 长发作期每请求挂满 max-time（接受连接不回数据），
# 8MiB 块 × 3 重试 × ~40 块 = 每 tag 空耗 ~15min。ghfast 恢复后可调回。
MIRRORS = [("https://gh-proxy.com/", 1 << 20),  # 2026-10-29 实测 ~480KB/s 聚合
           (GHFAST, 8 << 20)]               # 快但间歇截断/全灭
CHUNK_WORKERS = 16
CHUNK = 8 << 20  # 8MiB（ghfast 档；gh-proxy 档各自带块大小）

# 优先级序：前瞻价值（4.2.0）→ 4.1.15 缺口 → 3.x 全线（新到老）→
# 4.x 早期（dated tag 可能互为重复构建，挂载后构建号去重）
DEFAULT_TAGS = [
    "v3.8.9.17", "v3.8.8", "v3.8.7", "v3.8.6", "v3.8.5", "v3.8.4", "v3.8.2",
    "v3.8.1", "v3.8.0", "v3.7.1", "v3.7.0", "v3.6.2", "v3.6.1", "v3.6.0", "v3.5.5",
    "v4.1.0_20250828", "v4.1.0_20250902", "v4.1.0_20250906", "v4.1.2_20251031",
    "v4.1.5_20251121", "v4.1.5_20251203", "v4.1.5_20251205",
    "v4.1.6_20260107", "v4.1.6",
    "v4.1.7_20260131", "v4.1.7", "4.1.7.31", "4.1.7.33", "4.1.7.57",
    "4.1.8.28", "4.1.8.29", "4.1.8.67", "4.1.8.100", "4.1.8.106",
]


def asset_meta(tag):
    """(size, sha256_hex, url) —— GitHub API 权威值；镜像 content-length 不可信。
    返回真实 asset 下载 URL（v 前缀/日期后缀 tag 的资产名与 tag 不同构）。
    认证：GH_TOKEN/GITHUB_TOKEN 环境变量或 gh auth token——匿名 60 次/时
    限流一轮就耗尽（2026-10-29 实证），多 tag 批必须带 token。"""
    import subprocess as sp
    import urllib.request
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        r = sp.run(["gh", "auth", "token"], capture_output=True, text=True)
        if r.returncode == 0:
            token = r.stdout.strip()
    url = (f"https://api.github.com/repos/zsbai/wechat-versions/releases/tags/{tag}")
    headers = {"User-Agent": "wxkeep-zsbai"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        rel = json.load(r)
    size = digest = dl = None
    for a in rel.get("assets", []):
        if a["name"].endswith(".dmg"):
            size = a["size"]
            d = a.get("digest") or ""
            if d.startswith("sha256:"):
                digest = d[7:]
            dl = a["browser_download_url"]
    return size, digest, dl


def _fetch_range(url, start, end, dest, tries=3):
    for _ in range(tries):
        r = subprocess.run(["curl", "-sL", "--max-time", "120",
                            "-r", f"{start}-{end}", "-o", dest, url])
        if r.returncode == 0 and os.path.exists(dest) \
                and os.path.getsize(dest) == end - start + 1:
            return True
        time.sleep(2)
    return False


def download(tag, dest):
    """多镜像分块（ghfast 8MiB → gh-proxy 1MiB）→ 直连整文件回落。
    sha256+size 双校验。2026-10-29：ghfast 进入长发作期全灭（0 字节/
    截断），gh-proxy.com 实测可用但吞吐 ~60KB/s/路——1MiB 块 + 16 路聚
    合 ~480KB/s，300MB 构建 ~10min。镜像按序试，全败才走直连。"""
    want_len, digest, url = asset_meta(tag)
    if not want_len or not url:
        print("    API 无 asset 元数据，跳过")
        return False

    for prefix, chunk in MIRRORS:
        if _chunked_download(prefix + url, want_len, dest, chunk) \
                and os.path.getsize(dest) == want_len:
            if not digest:
                return True
            h = hashlib.sha256()
            with open(dest, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            if h.hexdigest() == digest:
                return True
            print(f"    {prefix} 分块拼装 sha256 不符")
            os.unlink(dest)

    # 直连整文件回落
    r = subprocess.run(["curl", "-sL", "--retry", "2", "--speed-time", "60",
                        "--speed-limit", "10240", "--max-time", "1200",
                        "-o", dest, url])
    ok = r.returncode == 0 and os.path.exists(dest) \
        and os.path.getsize(dest) == want_len
    if ok and digest:
        h = hashlib.sha256()
        with open(dest, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        ok = h.hexdigest() == digest
    if not ok:
        try:
            os.unlink(dest)
        except FileNotFoundError:
            pass
    return ok


def _chunked_download(url, want_len, dest, chunk_size):
    chunks = [(i, min(i + chunk_size, want_len) - 1)
              for i in range(0, want_len, chunk_size)]
    tmpdir = tempfile.mkdtemp(prefix="wxkeep-chunks-")
    try:
        with ThreadPoolExecutor(max_workers=CHUNK_WORKERS) as ex:
            futs = {ex.submit(_fetch_range, url, s, e,
                              os.path.join(tmpdir, f"c{i}")): i
                    for i, (s, e) in enumerate(chunks)}
            ok = all(f.result() for f in futs)
        if ok:
            with open(dest, "wb") as out:
                for i, _ in enumerate(chunks):
                    out.write(open(os.path.join(tmpdir, f"c{i}"), "rb").read())
            return os.path.getsize(dest) == want_len
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def read_plist_defaults(plist, key, tries=4):
    """macOS 27 hdiutil 连续快速挂/卸同一 dmg 后，挂载点内文件会瞬时
    stat 不可见（walk 能列名、随后 exists=False——2026-10-29 实证）。
    重试 + 间隔读，仍败才认 None。"""
    import time
    for i in range(tries):
        r = run(["/usr/bin/defaults", "read", plist, key])
        if r.returncode == 0:
            return r.stdout.strip()
        if i < tries - 1:
            time.sleep(0.6)
    return None


def mount_layout(dmg_path):
    """→ (info, binaries) ；info=版本字段 dict，binaries={slot: fat_path}。"""
    dmg_path = decompress_if_xz(dmg_path)
    mount = tempfile.mkdtemp(prefix="wxkeep-full-")
    r = run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly",
             "-mountpoint", mount, dmg_path])
    if r.returncode != 0:
        print(f"    hdiutil 失败: {r.stderr.strip()[:100]}")
        shutil.rmtree(mount, ignore_errors=True)
        return None, None
    try:
        app = res_dylib = fw_dylib = main_bin = None
        # 先定 app 再读 plist——plist 读取必须发生在全树 walk 之前：
        # macOS 27 上对刚挂载卷做大量 scandir 后，部分文件会进入
        # stat 不可见的陈旧态（2026-10-29 实证：walk 后 Info.plist
        # exists=False 而 MacOS/WeChat 仍 True；zsh 新挂载一切正常）。
        for name in os.listdir(mount):
            cand = os.path.join(mount, name)
            if name.endswith(".app") and \
                    os.path.exists(os.path.join(cand, "Contents", "Info.plist")):
                app = cand
                break
        info = {}
        if app:
            info["app"] = os.path.basename(app)
            for k in ("CFBundleVersion", "WeChatBundleVersion",
                      "CFBundleShortVersionString"):
                info[k] = read_plist_defaults(
                    os.path.join(app, "Contents", "Info.plist"), k)
        for root, _dirs, files in os.walk(mount):
            if "wechat.dylib" in files:
                p = os.path.join(root, "wechat.dylib")
                rel = os.path.relpath(p, app if app else mount)
                if rel.startswith("Resources"):
                    res_dylib = p
                elif rel.startswith("Frameworks"):
                    fw_dylib = p
            if "WeChat" in files and root.endswith(".app/Contents/MacOS"):
                main_bin = os.path.join(root, "WeChat")
        bins = {}
        for slot, p in (("res", res_dylib), ("fw", fw_dylib), ("main", main_bin)):
            if p and os.path.exists(p):
                bins[slot] = p
        # 切片提取必须在挂载生命周期内（finally 会卸载卷——bins 路径
        # 返回后即失效，2026-10-29 实证 slice 解析失败 No such file）
        slots = {}
        if bins:
            build = (info or {}).get("WeChatBundleVersion") \
                or (info or {}).get("CFBundleVersion")
            if build and build.isdigit():
                slots = extract_slices(build, bins, False)
        return info, bins, slots
    finally:
        # 优雅卸载优先——force 会撕掉仍在被扫描的卷，连带毒化同 dmg 的
        # 下一次挂载（plist 竞态根因之一）
        if run(["/usr/bin/hdiutil", "detach", mount]).returncode != 0:
            run(["/usr/bin/hdiutil", "detach", mount, "-force"])


SLOT_SUFFIX = {"res": "", "fw": "_fw", "main": "_main"}


def extract_slices(build, bins, keep_universal):
    """fat → thin 入库。→ {slot: {cpu_name: path}}。返回各 slot 架构面。"""
    out = {}
    for slot, fat in bins.items():
        try:
            slices = machutil.load_slices(fat)
        except Exception as e:
            print(f"    slice 解析失败 [{slot}]: {e}")
            continue
        paths = {}
        for cpu, name in ((machutil.CPU_X86_64, "x64"), (machutil.CPU_ARM64, "arm64")):
            if cpu in slices:
                ext = ".dylib" if slot != "main" else ""
                p = os.path.join(ROOT, "var/wxarm",
                                 f"{build}{SLOT_SUFFIX[slot]}_{name}{ext}")
                if not os.path.exists(p):  # 幂等
                    open(p, "wb").write(slices[cpu])
                paths[name] = p
        out[slot] = paths
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", help="逗号分隔，缺省 DEFAULT_TAGS")
    ap.add_argument("--keep-dmg", action="store_true")
    args = ap.parse_args()
    tags = args.tags.split(",") if args.tags else DEFAULT_TAGS

    log_path = os.path.join(ROOT, "var/staging/zsbai_full_log.json")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log = json.load(open(log_path)) if os.path.exists(log_path) else {}
    tagmap_path = os.path.join(ROOT, ".wxkeep-tagmap.json")
    tagmap = json.load(open(tagmap_path)) if os.path.exists(tagmap_path) else {}

    workdir = tempfile.mkdtemp(prefix="wxkeep-full-dl-")
    seen_builds = set()
    for tag in tags:
        print(f"=== {tag}", flush=True)
        dest = os.path.join(workdir, f"WeChatMac-{tag}.dmg")
        try:
            if not download(tag, dest):
                print("    下载失败（双路），跳过", flush=True)
                continue
            info, bins, slots = mount_layout(dest)
            if info:
                tagmap[tag] = info.get("CFBundleVersion")
                json.dump(tagmap, open(tagmap_path, "w"), indent=1, sort_keys=True)
            if not bins:
                print(f"    布局: {info} 无可补丁二进制，跳过", flush=True)
                log[tag] = {"info": info, "note": "no-binary"}
                continue
            build = info.get("WeChatBundleVersion") or info.get("CFBundleVersion")
            if not build or not build.isdigit():
                print(f"    构建号缺失（{info}），跳过", flush=True)
                log[tag] = {"info": info, "note": "no-build"}
                continue
            if not slots:
                slots = extract_slices(build, bins, args.keep_dmg)
            sizes = {s: {n: os.path.getsize(p) for n, p in d.items()}
                     for s, d in slots.items()}
            dup = "（构建号重复，多版本并存已各自入库）" if build in seen_builds else ""
            seen_builds.add(build)
            log[tag] = {"build": build, "info": info, "slices": sizes}
            print(f"    build={build} ver={info.get('CFBundleShortVersionString')} "
                  f"切面={list(slots.keys())} {dup}", flush=True)
        except Exception as e:
            print(f"    ✗ 故障隔离: {type(e).__name__}: {str(e)[:160]}", flush=True)
        finally:
            try:
                if not args.keep_dmg:
                    os.unlink(dest)
            except FileNotFoundError:
                pass
        json.dump(log, open(log_path, "w"), indent=1, ensure_ascii=False)
    shutil.rmtree(workdir, ignore_errors=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
