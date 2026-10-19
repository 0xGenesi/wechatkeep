#!/usr/bin/env python3
"""probe_cdn_line.py — 官方 CDN 归档的营销线存在性/边界探测（只读）。

用途（ROADMAP 66 轮遗留：4.1.14 线存在性未探；新营销线如 4.1.16 上线时
重跑定界）：CDN 按构建号永久归档 `xWeChatMac_universal_<点分>_<构建>.dmg`，
线内点分↔构建线性（4.1.13.N ↔ 269568+N、4.1.15.N ↔ 270080+N，25+ 直链
实证；base 阶梯等差 256——269312/269568/269824?/270080，4.1.12 段与
zsbai .25-.29 重叠互证）。给定点分线与 base（或 base 区间），range GET
bytes=0-0 探测（404=不存在、206=在档；2026-10-17 实证口径）。

两种用法：
  1) 线假设验证：--family 4.1.14 --base 269824
     探 N=0..maxN（默认 64）整行，报在档集合。
  2) base 搜索：--family 4.1.14 --base-sweep 269633:270020
     对区间内每个 base 先探 N=0..15（公开段通常低 N 起步：4.1.15 起点
     .4、4.1.13 起点 .5；--sweep-ns 可调），任一命中即锁定 base 并转
     整行扫描；全程无命中 = 该区间内此线无 CDN 归档。

并发 16（--concurrency），礼貌起见别开太高——这是对生产 CDN 的探测。
用法: python3 tools/probe_cdn_line.py --family 4.1.14 --base 269824
"""
import argparse
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CDN_URL_FMT = ("https://dldir1v6.qq.com/weixin/Universal/Mac/"
               "xWeChatMac_universal_{dotted}_{build}.dmg")


def exists(url, timeout=10):
    """206/200 = 在档；404 = 不存在；连接层异常 = None（计为不在档，
    但记入 neterr 汇总——大面积 None 意味着结论不可信而非不存在）。"""
    req = urllib.request.Request(url, headers={
        "Range": "bytes=0-0", "User-Agent": "wxkeep-probe"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status in (200, 206)
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def probe_grid(family, pairs, concurrency):
    """[(n, build)] → 命中的 (n, build) 集合 + 网络异常计数。"""
    hits, neterr = [], 0
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for (n, b), r in zip(pairs, ex.map(
                lambda p: exists(CDN_URL_FMT.format(
                    dotted=f"{family}.{p[0]}", build=p[1])), pairs)):
            if r is None:
                neterr += 1
            elif r:
                hits.append((n, b))
    return sorted(hits), neterr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", required=True, help="点分线名，如 4.1.14")
    ap.add_argument("--base", type=int, help="线 base 假设（构建号 = base + N）")
    ap.add_argument("--base-sweep", metavar="START:END",
                    help="base 搜索区间（含端点）")
    ap.add_argument("--max-n", type=int, default=64)
    ap.add_argument("--sweep-ns", type=int, default=16,
                    help="base 搜索阶段每 base 探的 N 上限（不含）")
    ap.add_argument("--concurrency", type=int, default=16)
    args = ap.parse_args()
    if not args.base and not args.base_sweep:
        ap.error("--base 与 --base-sweep 至少给一个")

    if args.base:
        pairs = [(n, args.base + n) for n in range(0, args.max_n + 1)]
        hits, neterr = probe_grid(args.family, pairs, args.concurrency)
        for n, b in hits:
            print(f"HIT {args.family}.{n} = 构建 {b}")
        print(f"[{args.family} base={args.base}] 在档 {len(hits)}/{len(pairs)}"
              + (f"，网络异常 {neterr}（结论需复测）" if neterr else ""))
        return

    lo, hi = (int(x) for x in args.base_sweep.split(":"))
    for base in range(lo, hi + 1):
        pairs = [(n, base + n) for n in range(0, args.sweep_ns)]
        hits, neterr = probe_grid(args.family, pairs, args.concurrency)
        if neterr > len(pairs) // 2:
            print(f"!! base={base} 网络异常 {neterr}/{len(pairs)}——中止，结论不可信",
                  file=sys.stderr)
            return 2
        if hits:
            print(f"锁定 base={base}（粗扫命中 {[f'.{n}' for n, _ in hits]}），转整行扫描")
            full = [(n, base + n) for n in range(0, args.max_n + 1)]
            fh, fe = probe_grid(args.family, full, args.concurrency)
            for n, b in fh:
                print(f"HIT {args.family}.{n} = 构建 {b}")
            print(f"[{args.family} base={base}] 在档 {len(fh)}/{len(full)}"
                  + (f"，网络异常 {fe}" if fe else ""))
            return
        if base % 16 == 0:
            print(f"  … base {base} 无命中", file=sys.stderr)
    print(f"[{args.family}] base 区间 {lo}..{hi} × N 0..{args.sweep_ns - 1} "
          f"全空——该区间内无此线 CDN 归档")


if __name__ == "__main__":
    sys.exit(main())
