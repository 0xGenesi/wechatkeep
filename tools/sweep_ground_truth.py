#!/usr/bin/env python3
"""
sweep_ground_truth.py — L1 数据完整性地面真值全扫（ROADMAP 72·L1）。

对 var/wxarm 现存全部 wechat.dylib 切片，逐条目读回 catalog 位点字节，
断言与 expected[0]（pristine 原像）匹配。语义与 Swift 侧 ExpectedPattern
一比一：`?` 通配半字节、可选 `:maskHEX` 后缀按位 AND 屏蔽（半字节级）。

VA→文件偏移走 LC_SEGMENT_64 段表（不假设 VA==fileoff）。
`--otool-sample N` 对前 N 个 OK 条目用 `xxd` 直读交叉核对
（绕过脚本自身读回路径的第二只眼；工具名沿用历史叫法）。

用法:
  python3 tools/sweep_ground_truth.py                 # 全扫
  python3 tools/sweep_ground_truth.py --otool-sample 5
退出码：失配数 > 0 或缺切片的已归档构建条目被 --strict 点名时为 1。
"""
import argparse
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WXARM = os.path.join(ROOT, "var", "wxarm")
LC_SEGMENT_64 = 0x19
MH_MAGIC_64 = 0xFEEDFACF


# ---- ExpectedPattern 语义（ExpectedPattern.swift 的 Python 镜像） ----

def parse_pattern(spec):
    """返回 (nibbles, mask_bytes) 或 None。nibbles[i] = None 表示通配。"""
    body, mask = spec, None
    if ":" in spec:
        body, tail = spec.split(":", 1)
        if not tail.startswith("mask") or len(tail) <= 4:
            return None
        m = bytes.fromhex(tail[4:])
        if not m:
            return None
        mask = m
    if not body or len(body) % 2 != 0:
        return None
    nibbles = []
    for ch in body:
        if ch == "?":
            nibbles.append(None)
        elif ch in "0123456789abcdefABCDEF":
            nibbles.append(int(ch, 16))
        else:
            return None
    return nibbles, mask


def pattern_matches(spec, data):
    """data（bytes）是否匹配 spec（与 ExpectedPattern.matches 同语义）。"""
    parsed = parse_pattern(spec)
    if parsed is None:
        return False
    nibbles, mask = parsed
    byte_count = len(nibbles) // 2
    if len(data) < byte_count:
        return False
    for i in range(byte_count):
        m = mask[i % len(mask)] if mask else 0xFF
        hi_wild = nibbles[2 * i] is None or (m >> 4) == 0
        lo_wild = nibbles[2 * i + 1] is None or (m & 0xF) == 0
        if hi_wild and lo_wild:
            continue
        got = data[i]
        if not hi_wild and (got >> 4) != nibbles[2 * i]:
            return False
        if not lo_wild and (got & 0xF) != nibbles[2 * i + 1]:
            return False
    return True


# ---- Mach-O 段表 ----

def load_segments(path):
    """thin Mach-O 的 [(vmaddr, vmsize, fileoff)]；非 thin 返回 None。"""
    with open(path, "rb") as f:
        head = f.read(32)
    if len(head) < 32 or struct.unpack_from("<I", head, 0)[0] != MH_MAGIC_64:
        return None
    ncmds = struct.unpack_from("<I", head, 16)[0]
    segs = []
    with open(path, "rb") as f:
        f.seek(32)
        for _ in range(ncmds):
            cmdhdr = f.read(8)
            if len(cmdhdr) < 8:
                break
            cmd, cmdsize = struct.unpack_from("<II", cmdhdr, 0)
            if cmd == LC_SEGMENT_64:
                body = f.read(64)
                if len(body) < 64:
                    break
                vmaddr, vmsize, fileoff = struct.unpack_from("<QQQ", body, 16)
                segs.append((vmaddr, vmsize, fileoff))
                f.seek(cmdsize - 72, 1)
            else:
                f.seek(cmdsize - 8, 1)
    return segs


def va_to_offset(segs, va):
    for vmaddr, vmsize, fileoff in segs:
        if vmaddr <= va < vmaddr + vmsize:
            return fileoff + (va - vmaddr)
    return None


def read_at(path, offset, n):
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(n)


# ---- otool 交叉（抽样） ----

def xxd_cross(slice_path, offset, n, spec):
    """xxd 直读（绕过本脚本自己的读回路径）做第二只眼。"""
    r = subprocess.run(["/usr/bin/xxd", "-s", str(offset), "-l", str(n), "-p",
                        slice_path], capture_output=True, text=True)
    raw = bytes.fromhex(r.stdout.strip())
    return pattern_matches(spec, raw), raw.hex().upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--otool-sample", type=int, default=0,
                    help="对前 N 个 OK 条目用 xxd/otool 独立读回交叉核对")
    ap.add_argument("--strict", action="store_true",
                    help="把「目录有条目但本地无切片」也计入失败（默认仅提示）")
    args = ap.parse_args()

    cfg = json.load(open(os.path.join(ROOT, "config.json")))
    rows, mismatch, quarantined, no_slice, ok = [], 0, 0, 0, 0
    cross_n = 0
    for v in cfg:
        build = v["version"]
        for t in v["targets"]:
            binary = t.get("binary")
            if binary is None or "wechat.dylib" not in (binary or ""):
                continue  # 切片库只存 wechat.dylib
            for e in t["entries"]:
                if e.get("addr") is None:
                    continue  # recipe 条目：运行期解析，位点不确定
                expected = e.get("expected")
                if expected is None:
                    quarantined += 1
                    continue
                variants = expected if isinstance(expected, list) else [expected]
                spec0 = variants[0]
                arch = "arm64" if e["arch"] == "arm64" else "x64"
                slice_path = os.path.join(WXARM, f"{build}_{arch}.dylib")
                if not os.path.exists(slice_path):
                    no_slice += 1
                    continue
                segs = load_segments(slice_path)
                va = int(e["addr"], 16)
                off = va_to_offset(segs, va)
                # 判定长度 = 最长变体（与 Patcher siteLen 同口径，通配尾部也读回）
                parsed_variants = [parse_pattern(s) for s in variants]
                if any(p is None for p in parsed_variants):
                    mismatch += 1
                    rows.append((build, e["arch"], t["identifier"], e["addr"],
                                 "-", spec0, "BAD-SPEC"))
                    continue
                n = max(len(p[0]) // 2 for p in parsed_variants)
                data = read_at(slice_path, off, n)
                # 分层预言（与引擎语义一比一）：
                # - 归一化条目（asm ∈ expected，如 keeptip 的序言恢复型）：
                #   restoreAsm 返回 asm 本身，expected[0] 是另一变体的补丁态
                #   ——pristine 只需匹配任一变体（通常就是 asm）。
                # - 普通条目：restore 反演写回 expected[0]，它必须是原始字节
                #   ——pristine 必须严格匹配 expected[0]。
                normalized = e["asm"] in variants
                if normalized:
                    hit_idx = next((i for i, s in enumerate(variants)
                                    if pattern_matches(s, data)), None)
                    good = hit_idx is not None
                    note = f"OK(normalized,variant#{hit_idx})" if good else "MISMATCH"
                else:
                    good = pattern_matches(spec0, data)
                    hit_idx = 0 if good else None
                    note = "OK" if good else "MISMATCH"
                rows.append((build, e["arch"], t["identifier"], e["addr"],
                             data.hex().upper(), spec0, note))
                if good:
                    ok += 1
                    if cross_n < args.otool_sample:
                        # 交叉核对的 spec 与主判定同源：归一化条目用实际匹配的
                        # 变体（expected[0] 是另一变体的补丁态，pristine 不匹配它）。
                        cross_spec = variants[hit_idx] if normalized else spec0
                        ok2, raw = xxd_cross(slice_path, off, n, cross_spec)
                        cross_n += 1
                        if not ok2:
                            mismatch += 1
                            rows.append((build, e["arch"], t["identifier"], e["addr"],
                                         raw, cross_spec, "XXD-CROSS-MISMATCH"))
                else:
                    mismatch += 1

    print(f"{'build':<8} {'arch':<7} {'target':<16} {'addr':<10} {'on-disk':<36} expected[0]")
    for r in rows:
        print(f"{r[0]:<8} {r[1]:<7} {r[2]:<16} {r[3]:<10} {r[4]:<36} {r[5]}  {r[6]}")
    print(f"\n条目总计 OK={ok}  MISMATCH={mismatch}  quarantined(无 expected)={quarantined}"
          f"  本地无切片(跳过)={no_slice}  交叉核对={cross_n}")
    fail = mismatch > 0 or (args.strict and no_slice > 0)
    print("结论：失配数 = 0，地面真值成立" if not fail else "结论：存在失配——数据级 P0")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
