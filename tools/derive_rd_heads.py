#!/usr/bin/env python3
"""derive_rd_heads.py — rd 直调表可选头锚派生（136 轮身份门扩展）。

给定 arm64 dylib（thin 或 fat，自动取 arm64 切片）与 rd 组函数位点偏移，
读各位点头 16B 原像并以行字段格式输出（clone_rd_wrap_head 等）。派生侧
校验与 dylib 侧武装门同源（machutil 同哲学——「派生时算的值」与「安装时
核的值」是同一个定义）：
  - 位点必须落在段表内（超图 = 拒绝派生并显式点名——270135 x2desc=
    0xa3de0a70 超图 16 倍的转录/滑移污染在这里就拦，不进 runtime.json）；
  - 头 16B 全零 = 拒绝（位点无效）。

x2desc 是数据槽（非函数），锚不适用——本工具不产出其锚；其正确性由
dylib 侧武装期范围门兜底。

用法:
  python3 tools/derive_rd_heads.py <arm64.dylib> \
      [--wrap 0x309ac50] [--getter 0x102b740] \
      [--x2single 0x571ce74] [--x2ctx 0x5720308]
缺省偏移 = 270135 行现役值。
"""
import argparse
import json
import struct
import sys

DEFAULTS = {
    "wrap": 0x309AC50,
    "getter": 0x102B740,
    "x2single": 0x571CE74,
    "x2ctx": 0x5720308,
}
KEYMAP = {"wrap": "clone_rd_wrap_head", "getter": "clone_rd_getter_head",
          "x2single": "clone_rd_x2single_head", "x2ctx": "clone_rd_x2ctx_head"}


def arm64_slice(data: bytes) -> bytes:
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:                       # thin（小端头）
        return data
    if magic == 0xCAFEBABE:                       # fat
        n = struct.unpack_from(">I", data, 4)[0]
        for i in range(n):
            cpu, _sub, off, size, _align = struct.unpack_from(">IIIII", data, 8 + 20 * i)
            if cpu == 0x0100000C:                 # arm64
                return data[off:off + size]
    sys.exit("输入既非 thin Mach-O 也无 arm64 切片")


def segments(data: bytes):
    assert struct.unpack_from("<I", data, 0)[0] == 0xFEEDFACF
    ncmds = struct.unpack_from("<I", data, 16)[0]
    p, out = 32, []
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from("<II", data, p)
        if cmd == 0x19 and cs >= 72:
            name = data[p + 8:p + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, p + 24)
            out.append((name, vmaddr, vmsize, fileoff, filesize))
        p += cs
    return out


def read_head(segs, data, va, name):
    """位点头 16B；落段检查（与 runtime.m layout_contains 同定义）。"""
    for (_n, vm, vms, fo, _fs) in segs:
        if vm <= va < vm + vms:
            off = fo + (va - vm)
            if off + 16 > len(data):
                sys.exit(f"{name}: VA {va:#x} 段内但超文件尾——镜像截断/坏值，拒绝派生")
            head = data[off:off + 16]
            if not any(head):
                sys.exit(f"{name}: VA {va:#x} 头 16B 全零——位点无效，拒绝派生")
            return head
    sys.exit(f"{name}: VA {va:#x} 不在任何段内（超图——转录/滑移污染同型，"
             f"拒绝派生；dylib 侧范围门会同样拒绝）")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dylib", help="arm64 thin 或 fat dylib")
    for k, v in DEFAULTS.items():
        ap.add_argument(f"--{k}", default=f"{v:#x}")
    args = ap.parse_args()

    raw = open(args.dylib, "rb").read()
    data = arm64_slice(raw)
    segs = segments(data)
    row = {}
    for key in DEFAULTS:
        va = int(getattr(args, key), 16)
        head = read_head(segs, data, va, key)
        row[KEYMAP[key]] = head.hex().upper()
        print(f"{KEYMAP[key]} = {head.hex().upper()}   # @{va:#x}")
    print("\nJSON 行字段（并入 runtime.json 对应构建行）:")
    print(json.dumps(row, indent=1))


if __name__ == "__main__":
    main()
