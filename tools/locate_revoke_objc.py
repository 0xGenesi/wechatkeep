#!/usr/bin/env python3
"""
locate_revoke_objc.py — 3.x 主程序（ObjC 时代）撤回链方法级定位器。

3.x 无 4.x 的 movabs SSO 谓词形态（revokemsg 字面量全在 __cstring，且
多为 CGI 路由/库名）——撤回执行体是 ObjC 方法（2026-10-29 首轮侦查定案）：
  - onDelMsg:msgData:isRevoke:  删除执行体（types v36@0:8@16@24c32 = void）
  - onAddRevokePromptMsg:msgData:  撤回提示插入
补丁形态 = 方法 imp 入口裸 ret（同 update 族：x64 C3 / arm64 C0035FD6；
void 返回无 rax 契约）。imp 0x0 = 协议声明，只有非零 imp 是实现。

对给定主程序切片（x64/arm64 各跑一次）：
  1. otool -oV 解析 ObjC 元数据（两遍：先类头名，再方法三元组）
  2. 定位目标选择子的宿主类 + 非零 imp
  3. 实读 imp 处序言 → expected
  4. 输出 config.json 形态条目（binary=Contents/MacOS/WeChat）

用法: var/venv/bin/python3 tools/locate_revoke_objc.py <main-slice> [--selector ...]
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil  # noqa: E402

DEFAULT_SELECTORS = [
    "onDelMsg:msgData:isRevoke:",        # 删除执行体（silent 主点位）
    "onAddRevokePromptMsg:msgData:",     # 提示插入（tip 面）
]

RE_NAME = re.compile(r"^\s*name\s+0x[0-9a-f]+(?:\s+\(0x[0-9a-f]+\))?\s+(\S+)\s*$")
RE_TYPES = re.compile(r"^\s*types\s+0x[0-9a-f]+(?:\s+\(0x[0-9a-f]+\))?\s+(\S+)\s*$")
RE_IMP = re.compile(r"^\s*imp\s+0x[0-9a-f]+(?:\s+\((0x[0-9a-f]+)\))?\s*$")
RE_METHODS_HDR = re.compile(
    r"^\s*(?:base|instance|class)Methods\s+0x[0-9a-f]+(?:\s+\(0x[0-9a-f]+\))?")


def parse_objc(path):
    """otool -oV → [(class, selector, types, imp_int_or_None)]。
    imp=0/缺席（协议声明）记 None。两遍：类头名（name 后紧随
    *Methods 头）先收，方法三元组再按「最近类头」归属。"""
    r = subprocess.run(["otool", "-oV", path], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    class_at = {}                     # 行号 → 类名
    cls = None
    for i, line in enumerate(lines):
        m = RE_NAME.match(line)
        if m:
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if RE_METHODS_HDR.match(nxt):
                cls = m.group(1)
            class_at[i] = cls
    out = []
    pending = None                    # (class, sel)
    for i, line in enumerate(lines):
        cls = class_at.get(i, cls)
        m = RE_NAME.match(line)
        if m:
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            if not RE_METHODS_HDR.match(nxt):
                pending = (cls, m.group(1))
            continue
        m = RE_TYPES.match(line)
        if m and pending:
            out.append({"class": pending[0], "sel": pending[1],
                        "types": m.group(1), "imp": None})
            continue
        m = RE_IMP.match(line)
        if m and out and out[-1]["imp"] is None:
            v = m.group(1) or ""
            if not v:
                # 裸值形态（x64 绝对地址）：整行取值
                v = line.split()[1]
            iv = int(v, 16)
            out[-1]["imp"] = iv if iv else None
    return out


def thin_slice(path):
    d = open(path, "rb").read()
    magic = struct.unpack_from("<I", d, 0)[0]
    if magic in (0xFEEDFACF, 0xFEEDFACE):
        # little-endian thin
        cputype = struct.unpack_from("<i", d, 4)[0]
        arch = "x86_64" if cputype == 0x01000007 else \
            ("arm64" if cputype == 0x0100000C else None)
        return arch, d
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        nfat = struct.unpack_from(">I", d, 4)[0]
        for i in range(nfat):
            # fat_arch = 20 字节/项（cputype,cpusub,offset,size,align）——
            # 16 字节步长会错位读到上一项的 align（28632 实证）
            ct, _cs, off, sz, _al = struct.unpack_from(">5I", d, 8 + 20 * i)
            if ct == 0x01000007:
                return "x86_64", d[off:off + sz]
            if ct == 0x0100000C:
                return "arm64", d[off:off + sz]
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--selector", action="append", default=None)
    ap.add_argument("--json", action="store_true", help="输出 config 形态 JSON")
    args = ap.parse_args()
    sels = args.selector or DEFAULT_SELECTORS

    arch, thin = thin_slice(args.binary)
    if not arch:
        print("未知/不支持的 Mach-O 形态")
        return 1

    methods = parse_objc(args.binary)
    entries = []
    for sel in sels:
        impls = [m for m in methods if m["sel"] == sel and m["imp"]]
        n_proto = sum(1 for m in methods if m["sel"] == sel and not m["imp"])
        if not impls:
            print(f"[miss] {sel}: 无实现（协议声明 {n_proto} 处）")
            continue
        for m in impls:
            off = machutil.va2off(thin, m["imp"])
            pro = thin[off:off + 16].hex().upper()
            ret = "C3" if arch == "x86_64" else "C0035FD6"
            entries.append({
                "arch": arch, "addr": format(m["imp"], "x"),
                "expected": [pro[:8]], "asm": ret,
                "source": f"wxkeep:objc3x:{m['class']}::{sel}",
                "_types": m["types"],
            })
            print(f"[hit] {sel} @ {m['class']} imp={hex(m['imp'])} "
                  f"types={m['types']} prologue={pro[:16]}")
    if args.json and entries:
        print(json.dumps(entries, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
