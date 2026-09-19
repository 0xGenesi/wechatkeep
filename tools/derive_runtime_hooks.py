#!/usr/bin/env python3
"""
derive_runtime_hooks.py — 从真实 wechat.dylib x64 slice 派生 M-R2 runtime hook 行。

输入：thin x86_64 dylib + 解析守卫位点（locate_x64_parse_guard.py 产出的
`test al,al` 条目地址，位于 parse 函数体内）。派生链：

  guard(parse 体内) --LC_FUNCTION_STARTS--> parse 入口 → 12B 序言门 + LC_UUID → hooks 行

**口径（2026-09-19 ㉒ 实弹定案）**：hook 挂 parse 入口直读 rsi（= sysmsg
XML 裸 SSO，drive25 地面真值）。wrapper+0x130 旧口径已被真实撤回证伪
（fires=0），本工具随之改发 parse 行；wrapper 拓扑（parse 的唯一 E8 调用者）
保留为 stderr 诊断与交叉验证。

输出：runtime.json `hooks` 行 JSON（uuid/arch/hook_off/msg_arg/xml_sso_off/
expected/build）。序言门：必须 == 554889E5 4157415641554154（纯栈操作序言，
蹦床换址执行安全）——不符即拒绝并退出非零。

用法: python3 tools/derive_runtime_hooks.py <thin-x64.dylib> <guard-test-va-hex> [build]
依赖 tools/machutil.py。
"""
import json
import re
import struct
import sys

import machutil

LC_UUID = 0x1B
EXPECTED_PROLOGUE = bytes.fromhex("554889E54157415641554154")
CALL_SCAN_BACK = 0x400          # wrapper 长度 ~0x230（270099），取两倍窗


def lc_uuid(d):
    for cmd, p in machutil._load_commands(d):
        if cmd == LC_UUID:
            raw = d[p + 8:p + 24]
            h = raw.hex()
            return (f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}")
    raise SystemExit("LC_UUID not found")


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    path, guard_hex = sys.argv[1], sys.argv[2]
    build = sys.argv[3] if len(sys.argv) > 3 else "?"
    d = machutil.load_slice(path, machutil.CPU_X86_64)

    uuid = lc_uuid(d)
    text_addr, text_size, text_off = machutil.text_range(d)
    funcs = machutil.function_starts(d)
    if not funcs:
        raise SystemExit("LC_FUNCTION_STARTS 缺失——无法定位函数边界")

    # guard → parse 入口（包含 guard 的函数起点）
    guard_va = int(guard_hex, 16)
    parse_entry = max((f for f in funcs if f <= guard_va), default=None)
    if parse_entry is None:
        raise SystemExit(f"guard {guard_hex:#x} 不在任何函数内")
    # guard 不得落入 parse 之后的函数（下一个起点之前）
    nxt = min((f for f in funcs if f > parse_entry), default=None)

    # parse 的唯一 E8 调用者 = wrapper 内的 call（全 __text 扫描 + 唯一性门；
    # 交叉验证拓扑，不再作为 hook 位点——㉒ wrapper+0x130 已证伪）
    callers = []
    pos = text_off
    end = text_off + text_size
    while True:
        idx = d.find(b"\xe8", pos, end)
        if idx < 0:
            break
        disp = struct.unpack_from("<i", d, idx + 1)[0]
        if text_addr + (idx - text_off) + 5 + disp == parse_entry:
            callers.append(text_addr + (idx - text_off))
        pos = idx + 1
    if len(callers) != 1:
        raise SystemExit(
            f"parse {parse_entry:#x} 有 {len(callers)} 个 E8 调用者（拓扑预期唯一）"
            + (f": {[hex(c) for c in callers]}" if callers else ""))
    call_site = callers[0]
    if not (parse_entry - CALL_SCAN_BACK <= call_site < parse_entry):
        raise SystemExit(
            f"调用者 {call_site:#x} 不在 parse 前窗内——拓扑与 270099 不符，需人工分析")

    wrapper_entry = max((f for f in funcs if f <= call_site), default=None)
    if wrapper_entry is None:
        raise SystemExit("call site 不在任何函数内")

    off = machutil.va2off(d, parse_entry)
    prologue = d[off:off + 12]
    if prologue != EXPECTED_PROLOGUE:
        raise SystemExit(
            f"parse {parse_entry:#x} 序言 {prologue.hex().upper()} != 纯栈操作门"
            f"（{EXPECTED_PROLOGUE.hex().upper()}）——蹦床换址不安全，拒绝派生")

    # parse 直挂（㉒ 口径）：hook_off=parse 入口，rsi（msg_arg=1）即 XML SSO
    row = {
        "build": str(build),
        "uuid": uuid,
        "arch": "x86_64",
        "hook_off": format(parse_entry, "#x"),
        "msg_arg": 1,
        "xml_sso_off": 0,
        "expected": prologue.hex().upper(),
    }
    print(json.dumps(row, ensure_ascii=False))
    print(f"# parse {parse_entry:#x} call {call_site:#x} wrapper {wrapper_entry:#x} "
          f"uuid {uuid} build {build}", file=sys.stderr)


if __name__ == "__main__":
    main()
