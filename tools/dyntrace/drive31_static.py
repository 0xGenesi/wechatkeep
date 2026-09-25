#!/usr/bin/env python3
"""drive31 静态解剖：270100 x64 pristine 切片上，parse 返回后的删除/插入
分支定位（㊾ 实弹收缩出的邻域）。

已知地面真值（drive22/29/30 实弹 + ㉜ 静态）：
  parse        0x537dcd0（wrapper 唯一调用；wrapper call 返回址 0x537dc63）
  到达解析 F1  含 call→storage-parser（返回址 0x35595cc）与 call→B（返回址
               0x35595d7）——两 call 相邻 11B，同一函数
  B            含 call→revoke_manager（返回址 0x3559697）
  revoke_manager [0x394ae30..0x394e4c0)，call→wrapper 返回址 0x394bf73
  已排除（30 原生流零命中）：3421bb0 簇 / DBOP 0x3680980 / LOOKUP
  0x5311b30 / INSERT 0x3415a30 / handlercmp 0x3445e20

输出：三区间的 capstone 反汇编（call/jmp 解析目标 + 已知函数命名 +
rip-rel 字符串引用对照 decrypt_strings），供人工判读删除/插入分支。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))   # tools/machutil.py
import machutil  # noqa: E402
import capstone  # noqa: E402

X64 = machutil.CPU_X86_64
DYLIB = os.path.join(ROOT, 'var/wxarm/270100_x64.dylib')

PARSE = 0x537DCD0
WRAP_RET = 0x537DC63
REGIONS = [
    # 锚点 = 实弹 bt 的返回址（调用位点）——函数边界由 FUNCTION_STARTS 反解
    ("F1-arrival", 0x35595CC),      # call→storage-parser 返回址（B 路起点同函数 +0xB）
    ("B-dispatch", 0x3559697),      # call→revoke_manager 返回址
    ("revoke_manager", 0x394BF73),  # call→wrapper→parse 返回址
]
KNOWN = {
    0x537DCD0: "PARSE",
    0x5311B30: "DBLOOKUP(excl)",
    0x3680980: "DBOPFN(excl)",
    0x3415A30: "DBINSERT(excl)",
    0x3421BB0: "CB(excl)",
    0x3444B40: "share_card_handler(excl)",
}


def main():
    d = machutil.load_slice(DYLIB, X64)
    starts = machutil.function_starts(d)
    strings = json.load(open(os.path.join(ROOT, 'var/wxarm/270100_strings.json')))
    str_by_site = {int(s['site'], 16): s['str'] for s in strings}

    def func_of(va):
        prev = None
        for s in starts:
            if s > va:
                break
            prev = s
        return prev

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # 三个调用位点所在的真实函数边界
    anchored = []
    for name, site in REGIONS:
        fs = func_of(site)
        nxt = next((s for s in starts if s > fs), None)
        anchored.append((name, fs, nxt, site))
        print(f"== {name}: site {site:#x} -> function {fs:#x}..{nxt:#x} "
              f"({(nxt or fs + 0x2000) - fs:#x}B)")

    for name, fs, nxt, site in anchored:
        end = min(nxt or fs + 0x3000, fs + 0x4000)
        off = machutil.va2off(d, fs)
        code = d[off:off + (end - fs)]
        print(f"\n===== {name} {fs:#x}..{end:#x} (site {site:#x}) =====")
        for ins in md.disasm(code, fs):
            line = f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}"
            note = ""
            if ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
                tgt = int(ins.op_str, 16)
                if tgt in KNOWN:
                    note = f"  ; ★ {KNOWN[tgt]}"
            if 'rip' in ins.op_str:
                import re
                m = re.search(r'\[rip \+ (0x[0-9a-f]+)\]', ins.op_str)
                if m:
                    va = ins.address + ins.size + int(m.group(1), 16)
                    if va in str_by_site:
                        note += f"  ; str {str_by_site[va][:60]!r}"
            if ins.address == site:
                note += "  <<< 实弹返回址"
            if note or ins.mnemonic in ('call', 'ret'):
                print(line + note)


if __name__ == '__main__':
    main()
