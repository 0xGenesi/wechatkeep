#!/usr/bin/env python3
"""R6 静态正道（109 轮定下轮主攻）：consumer_main(0x31a96d8) 唯一直连
调用者 0x45a5910 所在函数的反汇编 + +0xb78 写入者猎捕。

输出：函数边界（idx func_of）、逐指令反汇编（BL 目标/分支落点标注、
str xN,[xM,#0xb78] 高亮）、函数内全部 +0xb78 偏移访问清单。
"""
import os
import sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")  # 仓库根（脚本入 tools/，工件在 var/ab——本地未分发）
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SLICE = os.path.join(ROOT, "var/ab/270135_arm64.dylib")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm64_index as ai

ix, func_of = ai.load(os.path.join(ROOT, "var/ab/270135_arm64.idx"))
funcs = ix["funcs"]
import bisect

KNOWN = {
    0x31a96d8: "consumer_main(消费主)", 0x31ab38c: "consumer2", 0x31ac2f0: "consumer3",
    0x32edaec: "svrid查找A", 0x309ac50: "svrid查找B",
    0x4cd5e8c: "撤回标记写", 0x102b740: "取消息对象",
    0x44541bc: "统一分发器", 0x45a4948: "handler",
}

def func_bounds(va):
    start = func_of(va)
    i = bisect.bisect_right(funcs, start)
    end = funcs[i] if i < len(funcs) else start + 0x200
    return start, end

data = open(SLICE, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

def disasm(start, end, label):
    print(f"\n{'='*74}\n== {label} @ 0x{start:x}..0x{end:x} (0x{end-start:x}B)\n{'='*74}")
    insns = list(md.disasm(data[start:end], start))
    b78 = []
    for i in insns:
        note = ""
        if i.mnemonic == "bl":
            t = int(i.op_str[1:], 16) if i.op_str.startswith("#") else None
            if t is not None:
                if t in KNOWN:
                    note = f"   ; >>> {KNOWN[t]}"
                elif func_of(t) == t:
                    note = f"   ; [func head 0x{t:x}]"
        if "#0xb78]" in i.op_str:
            note += "   ; <<< +0xb78 访问"
            b78.append((i.address, i.mnemonic, i.op_str))
        print(f"{i.address:x}: {i.mnemonic:<8} {i.op_str}{note}")
    if b78:
        print(f"\n-- +0xb78 访问 {len(b78)} 处:")
        for a, m, o in b78:
            print(f"   0x{a:x}: {m} {o}")
    return b78

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "caller"
    if which == "caller":
        va = 0x45a5910
        s, e = func_bounds(va)
        disasm(s, e, "consumer_main 唯一直连调用者（含 0x45a5910）")
    elif which == "bl-xref":
        # idx calls 图复核：consumer_main 的 BL 调用者（109 已做原始 BL 扫，
        # 这里走 idx 侧对拍）
        for site, f in ix["calls"].get(0x31a96d8, []):
            print(f"0x{site:x}: bl consumer_main  caller_func 0x{f:x}")
    else:
        va = int(which, 16)
        s, e = func_bounds(va)
        disasm(s, e, f"函数 @0x{va:x}")
