#!/usr/bin/env python3
"""R8 M4 直调表合同 RE（docs/RUNTIME-DESIGN R8 节，charter M4 前置）：
定案三缺口：① container 语义（ctor 0x34597c8 第 2 参来源）② 0xa 类型
判别面 ③ 入库服务（AddMessageResource 的 this=[入库服务+8]）运行时获取。
用法: r8_m4_contract.py <mode>
  svc      入库服务 0x34579d0 体内 ctor/AddMessageResource 调用区反汇编
  ctor     ctor 0x34597c8 全函数反汇编（stubmap 标注）
  amr      AddMessageResource 0x33fd190 入口区（x0/x1 形态+首 0x200B）
"""
import os
import sys, pickle, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm64_index as ai
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")  # 仓库根（脚本入 tools/，工件在 var/ab——本地未分发）

ix, func_of = ai.load(os.path.join(ROOT, "var/ab/270135_arm64.idx"))
funcs = ix["funcs"]
stubs = pickle.load(open(os.path.join(ROOT, "var/ab/270135_stubmap.pkl"), "rb"))
data = open(os.path.join(ROOT, "var/ab/270135_arm64.dylib"), "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

KNOWN = {
    0x33fd190: "AddMessageResource", 0x3aeddb4: "写枢纽", 0x33f748c: "逐项处理",
    0x3b1afc: "键值装配", 0x4cd5e8c: "撤回写点", 0x31a96d8: "consumer_main",
    0x32edaec: "lookup", 0x102b740: "getter", 0x34579d0: "入库服务",
    0x34597c8: "ctor", 0x3402f74: "svrid批量请求", 0x56f412c: "取订阅者",
    0x347cd3c: "ctor_sub1", 0x56fa6fc: "ctor_sub2", 0x2f717e8: "ctor_sub3",
    0x56fa308: "ctor_sub4", 0x4cd60c0: "写点自递归",
}

def func_bounds(va):
    start = func_of(va)
    i = bisect.bisect_right(funcs, start)
    end = funcs[i] if i < len(funcs) else start + 0x400
    return start, end

def bl_note(t):
    if t in KNOWN: return f"   ; >>> {KNOWN[t]}"
    if t in stubs: return f"   ; [stub {stubs[t].split('/')[-1]}]"
    if func_of(t) == t: return "   ; [func]"
    return f"   ; [into 0x{func_of(t):x}+0x{t-func_of(t):x}]"

def disasm(start, end, mark=None):
    for i in md.disasm(data[start:end], start):
        note = ""
        if i.mnemonic in ("bl", "b") and i.op_str.startswith("#"):
            try: t = int(i.op_str[1:], 16)
            except ValueError: t = None
            if t is not None: note = bl_note(t)
        tag = " <<<" if mark and i.address in mark else ""
        print(f"{i.address:x}: {i.mnemonic:<8} {i.op_str}{note}{tag}")

def find_bl_to(target):
    """全 __text 扫描 BL target 的调用点（返回指令 VA 列表）。"""
    hits = []
    for f0 in funcs:
        pass
    return hits

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "svc"
    if mode == "svc":
        s, e = func_bounds(0x34579d0)
        print(f"== 入库服务 0x34579d0 bounds 0x{s:x}..0x{e:x} ({e-s}B)")
        # 找体内 BL 0x34597c8 与 BL 0x33fd190 的位置，打上下文
        marks = []
        for i in md.disasm(data[s:e], s):
            if i.mnemonic == "bl" and i.op_str.startswith("#"):
                try: t = int(i.op_str[1:], 16)
                except ValueError: continue
                if t in (0x34597c8, 0x33fd190, 0x3402f74):
                    marks.append((i.address, KNOWN.get(t, hex(t))))
        print(f"== 体内关键调用点: {[(hex(a), n) for a, n in marks]}")
        for a, n in marks:
            lo = max(s, a - 0x40); hi = min(e, a + 0x30)
            print(f"\n---- {n} @ 0x{a:x} 上下文 ----")
            disasm(lo, hi, mark={a})
    elif mode == "ctor":
        s, e = func_bounds(0x34597c8)
        print(f"== ctor 0x34597c8 bounds 0x{s:x}..0x{e:x} ({e-s}B)")
        disasm(s, e)
    elif mode == "amr":
        s, e = func_bounds(0x33fd190)
        print(f"== AddMessageResource 0x33fd190 bounds 0x{s:x}..0x{e:x} ({e-s}B)")
        disasm(s, min(e, s + 0x280))

def _prologue():
    s, e = func_bounds(0x34579d0)
    print("== 入库服务序言（x20/x26 初始化）==")
    disasm(s, s + 0x100)
