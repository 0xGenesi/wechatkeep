#!/usr/bin/env python3
"""R7 插入族队列归属 RE（docs/RUNTIME-DESIGN R7 节）：
   0x33fd190(AddMessageResource) / 0x3aeddb4(写枢纽) 全函数反汇编，
   BL 目标经 stubmap 解析为符号名（dispatch_*/objc/GCD 面全标注），
   任务 vtable 0x9f2b3b8 的 execute 函数指针读出并追踪。
用法: r7_insert_queue.py <mode> [va]
  fnda / fndb  反汇编两主函数（BL 符号标注）
  xref <va>    idx BL 入边 + stubmap 反查（谁调它）
  vtable <va>  读 vtable 前 N 槽（chained-fixup rebase 解析）
"""
import os
import sys, pickle, bisect
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")  # 仓库根（脚本入 tools/，工件在 var/ab——本地未分发）
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SLICE = os.path.join(ROOT, "var/ab/270135_arm64.dylib")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm64_index as ai

ix, func_of = ai.load(os.path.join(ROOT, "var/ab/270135_arm64.idx"))
funcs = ix["funcs"]
stubs = pickle.load(open(os.path.join(ROOT, "var/ab/270135_stubmap.pkl"), "rb"))
data = open(SLICE, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

KNOWN = {
    0x33fd190: "AddMessageResource", 0x3aeddb4: "写枢纽", 0x33f748c: "逐项处理",
    0x3b1afc: "键值装配", 0x4cd5e8c: "撤回写点", 0x31a96d8: "consumer_main",
    0x32edaec: "lookup", 0x102b740: "getter", 0x4190130: "表注册",
    0x4195490: "SELECT", 0x4195ca0: "INSERT", 0x4196130: "清理A", 0x4196650: "清理B",
}
QUEUE_STUBS = {va: name for va, name in stubs.items()
               if any(k in name for k in ("dispatch_async", "dispatch_sync", "dispatch_barrier",
                                          "dispatch_get_global", "dispatch_queue_create",
                                          "dispatch_after", "dispatch_resume", "dispatch_group"))}

def func_bounds(va):
    start = func_of(va)
    i = bisect.bisect_right(funcs, start)
    end = funcs[i] if i < len(funcs) else start + 0x400
    return start, end

def bl_note(t):
    if t in KNOWN: return f"   ; >>> {KNOWN[t]}"
    if t in QUEUE_STUBS: return f"   ; *** GCD {stubs[t]} ***"
    if t in stubs: return f"   ; [stub {stubs[t].split('/')[-1]}]"
    if func_of(t) == t: return "   ; [func]"
    f = func_of(t)
    return f"   ; [into 0x{f:x}+0x{t-f:x}]"

def disasm(start, end):
    insns = list(md.disasm(data[start:end], start))
    gcd = []
    for i in insns:
        note = ""
        if i.mnemonic in ("bl", "b") and i.op_str.startswith("#"):
            try: t = int(i.op_str[1:], 16)
            except ValueError: t = None
            if t is not None: note = bl_note(t)
        if "GCD" in note: gcd.append((i.address, note.strip("; *").strip()))
        print(f"{i.address:x}: {i.mnemonic:<8} {i.op_str}{note}")
    return gcd

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "fnda"
    if mode == "fnda":
        s, e = func_bounds(0x33fd190)
        print(f"== AddMessageResource 0x{s:x}..0x{e:x} ({e-s}B)")
        g = disasm(s, min(e, s + 0x600))
        print(f"\n== GCD 调用（前 0x600B 内）: {g}")
    elif mode == "fndb":
        s, e = func_bounds(0x3aeddb4)
        print(f"== 写枢纽 0x{s:x}..0x{e:x} ({e-s}B)")
        g = disasm(s, min(e, s + 0x600))
        print(f"\n== GCD 调用: {g}")
    elif mode == "size":
        for va in (0x33fd190, 0x3aeddb4, 0x33f748c, 0x3b1afc):
            s, e = func_bounds(va)
            print(f"0x{va:x}: 0x{e-s:x} ({e-s}B)")
    elif mode == "vtable":
        va = int(sys.argv[2], 16)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        for i in range(n):
            w = int.from_bytes(data[va + i*8: va + i*8 + 8], "little")
            tag = ""
            if func_of(w) == w: tag = f"[func] {stubs.get(w,'')}"
            print(f"+0x{i*8:x}: 0x{w:x} {tag}")
