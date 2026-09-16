#!/usr/bin/env python3
"""
gen_verify_spec.py — 从补丁点自动反解行为验证规格（verify spec）。

对 x64 比较函数（isRevokemsg 同构体）反汇编，自动提取：
  stubs        : 函数 call 的 PLT 桩（ff 25 → GOT 槽），按调用序映射
                 [strlen, memcmp]（第 1 个外部调用取全局常量长度、第 2 个做内容比较）
  zero_regions : movabs 懒初始化写入的字符串槽（mov [rip+X], rax 的 X，清 16 字节）
  probes       : 默认探针集（revokemsg→1 其余→0）

用法: python3 tools/gen_verify_spec.py <thin-x64-dylib> <site-VA-hex>
输出: verify spec JSON（贴进 signatures.json 对应配方的 "verify" 字段）
"""
import json
import struct
import sys

from capstone import *
from capstone.x86 import X86_REG_RIP, X86_OP_MEM, X86_OP_IMM

def parse_text(d):
    p, ncmds, secs = 32, struct.unpack_from('<I', d, 16)[0], []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, p)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', d, p+64)[0]; sp = p+72
            for i in range(nsects):
                sname = d[sp:sp+16].rstrip(b'\0').decode()
                saddr, ssize = struct.unpack_from('<QQ', d, sp+32)
                soff = struct.unpack_from('<I', d, sp+48)[0]
                secs.append((sname, saddr, ssize, soff)); sp += 80
        if cmdsize == 0: break
        p += cmdsize
    return next(s for s in secs if s[0] == '__text')

def parse_segments(d):
    """__TEXT 段级 VA→fileoff（PLT 桩在 __stubs，不在 __text——section 级换算会漏）。"""
    p, ncmds, segs = 32, struct.unpack_from('<I', d, 16)[0], []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, p)
        if cmd == 0x19:
            segname = d[p+8:p+24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, _ = struct.unpack_from('<QQQQ', d, p+24)
            segs.append((segname, vmaddr, vmsize, fileoff))
        if cmdsize == 0: break
        p += cmdsize
    return segs

def va2off(text, va):
    return text[3] + (va - text[1])

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    d = open(sys.argv[1], 'rb').read()
    site = int(sys.argv[2], 16)
    text = parse_text(d)
    segs = parse_segments(d)
    def seg_off(va):
        for name, vmaddr, vmsize, fileoff in segs:
            if vmaddr <= va < vmaddr + vmsize:
                return fileoff + (va - vmaddr)
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    fn = d[va2off(text, site):va2off(text, site) + 0x120]
    stubs = {}          # stub VA hex -> semantic
    zero = []           # [hexVA, "16"]
    semantic_cycle = ["strlen", "memcmp", "memcmp", "memcmp"]

    # 两遍独立扫描（对同一 Cs 对象嵌套 disasm 会互相干扰迭代状态）
    insns = list(md.disasm(fn, site))

    for insn in insns:
        if insn.mnemonic == 'call' and insn.operands and insn.operands[0].type == X86_OP_IMM:
            tgt = insn.operands[0].imm
            toff = seg_off(tgt)   # 段级换算：桩可能位于 __stubs 等 text 外 section
            if toff is None or toff + 6 > len(d): continue
            if d[toff] == 0xFF and d[toff+1] == 0x25:   # PLT 桩
                key = format(tgt, 'X')
                if key not in stubs:
                    stubs[key] = semantic_cycle[len(stubs)] if len(stubs) < len(semantic_cycle) else f"fn{len(stubs)}"

    for i, insn in enumerate(insns[:-1]):
        # 懒初始化: movabs rax, imm64 紧跟 mov qword [rip+X], rax → X 是字符串槽起点
        if insn.mnemonic == 'movabs' and insn.op_str.startswith('rax,') \
           and insns[i+1].mnemonic == 'mov' and insns[i+1].op_str.startswith('qword ptr [rip'):
            nxt = insns[i+1]
            tgt = nxt.address + nxt.size + nxt.operands[0].mem.disp
            zero.append([format(tgt, 'X'), "16"])

    spec = {
        "stubs": stubs,
        "zero_regions": zero,
        "probes": [["revokemsg", "1"], ["sysmsg", "0"], ["NewMsg", "0"], ["", "0"]],
        "_generated": f"site 0x{site:X} on {sys.argv[1]}"
    }
    print(json.dumps(spec, indent=2))

if __name__ == '__main__':
    main()
