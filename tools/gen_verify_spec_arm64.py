#!/usr/bin/env python3
"""
gen_verify_spec_arm64.py — arm64 行为验证规格派生（gen_verify_spec 的 arm64 孪生）。

arm64 的撤回补丁 = parse 函数内 cbz 分支翻转（非独立函数），但 parse 里
喂值给 cbz 的比较谓词是独立小函数（bl 紧贴 cbz 之前：
    mov x0, x22 ; bl <pred> ; cbz w0, <skip>
谓词 = "revokemsg" SSO 比较器，w0 返回 0/1）——可出进程直接调用，
行为验证在 arm64 由此成立。

对 arm64 谓词自动提取（270100 实测形态）：
  stubs        : 谓词内的 bl 桩（adrp x16/ldr x16,[x16,#off]/br x16 三件套），
                 按调用序映射 [strlen, memcmp]
  zero_regions : "revokemsg" 懒初始化槽（memcmp 调用前的 adrp+add x1 基址；
                 槽 + guard 位在 16B 内）→ 清 16 字节
  probes       : 默认探针集（revokemsg→1 其余→0）
  target       : 谓词 VA（cbz 位点 -4 处 bl 反解）

⚠ arm64 SSO 布局与 x64 不同：短串数据在偏移 0、长度字节在 +0x17（直接
  长度非 <<1）——worker 侧按此构造探针。谓词不是 arm64 补丁位点（cbz 才
  是），patched 态下谓词行为不变：arm64 行为验证的语义 = 家族完整性自检
  + 谓词输入路径证明（详见 ROADMAP ㉝）。

用法: python3 tools/gen_verify_spec_arm64.py <thin-arm64-dylib> <cbz-site-VA-hex>
"""
import json
import sys

import machutil

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit('需要 capstone: pip3 install capstone')

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def adrp_target(insn_addr, word):
    """adrp Xd, <page> → 绝对页地址（PC 相对 ±4GB）。"""
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return ((insn_addr & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def is_adrp(word):
    return (word >> 31) == 1 and ((word >> 24) & 0x1F) == 0x10


def is_add_imm(word):
    return (word >> 23) & 0x1FF == 0x122   # ADD (immediate) 64-bit: sf=1 op=0 S=0 100010


def add_imm12(word):
    return (word >> 10) & 0xFFF


def is_ldr_imm_x16(word):
    """LDR (immediate, unsigned offset) Xt,[Xn,#imm12]，64 位。"""
    return (word >> 22) & 0x3FF == 0x3E5 and ((word >> 5) & 0x1F) == 16


def ldr_imm12(word):
    return ((word >> 10) & 0xFFF) * 8


def is_br_x16(word):
    return word == 0xD61F0200


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    d = machutil.load_slice(sys.argv[1], machutil.CPU_ARM64)
    site = int(sys.argv[2], 16)

    # 1. cbz 位点 -4 处必须 BL（谓词调用）
    off = machutil.va2off(d, site - 4)
    word = int.from_bytes(d[off:off + 4], 'little')
    if (word >> 26) != 0x25:   # BL: 100101
        sys.exit(f'{site - 4:#x} 不是 BL（{word:08X}）——gen3 形态不符')
    imm26 = word & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    pred = site - 4 + imm26 * 4

    # 2. 谓词函数边界
    import bisect
    funcs = machutil.function_starts(d)
    i = bisect.bisect_right(funcs, pred)
    end = funcs[i] if i < len(funcs) else pred + 0x400
    fo = machutil.va2off(d, pred)
    code = d[fo:fo + (end - pred)]

    # 3. 扫描：bl 桩（校验三件套形态）+ memcmp 前的 adrp+add x1（懒初始化槽）
    stubs = {}          # stub VA hex → semantic
    zero = []
    semantic_cycle = ["strlen", "memcmp", "memcmp", "memcmp"]
    insns = list(MD.disasm(code, pred))
    words = [int.from_bytes(code[j:j+4], 'little') for j in range(0, len(code) - 3, 4)]

    for j, insn in enumerate(insns):
        if insn.mnemonic != 'bl':
            continue
        tgt = int(insn.op_str.replace('#', ''), 16)
        toff = machutil.va2off(d, tgt)
        if toff is None:
            continue
        s = d[toff:toff + 12]
        w = [int.from_bytes(s[k:k+4], 'little') for k in (0, 4, 8)]
        if is_adrp(w[0]) and is_ldr_imm_x16(w[1]) and is_br_x16(w[2]):
            key = format(tgt, 'X')
            if key not in stubs:
                stubs[key] = (semantic_cycle[len(stubs)]
                              if len(stubs) < len(semantic_cycle) else f"fn{len(stubs)}")

    # 懒初始化槽：memcmp（第 2 个桩）调用前最近的一对 adrp+add X1
    memcmp_stub = next((int(k, 16) for k, v in stubs.items() if v == 'memcmp'), None)
    if memcmp_stub:
        for j, insn in enumerate(insns):
            if insn.mnemonic == 'bl' and int(insn.op_str.replace('#', ''), 16) == memcmp_stub:
                for k in range(j - 1, max(0, j - 8), -1):
                    a = insns[k]
                    if a.mnemonic == 'adrp':
                        page = int(a.op_str.split('#')[1], 16)
                        # 找紧随的 add Xn, Xn, #off
                        b = insns[k + 1] if k + 1 < len(insns) else None
                        if b is not None and b.mnemonic == 'add' and ',' in b.op_str:
                            parts = [p.strip() for p in b.op_str.split(',')]
                            offv = int(parts[-1].replace('#', ''), 16)
                            slot = page + offv
                            zero = [[format(slot, 'X'), '16']]
                break

    spec = {
        "stubs": stubs,
        "zero_regions": zero,
        "probes": [["revokemsg", "1"], ["sysmsg", "0"], ["NewMsg", "0"], ["", "0"]],
        "_generated": f"arm64 predicate 0x{pred:X} (cbz 0x{site:X}) on {sys.argv[1]}"
    }
    print(json.dumps(spec, indent=2))
    print(f'# target(谓词) = 0x{pred:X}', file=sys.stderr)


if __name__ == '__main__':
    main()
