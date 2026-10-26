#!/usr/bin/env python3
"""arm64_index.py — arm64 切片全量引用索引（capstone 重同步线性扫描）。

来源：76/77 轮 arm64 链全图 derive 会话主力工具（var/ab/arm64_index.py
正化入库，原工件保留在 var/）。一次构建（~2-4 分钟，29M 指令；resync
规避 literal-pool 数据截断），pickle 复用：

  refs:  有效地址(VA) -> [(site_va, kind)]   kind ∈ adrp_add / adrp_ldr
  calls: 直接 BL 目标 -> [(site_va, caller_func)]

「anchor 字符串/目标 VA → 引用者 → 链式行走」五步法的索引基座（76 轮
方法论）。已知边界：远偏移 adrp+ldr（>4 指令窗口）与加法链形态不在此
索引内（76 轮 re-derive 首探的负结果——引用者定位需扩展窗口或 Ghidra）。

用法（显式路径，无隐式缺省——索引与切片配对是调用方责任）:
  var/venv/bin/python tools/arm64_index.py build <slice.dylib> <out.idx>
  var/venv/bin/python tools/arm64_index.py query <idx> <va-hex>...
  var/venv/bin/python tools/arm64_index.py near <idx> <va-hex> <window>
  # near：[va-window, va] 内已索引目标（77 续二探——长表基址+偏移形态下
  # needle VA 本身无直引，但表基址在窗内；含 delta 与引用函数归属）
依赖 capstone（var/venv）+ tools/machutil.py。
"""
import bisect
import pickle
import sys

import capstone

import machutil


def build(slice_path, idx_path):
    d = machutil.load_slice(slice_path, machutil.CPU_ARM64)
    secs = [(s[0], s[1], s[2], s[3], s[4]) for s in machutil.sections(d)]
    ta, tsz, to = [(a, z, o) for seg, sect, a, z, o in secs
                   if (seg, sect) == ('__TEXT', '__text')][0]
    funcs = sorted(set(machutil.function_starts(d)))

    def func_of(va):
        i = bisect.bisect_right(funcs, va) - 1
        return funcs[i] if i >= 0 else 0

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    refs = {}
    calls = {}
    buf = d[to:to + tsz]
    pos = 0
    n = len(buf)
    insns = 0
    while pos < n:
        ins = next(md.disasm(buf[pos:pos + 16], ta + pos), None)
        if ins is None:
            pos += 4          # 数据/池：跳一个 word 重同步
            continue
        insns += 1
        site = ins.address
        if ins.mnemonic == 'bl':
            op = ins.operands[0]
            if op.type == capstone.arm64.ARM64_OP_IMM:
                calls.setdefault(op.imm, []).append((site, func_of(site)))
        elif ins.mnemonic in ('adrp',):
            # 向后看 ≤4 条找同基址寄存器的 add/ldr
            page = None
            for op in ins.operands:
                if op.type == capstone.arm64.ARM64_OP_IMM:
                    page = op.imm      # capstone 给出绝对页地址
            rn = ins.operands[0].reg if ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_REG else None
            if page is not None and rn is not None:
                off = pos + ins.size
                for _ in range(4):
                    nx = next(md.disasm(buf[off:off + 16], ta + off), None)
                    if nx is None:
                        break
                    off += nx.size
                    if nx.mnemonic in ('add', 'ldr', 'ldrb', 'ldur', 'ldrsb') and len(nx.operands) >= 2:
                        m = nx.operands[1].mem if nx.operands[1].type == capstone.arm64.ARM64_OP_MEM else None
                        if m is not None and m.base == rn:
                            tgt = page + m.disp
                            refs.setdefault(tgt, []).append((site, 'adrp_ldr'))
                            break
                        if nx.mnemonic == 'add' and nx.operands[1].type == capstone.arm64.ARM64_OP_REG \
                           and nx.operands[1].reg == rn:
                            imm = nx.operands[2].imm if len(nx.operands) > 2 and \
                                nx.operands[2].type == capstone.arm64.ARM64_OP_IMM else 0
                            tgt = page + imm
                            refs.setdefault(tgt, []).append((site, 'adrp_add'))
                            break
        pos += ins.size
    print(f'{insns} insns, {len(refs)} ref targets, {len(calls)} bl targets')
    with open(idx_path, 'wb') as f:
        pickle.dump({'refs': refs, 'calls': calls, 'funcs': funcs}, f)
    print('index saved', idx_path)


def load(idx_path):
    with open(idx_path, 'rb') as f:
        ix = pickle.load(f)
    funcs = ix['funcs']

    def func_of(va):
        i = bisect.bisect_right(funcs, va) - 1
        return funcs[i] if i >= 0 else 0
    return ix, func_of


def main():
    argv = sys.argv[1:]
    if len(argv) >= 3 and argv[0] == 'build':
        build(argv[1], argv[2])
    elif len(argv) >= 3 and argv[0] == 'query':
        ix, func_of = load(argv[1])
        for a in argv[2:]:
            va = int(a, 16)
            for site, kind in ix['refs'].get(va, []):
                print(f'{site:#x}: {kind}  func {func_of(site):#x}')
            for site, f in ix['calls'].get(va, []):
                print(f'{site:#x}: bl  caller {f:#x}')
    elif len(argv) >= 3 and argv[0] == 'near':
        ix, func_of = load(argv[1])
        va = int(argv[2], 16)
        window = int(argv[3], 16)
        targets = sorted(ix['refs'].keys())
        lo = bisect.bisect_left(targets, va - window)
        hi = bisect.bisect_right(targets, va)
        for t in targets[lo:hi]:
            refs = ix['refs'][t]
            fs = sorted(set(func_of(s) for s, _ in refs))
            print(f'{t:#x} (delta -{va - t:#x}) refs {len(refs)} '
                  f'funcs {" ".join(hex(f) for f in fs[:8])}')
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main()
