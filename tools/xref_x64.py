#!/usr/bin/env python3
"""270099 x64 静态交叉引用工具（LC_FUNCTION_STARTS 边界 + E8 对齐验证）
输入 dylib 放仓库 var/wxarm/（持久；/tmp 会被清）：
  lipo -thin x86_64 /Applications/WeChat.app/Contents/Resources/wechat.dylib \
    -output var/wxarm/new270099_x64.dylib
用法:
  python3 tools/xref_x64.py [--dylib <path>] callers <fn-va-hex>
  python3 tools/xref_x64.py dis <va-hex> [n] | find <str> | xrefs <str>
  （--dylib 缺省取 var/wxarm/new270099_x64.dylib，或环境变量 WXKEEP_X64_DYLIB）
依赖 tools/machutil.py（段表/function_starts 统一口径）。
"""
import bisect
import os
import struct
import sys

import capstone
import machutil

DEFAULT_DYLIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             'var', 'wxarm', 'new270099_x64.dylib')


def load(path):
    d = open(path, 'rb').read()
    ta, tsz, to = machutil.text_range(d)
    sections = {(seg, sect): (addr, size, off)
                for seg, sect, addr, size, off in machutil.sections(d)}
    funcs = sorted(set(machutil.function_starts(d)))
    return d, ta, tsz, to, sections, funcs


def func_of(funcs, va):
    i = bisect.bisect_right(funcs, va) - 1
    return funcs[i] if i >= 0 else None


def func_end(ta, tsz, funcs, va):
    i = bisect.bisect_right(funcs, va)
    return funcs[i] if i < len(funcs) else ta + tsz


def disasm(md, d, ta, to, va, n=16):
    off = va - ta + to
    out = []
    for ins in md.disasm(d[off:off + n * 18], va):
        out.append(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
        if len(out) >= n:
            break
    return out


def aligned(md, d, ta, to, site):
    """E8 对齐验证：site-1..site-16 任一起点线性反汇编恰好落在 site"""
    off = site - ta + to
    for k in range(1, 17):
        o = off - k
        for ins in md.disasm(d[o:off + 16], site - k):
            if ins.address == site:
                return True
            if ins.address > site:
                break
    return False


def callers_of(md, d, ta, tsz, to, funcs, target):
    res = []
    blob = d[to:to + tsz]
    pos = 0
    while True:
        i = blob.find(b'\xe8', pos)
        if i < 0:
            break
        pos = i + 1
        rel = struct.unpack_from('<i', blob, i + 1)[0]
        if rel + (i + ta) + 5 != target:
            continue
        site = ta + i
        if aligned(md, d, ta, to, site):
            res.append((site, func_of(funcs, site)))
    return res


def find_str(d, s):
    out, pos = [], 0
    b = s.encode() if isinstance(s, str) else s
    while True:
        i = d.find(b, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def rip_xrefs(d, ta, tsz, to, sections, target_off):
    """__text 内 lea rip-rel 引用（目标为文件偏移 target_off）。
    模式 = REX(48/4c) 8d modrm(mod=00,rm=101) disp32——旧实现找单个 0x8d 再回看
    两字节，实际匹配的是 `48 8d 8d`（lea [rbp+d]）形态，rip 引用恒漏（2026-09
    审计实测发现：对 libsystem_kernel 全零命中）。"""
    res = []
    blob = d[to:to + tsz]
    for rex in (b'\x48\x8d', b'\x4c\x8d'):
        pos = 0
        while True:
            i = blob.find(rex, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 7 > len(blob):
                continue
            modrm = blob[i + 2]
            if (modrm & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from('<i', blob, i + 3)[0]
            site = ta + i
            tgt_va = site + 7 + disp   # rip = 指令末尾
            for (_seg, _sec), (addr, size, off) in sections.items():
                if addr and addr <= tgt_va < addr + size:
                    if off + (tgt_va - addr) == target_off:
                        res.append(site)
                    break
    return res


def main():
    args = sys.argv[1:]
    if args and args[0] == '--dylib':
        if len(args) < 2:
            raise SystemExit('--dylib 需要路径参数')
        path, args = args[1], args[2:]
    else:
        path = os.environ.get('WXKEEP_X64_DYLIB', DEFAULT_DYLIB)
    if not args:
        raise SystemExit(__doc__)
    cmd = args[0]

    if not os.path.exists(path):
        raise SystemExit(f'输入 dylib 不存在: {path}\n'
                         f'（lipo -thin x86_64 <wechat.dylib> -output {path}）')
    d, ta, tsz, to, sections, funcs = load(path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    print(f'__text [{ta:#x}..{ta + tsz:#x}) fileoff={to:#x} functions={len(funcs)}',
          file=sys.stderr)

    if cmd == 'callers':
        t = int(args[1], 16)
        for site, f in callers_of(md, d, ta, tsz, to, funcs, t):
            print(f'call@{site:#x} in [{f:#x}..{func_end(ta, tsz, funcs, f):#x})')
    elif cmd == 'dis':
        va = int(args[1], 16)
        n = int(args[2]) if len(args) > 2 else 20
        print('\n'.join(disasm(md, d, ta, to, va, n)))
    elif cmd == 'find':
        for off in find_str(d, args[1]):
            print(f'{off:#x}')
    elif cmd == 'xrefs':
        for off in find_str(d, args[1]):
            for s in rip_xrefs(d, ta, tsz, to, sections, off):
                print(f'str@{off:#x} <- lea@{s:#x} in '
                      f'[{func_of(funcs, s):#x}..{func_end(ta, tsz, funcs, s):#x})')
    else:
        raise SystemExit(f'未知子命令: {cmd}\n{__doc__}')


if __name__ == '__main__':
    main()
