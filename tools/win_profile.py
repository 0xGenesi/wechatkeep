#!/usr/bin/env python3
"""win_profile.py — Windows 函数画像：.pdata 边界内全部 call 目标 + rip 引用串。

来源：Windows spike 会话（var/win/profile.py 正化入库，更名 win_profile
避免与 stdlib profile 模块撞名；原工件保留 var/win/）。用于快速定性
（找 memcpy 模板 / DB API / WCDB 形态），替代全量反汇编通读——75 轮
五函数家族定性与链式行走的日常起点。

用法（--dll/WXKEEP_WIN_DLL 同 tools/winre.py；缺省 var/win 4.1.15.56）:
  var/venv/bin/python tools/win_profile.py <va-hex> [<va-hex>...]
依赖 tools/winre.py（同目录）+ capstone（var/venv）。
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import winre


def func_bounds(pe, va):
    i = bisect.bisect_right(pe.funcs, va) - 1
    f = pe.funcs[i]
    nxt = pe.funcs[i + 1] if i + 1 < len(pe.funcs) else f + 0x1000
    return f, nxt


def profile(pe, va, max_calls=60):
    f, nxt = func_bounds(pe, va)
    off = pe.va2off(f)
    m = winre.md()
    calls, strs = [], []
    for ins in m.disasm(pe.data[off:off + (nxt - f)], f):
        if ins.mnemonic == 'call':
            op = ins.operands[0]
            try:
                imm = op.imm
                calls.append((ins.address, imm))
            except Exception:
                calls.append((ins.address, None))
        for t in winre.resolve_rip(pe, ins):
            o = pe.va2off(t)
            if o is not None:
                raw = pe.data[o:o + 48]
                # SSO 短串 / rdata 常量串
                end = raw.find(b'\0')
                if 0 < end <= 47:
                    try:
                        s = raw[:end].decode('ascii')
                        if all(32 <= ord(c) < 127 for c in s) and len(s) >= 4:
                            strs.append((ins.address, t, s))
                    except UnicodeDecodeError:
                        pass
    return f, nxt, calls, strs


def main():
    dll = os.environ.get('WXKEEP_WIN_DLL', winre.DEFAULT_DLL)
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    pe = winre.PE(dll)
    for a in sys.argv[1:]:
        va = int(a, 16)
        f, nxt, calls, strs = profile(pe, va)
        print(f'=== {f:#x} .. {nxt:#x} ({nxt - f:#x}B)')
        cc = {}
        for site, t in calls:
            if t:
                cc.setdefault(t, []).append(site)
        for t in sorted(cc, key=lambda x: -len(cc[x])):
            marks = ' '.join(hex(s) for s in cc[t][:4])
            print(f'  call {t:#x} x{len(cc[t])}  @ {marks}')
        seen = set()
        for site, t, s in strs:
            if s in seen:
                continue
            seen.add(s)
            print(f'  str @ {site:#x} -> {t:#x}: "{s[:44]}"')


if __name__ == '__main__':
    main()
