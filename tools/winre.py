#!/usr/bin/env python3
"""winre.py — Windows Weixin.dll（PE32+ x64）RE 工具箱（75 轮 spike 方法论成品）。

来源：Windows spike 会话（var/win/winre.py 正化入库，原工件保留 var/）。
与 macOS 侧 tools/xref_x64.py + tools/decrypt_strings.py 同构：
  PE 段表解析（自写极简，无 pefile 依赖）+ 字节模式扫描 + capstone 反汇编
  + rip 相对寻址解析 + E8/E9/rip-LEA **rel32 算术扫描**直接调用图（75 轮
  教训：capstone 线性扫描遇坏字节即停，「零调用者」假阴性——与
  tools/xref_x64.py 同法修正后的正确实现）+ xlog 混淆串静态解密（同款
  i%20 滚动密钥——Weixin 4.x 与 wechat.dylib 同一 C++ 代码库）。

函数边界 = .pdata RUNTIME_FUNCTION（PE 版 LC_FUNCTION_STARTS，513,887
函数级权威）；序言启发仅为缺失兜顶。docs/WINDOWS-SPIKE.md 有全链用例。

用法（--dll 或 WXKEEP_WIN_DLL 指定 DLL；缺省 var/win 工件区的 4.1.15.56）:
  winre.py sections
  winre.py find <hex-bytes|ascii:str>          # 全 .text 模式扫描（movabs 立即数等）
  winre.py dis <va> [n]                        # VA 反汇编
  winre.py xrefs <va>                          # rip 相对引用 + E8/E9 直接调用
  winre.py callers <va> / callees <va>          # 直接调用图
  winre.py funcinfo <va>                        # .pdata 函数边界与归属
  winre.py decrypt [--grep kw]                 # xlog 混淆串解密（函数归属）
  winre.py str2va <ascii>                      # 找明文串的 VA（含结尾判断）
"""
import argparse, bisect, os, re, struct, sys

import capstone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DLL = os.path.join(REPO_ROOT, 'var/win/extracted/payload/4.1.15.56/Weixin.dll')


class PE:
    def __init__(self, path):
        self.path = path
        self.data = d = open(path, 'rb').read()
        e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
        assert d[e_lfanew:e_lfanew + 4] == b'PE\0\0'
        coff = e_lfanew + 4
        machine, nsec, _, _, _, opt_sz, _ = struct.unpack_from('<HHIIIHH', d, coff)
        assert machine == 0x8664, 'expect x64'
        opt = coff + 20
        self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        self.sections = []
        sec = opt + opt_sz
        for i in range(nsec):
            name, vsz, vaddr, rsz, roff = struct.unpack_from('<8sIIII', d, sec + i * 40)
            self.sections.append({
                'name': name.rstrip(b'\0').decode(errors='replace'),
                'vaddr': vaddr, 'vsize': vsz, 'roff': roff, 'rsz': rsz})
        t = self.sec('.text')
        self.text_va = self.image_base + t['vaddr']
        self.text_rva = t['vaddr']
        self.text_off = t['roff']
        self.text_sz = t['rsz']
        # .pdata RUNTIME_FUNCTION = 权威函数边界（PE 版 function_starts）
        self.funcs = []
        pd = self.sec('.pdata') if any(s['name'] == '.pdata' for s in self.sections) else None
        if pd:
            d_ = self.data
            for o in range(pd['roff'], pd['roff'] + min(pd['rsz'], pd['vsize']), 12):
                beg, end, _ = struct.unpack_from('<III', d_, o)
                if not beg:
                    break
                self.funcs.append(self.image_base + beg)

    def sec(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        raise KeyError(name)

    def va2off(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rsz']):
                o = s['roff'] + (rva - s['vaddr'])
                return o if o < s['roff'] + s['rsz'] else None
        return None

    def off2va(self, off):
        for s in self.sections:
            if s['roff'] <= off < s['roff'] + s['rsz']:
                return self.image_base + s['vaddr'] + (off - s['roff'])
        return None


PROLOGUES = (b'\x55\x48\x89\xe5', b'\x40\x55', b'\x48\x83\xec', b'\x48\x81\xec',
             b'\x55', b'\x41\x57', b'\x41\x56', b'\x41\x55', b'\x41\x54',
             b'\x53', b'\x56', b'\x57', b'\x48\x8d\x64\x24')


def func_start(pe, va):
    """.pdata 权威边界；缺失时退序言启发。"""
    if pe.funcs:
        i = bisect.bisect_right(pe.funcs, va) - 1
        return pe.funcs[i] if i >= 0 else None
    off = pe.va2off(va)
    if off is None:
        return None
    lo = max(pe.text_off, off - 0x4000)
    d = pe.data
    for o in range(off, lo, -1):
        pre = d[o - 1] if o - 1 >= pe.text_off else 0xCC
        if pre in (0xCC,) or (pre == 0x90):
            for pl in PROLOGUES:
                if d[o:o + len(pl)] == pl:
                    return pe.off2va(o)
    return None


def md():
    m = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    m.detail = True
    return m


def resolve_rip(pe, ins):
    """返回指令内 rip 相对目标 VA 列表。"""
    out = []
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            out.append(ins.address + ins.size + op.mem.disp)
    return out


def scan_xrefs(pe, targets):
    """全 .text rel32 算术扫描（不受坏字节截断）：E8/E9 直接调用 + 48/4C 8D rip-LEA。
    比 capstone 线性扫描可靠（后者遇数据字节即停，覆盖率不完——75 轮首版
    「零调用者」假阴性的根因）。"""
    import re as _re
    tset = set(targets)
    hits = []
    d = pe.data
    t, tsz = pe.text_off, pe.text_sz
    va = lambda i: pe.text_va + (i - t)
    # E8/E9 rel32 直接 call/jmp
    for m in _re.finditer(rb'[\xe8\xe9](....)', d[t:t + tsz], _re.S):
        i = m.start() + t
        rel = struct.unpack_from('<i', d, i + 1)[0]
        dst = va(i) + 5 + rel
        if dst in tset:
            hits.append((va(i), 'call' if d[i] == 0xE8 else 'jmp', dst))
    # 48/4C 8D /r (rip-rel: modrm mod=00 rm=101)
    for m in _re.finditer(rb'[\x48\x4c]\x8d(.)(....)', d[t:t + tsz], _re.S):
        i = m.start() + t
        modrm = d[i + 2]
        if modrm & 0xC7 != 0x05:
            continue
        rel = struct.unpack_from('<i', d, i + 3)[0]
        dst = va(i) + 7 + rel
        if dst in tset:
            hits.append((va(i), 'lea', dst))
    return hits


PATS = [
    rb'\x0f\xb6\x44\x0e(.)\x04(.)\x32\x42(.)',
    rb'\x44\x0f\xb6\x44\x0e(.)\x44\x04(.)\x44\x32\x42(.)',
    rb'\x0f\xb6\x84\x0e(....)\x04(.)\x32\x42(.)',
    rb'\x44\x0f\xb6\x84\x0e(....)\x44\x04(.)\x44\x32\x42(.)',
]


def decrypt(pe, grep=None):
    d = pe.data
    to, tsz = pe.text_off, pe.text_sz
    out = []
    for pi, pat in enumerate(PATS):
        rx = re.compile(pat, re.S)
        pos = to
        while True:
            m = rx.search(d, pos, to + tsz)
            if not m:
                break
            off = m.start()
            gs = m.groups()
            data_off = gs[0][-1] if pi < 2 else struct.unpack('<I', gs[0])[0]
            addend, key_off = gs[1][-1], gs[2][-1]
            if data_off > 0x4000 or key_off > 0x4000:
                pos = off + 1
                continue
            va = pe.off2va(off)
            back = d[max(to, off - 0x60):off]
            base = None
            for k in range(len(back) - 6, -1, -1):
                if back[k:k + 3] == b'\x48\x8d\x0d':
                    bo = max(to, off - 0x60) + k
                    base = pe.off2va(bo) + 7 + struct.unpack_from('<i', back, k + 3)[0]
                    break
            span = m.end() - m.start()
            fwd = d[off + span:off + span + 0x60]
            length = None
            for k in range(len(fwd) - 3):
                if fwd[k:k + 2] == b'\x81\xfe':
                    length = struct.unpack_from('<I', fwd, k + 2)[0]
                    break
                if fwd[k:k + 2] == b'\x83\xfe':
                    length = struct.unpack_from('<b', fwd, k + 2)[0]
                    break
            if base is None or not (3 < (length or 0) <= 0x600):
                pos = off + 1
                continue
            bo = pe.va2off(base)
            if bo is None or bo + data_off + length > len(d) or bo + key_off + 32 > len(d):
                pos = off + 1
                continue
            best = None
            for mod in (20, 5, 10):
                buf = bytearray()
                for i2 in range(length):
                    b = (d[bo + data_off + i2] + addend) & 0xFF
                    b ^= d[bo + key_off + (i2 % mod)]
                    buf.append(b)
                try:
                    s = buf.decode('utf-8').rstrip('\0')
                    pr = sum(1 for c in s if 32 <= ord(c) < 127) / max(len(s), 1)
                except UnicodeDecodeError:
                    continue
                if pr > 0.9:
                    best = s
                    break
            if best:
                out.append({'func': hex(func_start(pe, va) or 0), 'site': hex(va), 'str': best})
            pos = off + max(1, span)
    if grep:
        out = [r for r in out if grep.lower() in r['str'].lower()]
    return out


def parse_pattern(p):
    if p.startswith('ascii:'):
        return p[6:].encode().decode('unicode_escape').encode('latin1')
    return bytes.fromhex(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dll', default=os.environ.get('WXKEEP_WIN_DLL', DEFAULT_DLL))
    ap.add_argument('cmd')
    ap.add_argument('args', nargs='*')
    ap.add_argument('--grep', default=None)
    a = ap.parse_args()
    pe = PE(a.dll)
    if a.cmd == 'sections':
        print(f'ImageBase {pe.image_base:#x}')
        for s in pe.sections:
            print(f"  {s['name']:<10} va {pe.image_base + s['vaddr']:#x} "
                  f"vsz {s['vsize']:#x} off {s['roff']:#x} rsz {s['rsz']:#x}")
        return
    if a.cmd == 'find':
        pat = parse_pattern(a.args[0])
        d = pe.data
        t = pe.text_off
        pos, n = t, 0
        while True:
            i = d.find(pat, pos, t + pe.text_sz)
            if i < 0:
                break
            print(f'{pe.off2va(i):#x} (off {i:#x})')
            n += 1
            pos = i + 1
        print(f'-- {n} hits in .text')
        return
    if a.cmd == 'str2va':
        s = a.args[0].encode()
        d = pe.data
        pos, n = 0, 0
        while True:
            i = d.find(s, pos)
            if i < 0:
                break
            va = pe.off2va(i)
            if va:
                print(f'{va:#x} (off {i:#x})')
                n += 1
            pos = i + 1
        print(f'-- {n} hits (mapped)')
        return
    if a.cmd == 'dis':
        va = int(a.args[0], 16)
        n = int(a.args[1]) if len(a.args) > 1 else 16
        off = pe.va2off(va)
        for ins in md().disasm(pe.data[off:off + n * 18], va):
            print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
            if (ins.address - va) // 1 >= n - 1 or ins.mnemonic == 'ret':
                break
        return
    if a.cmd in ('xrefs', 'callers', 'callees'):
        va = int(a.args[0], 16)
        if a.cmd == 'callees':
            off = pe.va2off(va)
            for ins in md().disasm(pe.data[off:off + 0x800], va):
                if ins.mnemonic == 'call':
                    op = ins.operands[0]
                    if op.type == capstone.x86.X86_OP_IMM:
                        print(f'{ins.address:#x}: call {op.imm:#x}')
            return
        hits = scan_xrefs(pe, [va])
        for src, kind, dst in hits:
            if a.cmd == 'callers' and not kind.startswith('call') and kind != 'jmp':
                continue
            print(f'{src:#x}: {kind} -> {dst:#x}')
        print(f'-- {len(hits)} hits')
        return
    if a.cmd == 'funcinfo':
        va = int(a.args[0], 16)
        i = bisect.bisect_right(pe.funcs, va) - 1
        if i < 0:
            print('below first function')
            return
        f = pe.funcs[i]
        nxt = pe.funcs[i + 1] if i + 1 < len(pe.funcs) else None
        print(f'func {f:#x} .. {hex(nxt) if nxt else "?"} '
              f'({(nxt - f) if nxt else 0:#x} bytes)  [query {va:#x} '
              f'{"inside" if f <= va < (nxt or f + 1 << 30) else "at-entry"}]')
        return
    if a.cmd == 'decrypt':
        rows = decrypt(pe, a.grep)
        byf = {}
        for r in rows:
            byf.setdefault(r['func'], []).append(r)
        print(f'解密 {len(rows)} 串（{len(byf)} 函数）')
        for f in sorted(byf, key=lambda x: int(x, 16)):
            for r in byf[f]:
                print(f'  {f} @ {r["site"]}: "{r["str"][:70]}"')
        return
    ap.error(f'unknown cmd {a.cmd}')


if __name__ == '__main__':
    main()
