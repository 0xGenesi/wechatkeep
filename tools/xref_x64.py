#!/usr/bin/env python3
"""270099 x64 静态交叉引用工具（LC_FUNCTION_STARTS 边界 + E8 对齐验证）"""
import struct, sys, bisect
import capstone

PATH = '/tmp/wxarm/new270099_x64.dylib'
d = open(PATH, 'rb').read()

sections = {}
func_starts_off = func_starts_size = 0
p, ncmds = 32, struct.unpack_from('<I', d, 16)[0]
text_seg_addr = 0
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, p)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = d[p+8:p+24].rstrip(b'\0').decode()
        if segname == '__TEXT':
            text_seg_addr = struct.unpack_from('<Q', d, p+24)[0]
        nsects = struct.unpack_from('<I', d, p+64)[0]
        sp = p + 72
        for _ in range(nsects):
            sectname = d[sp:sp+16].rstrip(b'\0').decode()
            addr, size = struct.unpack_from('<QQ', d, sp+32)
            offset = struct.unpack_from('<I', d, sp+48)[0]
            sections[(segname, sectname)] = (addr, size, offset)
            sp += 80
    elif cmd == 0x26:  # LC_FUNCTION_STARTS
        func_starts_off, func_starts_size = struct.unpack_from('<II', d, p+8)
    p += cmdsize

TEXT_ADDR, TEXT_SIZE, TEXT_OFF = sections[('__TEXT', '__text')]

# LC_FUNCTION_STARTS: ULEB128 deltas, base = __TEXT vmaddr
fs = d[func_starts_off:func_starts_off+func_starts_size]
vals, cur, shift = [], 0, 0
for b in fs:
    cur |= (b & 0x7f) << shift
    shift += 7
    if not (b & 0x80):
        vals.append(cur)
        cur, shift = 0, 0
funcs, acc = [], text_seg_addr
for v in vals:
    acc += v
    funcs.append(acc)
funcs = sorted(set(funcs))
print(f'__text [{TEXT_ADDR:#x}..{TEXT_ADDR+TEXT_SIZE:#x}) fileoff={TEXT_OFF:#x} functions={len(funcs)}', file=sys.stderr)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def func_of(va):
    i = bisect.bisect_right(funcs, va) - 1
    return funcs[i] if i >= 0 else None

def func_end(va):
    i = bisect.bisect_right(funcs, va)
    return funcs[i] if i < len(funcs) else TEXT_ADDR + TEXT_SIZE

def disasm(va, n=16):
    off = va - TEXT_ADDR + TEXT_OFF
    out = []
    for ins in md.disasm(d[off:off+n*18], va):
        out.append(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}')
        if len(out) >= n:
            break
    return out

def aligned(site):
    """E8 对齐验证：site-1..site-16 任一起点线性反汇编恰好落在 site"""
    off = site - TEXT_ADDR + TEXT_OFF
    for k in range(1, 17):
        o = off - k
        for ins in md.disasm(d[o:off+16], site - k):
            if ins.address == site:
                return True
            if ins.address > site:
                break
    return False

def callers_of(target):
    res = []
    blob = d[TEXT_OFF:TEXT_OFF+TEXT_SIZE]
    pos = 0
    while True:
        i = blob.find(b'\xe8', pos)
        if i < 0:
            break
        pos = i + 1
        rel = struct.unpack_from('<i', blob, i+1)[0]
        if rel + (i + TEXT_ADDR) + 5 != target:
            continue
        site = TEXT_ADDR + i
        if aligned(site):
            res.append((site, func_of(site)))
    return res

def find_str(s):
    out, pos = [], 0
    b = s.encode() if isinstance(s, str) else s
    while True:
        i = d.find(b, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1

def rip_xrefs(target_off):
    """__text 内 lea rip-rel 引用（目标为文件偏移 target_off）"""
    res = []
    blob = d[TEXT_OFF:TEXT_OFF+TEXT_SIZE]
    pos = 0
    while True:
        i = blob.find(b'\x8d', pos)
        if i < 0:
            break
        pos = i + 1
        if i < 2:
            continue
        pre = blob[i-2:i]
        if pre not in (b'\x48\x8d', b'\x4c\x8d'):
            continue
        modrm = blob[i+1]
        if (modrm & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from('<i', blob, i+2)[0]
        site = TEXT_ADDR + i - 2
        tgt_va = site + 7 + disp
        for (seg, sec), (addr, size, off) in sections.items():
            if addr and addr <= tgt_va < addr + size:
                if off + (tgt_va - addr) == target_off:
                    res.append(site)
                break
    return res

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'callers':
        t = int(sys.argv[2], 16)
        for site, f in callers_of(t):
            print(f'call@{site:#x} in [{f:#x}..{func_end(f):#x})')
    elif cmd == 'dis':
        va = int(sys.argv[2], 16)
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        print('\n'.join(disasm(va, n)))
    elif cmd == 'find':
        for off in find_str(sys.argv[2]):
            print(f'{off:#x}')
    elif cmd == 'xrefs':
        for off in find_str(sys.argv[2]):
            for s in rip_xrefs(off):
                print(f'str@{off:#x} <- lea@{s:#x} in [{func_of(s):#x}..{func_end(s):#x})')
