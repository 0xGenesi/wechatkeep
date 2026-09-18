#!/usr/bin/env python3
"""
machutil.py — tools/ 共享的 Mach-O 解析模块（2026-09 工具审计引入，见
docs/TOOLS-AUDIT.md）。

此前 8 个脚本各自手写一遍 load_command 解析，衍生出两类真实缺陷：
  1. backfill_expected.py 把 VA 直接当文件偏移（依赖「fileoff==vmaddr」的
     隐含假设——__TEXT 段碰巧成立，条目一旦落在 __DATA 即读错字节）；
  2. decrypt_strings.py 的 LC_FUNCTION_STARTS 基址取了第一个 section 的
     addr 而非 __TEXT 段 vmaddr（函数归属 VA 整体偏移了头部区域大小）。
统一口径：VA→file offset 一律走段表；function starts 基址一律 __TEXT.vmaddr
（LLVM/dyld 语义）。只依赖 stdlib。
"""
import struct

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
CPU_NAMES = {CPU_X86_64: 'x86_64', CPU_ARM64: 'arm64'}

FAT_MAGICS = (0xCAFEBABE, 0xBEBAFECA)
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26


def load_slices(path):
    """fat/thin 均可 → {cputype: slice_bytes}。"""
    data = open(path, 'rb').read()
    magic = struct.unpack_from('>I', data, 0)[0]
    out = {}
    if magic in FAT_MAGICS:
        # fat header / fat_arch 恒为大端（与 slice 本体的字节序无关）
        nfat = struct.unpack_from('>I', data, 4)[0]
        for i in range(nfat):
            cputype, _cpusub, off, size, _align = struct.unpack_from(
                '>IIIII', data, 8 + i * 20)
            out[cputype] = data[off:off + size]
    else:
        out[struct.unpack_from('<i', data, 4)[0]] = data
    return out


def load_slice(path, cputype):
    """指定架构 slice；缺失时 SystemExit 带可读原因（研究工具的交互习惯）。"""
    slices = load_slices(path)
    if cputype not in slices:
        have = ', '.join(CPU_NAMES.get(c, hex(c)) for c in sorted(slices))
        raise SystemExit(f'{path}: 没有 {CPU_NAMES.get(cputype, hex(cputype))} slice'
                         f'（实际含: {have or "空"}）')
    return slices[cputype]


def _load_commands(d):
    p, ncmds = 32, struct.unpack_from('<I', d, 16)[0]
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, p)
        yield cmd, p
        if cmdsize == 0:   # 防 cmdsize==0 死循环（损坏文件）
            break
        p += cmdsize


def segments(d):
    """[(segname, vmaddr, vmsize, fileoff, filesize)] — VA→offset 换算的唯一权威。"""
    out = []
    for cmd, p in _load_commands(d):
        if cmd == LC_SEGMENT_64:
            name = d[p + 8:p + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, p + 24)
            out.append((name, vmaddr, vmsize, fileoff, filesize))
    return out


def sections(d):
    """[(segname, sectname, addr, size, fileoff)]，按 load command 顺序。"""
    out = []
    for cmd, p in _load_commands(d):
        if cmd == LC_SEGMENT_64:
            segname = d[p + 8:p + 24].rstrip(b'\0').decode()
            nsects = struct.unpack_from('<I', d, p + 64)[0]
            sp = p + 72
            for _ in range(nsects):
                sectname = d[sp:sp + 16].rstrip(b'\0').decode()
                addr, size = struct.unpack_from('<QQ', d, sp + 32)
                offset = struct.unpack_from('<I', d, sp + 48)[0]
                out.append((segname, sectname, addr, size, offset))
                sp += 80
    return out


def text_range(d):
    """(__TEXT,__text) → (addr, size, fileoff)。"""
    for _seg, name, addr, size, offset in sections(d):
        if name == '__text':
            return addr, size, offset
    raise SystemExit('找不到 __TEXT,__text')


def va2off(d, va):
    """VA → file offset（走段表）；落在未映射区/文件外返回 None。"""
    for _name, vmaddr, vmsize, fileoff, filesize in segments(d):
        if vmaddr <= va < vmaddr + vmsize:
            delta = va - vmaddr
            return fileoff + delta if delta < filesize else None
    return None


def function_starts(d):
    """LC_FUNCTION_STARTS → 函数起始 VA 升序列表（去重）。
    基址 = __TEXT 段 vmaddr（dyld 语义）——不是第一个 section 的 addr：
    头部区域（mach header + load commands）使两者相差数千字节。"""
    blob_off = blob_size = 0
    found = False
    for cmd, p in _load_commands(d):
        if cmd == LC_FUNCTION_STARTS:
            blob_off, blob_size = struct.unpack_from('<II', d, p + 8)
            found = True
            break
    if not found:
        return []
    base = next((vm for name, vm, *_ in segments(d) if name == '__TEXT'), 0)
    blob = d[blob_off:blob_off + blob_size]
    funcs, addr, i = [], base, 0
    while i < len(blob):
        delta = shift = 0
        while True:
            b = blob[i]
            i += 1
            delta |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break
        if delta:   # 0 增量 = 重复地址，跳过即去重
            addr += delta
            funcs.append(addr)
    return funcs
