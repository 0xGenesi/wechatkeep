#!/usr/bin/env python3
"""arm64_slotref.py — arm64 指针槽间接引用解析（fixup 感知；77 续 re-derive 工具）。

堵点（77 轮首探负结果）与结论（77 续二探，2026-10-26）：arm64 切片带
LC_DYLD_CHAINED_FIXUPS，__DATA* 指针槽文件态是 fixup 编码值——实测编码
（__cfstring char* 字段实证）：rebase 值 = 目标 VA | 0x0020_0000_0000_0000，
低 36 位即 VA，故匹配谓词 (v & 0xFFFFFFFFF) == VA 同时覆盖裸指针与 rebase
编码。**270100 arm64 判定：代码对字面量的引用全部是直接 adrp（无槽间接
形态）**——本工具的槽层在此切片无命中属真实属性，为未来代际/其他二进制
备而不用；端到端真阳性验证 = __cfstring 槽（0x96950de → 槽 0x9e32ed0）。

配套结论（首探悬案全解）：
  - 「撤回」「你撤回了一条消息」命中在 __DATA/__data = 嵌入配置数据
    （非代码引用字面量）——以之为锚的收敛线从构造上死路；
  - newmsgid 在 __TEXT/__const 字段名表（模型层）且有直引（0x4bc4d34
    本尊在引）；
  - XML 标签字面量（<newmsgid> 等）不存在于二进制 = 通用 XML 解析 +
    字段分发，tag 搜串锚线不成立。

用法：
  arm64_slotref.py <slice> <idx> --find <utf8>       # 找字面量（自动回溯串起点）→ 槽 → 引用者
  arm64_slotref.py <slice> <idx> <va-hex>...          # 已知 VA 直查槽引用
"""
import bisect
import struct
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
import arm64_index
import machutil

MASK36 = (1 << 36) - 1   # generic64/OFFSET rebase：目标在低 36 位


def string_starts(d, needle):
    """needle 全部命中 VA → 回溯到串起点（NUL 定界；UTF-8 尾字节安全回退）。"""
    secs = [(addr, size, off) for seg, sect, addr, size, off in machutil.sections(d)
            if size and size <= (1 << 26)]
    hits = []
    for addr, size, off in secs:
        blob = d[off:off + size]
        pos = 0
        while True:
            i = blob.find(needle, pos)
            if i < 0:
                break
            hits.append(addr + i)
            pos = i + 1
    out = []
    for va in hits:
        o = machutil.va2off(d, va)
        s = o
        while s > 0 and d[s - 1] != 0 and o - s < 64:
            s -= 1
        out.append((va, _off2va(d, s)))
    return out


def _off2va(d, off):
    for seg, sect, addr, size, soff in machutil.sections(d):
        if soff <= off < soff + size:
            return addr + (off - soff)
    return None


def find_slots(d, target, raw_first=True):
    """全 __DATA* 段扫 8 字节槽：(v & MASK36) == target。返回 [(slot_va, raw)]。
    step=4（ARM64 数据对齐下限；8 对齐会漏 __TEXT,__const 内紧排槽）。"""
    out = []
    for seg, sect, addr, size, off in machutil.sections(d):
        if size == 0 or size > (1 << 27):
            continue
        blob = d[off:off + size]
        n = len(blob) - 8
        i = 0
        while i <= n:
            v = struct.unpack_from('<Q', blob, i)[0]
            if v == target or (v & MASK36) == target:
                out.append((addr + i, v))
            i += 4
    return out


def func_of(funcs, va):
    i = bisect.bisect_right(funcs, va) - 1
    return funcs[i] if i >= 0 else 0


def main():
    argv = sys.argv[1:]
    if len(argv) < 3:
        raise SystemExit(__doc__)
    d = machutil.load_slice(argv[0], machutil.CPU_ARM64)
    ix, _ = arm64_index.load(argv[1])
    funcs = ix['funcs']
    targets = []
    if argv[2] == '--find':
        needle = argv[3].encode('utf-8')
        for hit, start in string_starts(d, needle):
            print(f'literal hit {hit:#x} start {start:#x}')
            targets.append(start)
            targets.append(hit)
    else:
        targets = [int(a, 16) for a in argv[2:]]

    by_func = {}
    for t in targets:
        slots = find_slots(d, t)
        for slot_va, raw in slots:
            refs = ix['refs'].get(slot_va, [])
            calls = ix['calls'].get(slot_va, [])
            tag = 'RAW' if raw == t else 'FIXUP'
            print(f'target {t:#x} slot {slot_va:#x} [{tag} raw={raw:#x}] '
                  f'refs={len(refs)} calls={len(calls)}')
            for site, kind in refs:
                f = func_of(funcs, site)
                print(f'  {site:#x}: {kind}  func {f:#x}')
                by_func.setdefault(f, set()).add(t)
            for site, caller in calls:
                print(f'  {site:#x}: bl  func {caller:#x}')
                by_func.setdefault(caller, set()).add(t)
    if by_func:
        print('== referencing functions ==')
        for f in sorted(by_func):
            print(f'  {f:#x}  targets {sorted(hex(t) for t in by_func[f])}')


if __name__ == '__main__':
    main()
