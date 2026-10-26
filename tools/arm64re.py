#!/usr/bin/env python3
"""arm64re.py — arm64 链推导原语箱（纯算术字扫描，无线性反汇编截断风险）。

来源：76/77 轮 arm64 撤回链 derive 会话（var/ab/arm64re.py 正化入库，
原工件保留在 var/——台账证据不删）。方法论：arm64 编译器不用 movabs——
字符串常量以 16B 对齐 SSO 池存于 __TEXT,__const，引用走 ADRP+LDR/ADD
间接，调用走 BL。锚串字面量经 movz/movk 立即数构造是少数可直搜形态。

原语：
  movz/movk 立即数构造扫描（x64 movabs 的 arm64 对应物）
  BL 直接调用扫描（word & 0xFC000000 == 0x94000000, target = pc + sext26<<2）
  ADRP+ADD 对扫描（rip-lea 的对应物；配对寄存器不校验，以目标地址命中为准）
函数边界 = LC_FUNCTION_STARTS（machutil，基址 __TEXT.vmaddr）。

用法（切片可为 fat 或 thin arm64 dylib；缺省 270100 切片引用）:
  var/venv/bin/python tools/arm64re.py <slice.dylib>            # 概览（函数数/text 范围）
  var/venv/bin/python tools/arm64re.py <slice.dylib> scan       # revokeme/reeditre 常量站点
依赖 tools/machutil.py（同目录自动入 sys.path）。
"""
import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import machutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SLICE = os.path.join(REPO_ROOT, 'var/ab/270100_arm64.dylib')


class Arm:
    def __init__(self, path):
        self.d = machutil.load_slice(path, machutil.CPU_ARM64)
        secs = [(s[0], s[1], s[2], s[3], s[4]) for s in machutil.sections(self.d)]
        self.ta, self.tsz, self.to = [(a, z, o) for seg, sect, a, z, o in secs
                                      if (seg, sect) == ('__TEXT', '__text')][0]
        self.funcs = sorted(set(machutil.function_starts(self.d)))
        self.words = None

    def text_words(self):
        if self.words is None:
            n = self.tsz // 4
            self.words = struct.unpack_from('<%dI' % n, self.d, self.to)
        return self.words

    def func_of(self, va):
        i = bisect.bisect_right(self.funcs, va) - 1
        return self.funcs[i] if i >= 0 else 0

    def find_movz_movk(self, halves, window=8):
        """找 movz imm16=halves[0] 且其后 window 条指令内含 movk halves[1..] (lsl 16,32,48)。
        返回 (va_of_movz, rd) 站点列表。"""
        w = self.text_words()
        n = len(w)
        base = 0xD2800000
        out = []
        hw0 = halves[0]
        # movz: sf=1 opc=00 → 0xD2800000 | (hw<<21=0) | imm16<<5 | rd
        lo_w = base | (hw0 << 5)
        hi_w = lo_w | 0x1F
        movk_expect = {1: halves[1] if len(halves) > 1 else None,
                       2: halves[2] if len(halves) > 2 else None,
                       3: halves[3] if len(halves) > 3 else None}
        for i in range(n):
            x = w[i]
            if lo_w <= x <= hi_w:
                rd = x & 0x1F
                hit = 0
                for j in range(1, window + 1):
                    if i + j >= n:
                        break
                    y = w[i + j]
                    if (y & 0xFFC00000) != 0xF2800000:  # movk 64
                        continue
                    hw = (y >> 21) & 3
                    imm = (y >> 5) & 0xFFFF
                    if y & 0x1F == rd and movk_expect.get(hw) == imm:
                        hit += 1
                need = sum(1 for v in movk_expect.values() if v is not None)
                if hit == need:
                    va = self.ta + i * 4
                    out.append((va, rd))
        return out

    def find_bl(self, targets):
        """BL 直接调用：返回 [(site_va, target)]"""
        w = self.text_words()
        tset = set(targets)
        out = []
        for i, x in enumerate(w):
            if (x & 0xFC000000) == 0x94000000:
                imm = x & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                tgt = (self.ta + i * 4) + (imm << 2)
                if tgt in tset:
                    out.append((self.ta + i * 4, tgt))
        return out

    def find_adrp_add(self, targets):
        """ADRP+ADD 对（页 + imm12）合成地址命中 targets。粗配：不校验寄存器链。"""
        w = self.text_words()
        tset = set(targets)
        out = []
        for i, x in enumerate(w):
            if (x & 0x9F000000) != 0x90000000:
                continue
            immlo = (x >> 29) & 3
            immhi = (x >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & 0x100000:
                imm -= 0x200000
            page = ((self.ta + i * 4) & ~0xFFF) + (imm << 12)
            if page > 0x1000000000000:
                continue
            rn = (x >> 5) & 0x1F
            rd = x & 0x1F
            for j in range(1, 5):
                if i + j >= len(w):
                    break
                y = w[i + j]
                # ADD Xd, Xn, #imm12 (64-bit, no shift): 0x91000000 | imm12<<10 | rn<<5 | rd
                if (y & 0xFF800000) != 0x91000000:
                    continue
                if (y >> 5) & 0x1F != rn:
                    continue
                a = page + ((y >> 10) & 0xFFF)
                if a in tset:
                    out.append((self.ta + i * 4, a))
        return out


REVOKEME_HALVES = (0x6572, 0x6F76, 0x656B, 0x656D)   # "revokeme"
REEDITRE_HALVES = (0x6572, 0x7469, 0x6465, 0x6572)   # "reeditre"


def main():
    argv = sys.argv[1:]
    path = argv[0] if argv else DEFAULT_SLICE
    a = Arm(path)
    print(f'{path}: funcs {len(a.funcs)}, text {a.ta:#x}+{a.tsz:#x}')
    if len(argv) > 1 and argv[1] == 'scan':
        print('== revokeme const sites:')
        for va, rd in a.find_movz_movk(REVOKEME_HALVES):
            print(f'  {va:#x} (x{rd})  func {a.func_of(va):#x}')
        print('== reeditre const sites:')
        for va, rd in a.find_movz_movk(REEDITRE_HALVES):
            print(f'  {va:#x} (x{rd})  func {a.func_of(va):#x}')


if __name__ == '__main__':
    main()
