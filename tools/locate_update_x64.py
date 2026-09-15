#!/usr/bin/env python3
"""
locate_update_x64.py — 在 x86_64 slice 中按 ObjC 方法名定位 XAppUpdateManager
的 8 个屏蔽更新补丁点（zengtianli arm64 方法的 x64 移植）。

方法（与 arm64 侧 signatures.json update 段一致）:
  - __objc_classlist → class 指针（chained-fixup 编码 → 低 36 位 + 段校验）
  - class_t+0x20 → data(&~7) → class_ro_t: name@0x18, baseMethodList@0x20
  - relative 方法表（12B/项）: name/types/imp 均为相对偏移
  - 对每个 IMP 做 x64 指令形态校验:
      ret_methods  入口 = push rbp 序言 (55 48 89 E5 或 41 5x) → 补丁 C3
      getter       = movzx eax, byte [rdi+disp]; ret → 补丁 31 C0 C3
      setter       = mov [rdi+disp], sil → 补丁 C3
    getter/setter 的 disp 必须一致（交叉验证）。

只读分析。输出 config.json 风格的 update target JSON。
用法: python3 locate_update_x64.py <thin-x64.dylib> [--class XAppUpdateManager]
"""
import argparse
import json
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RDI
except ImportError:
    sys.exit("需要 capstone: pip3 install capstone")

RET_METHODS = ["startUpdater", "checkForUpdates:", "startBackgroundUpdatesCheck:", "enableAutoUpdate:"]
GETTERS = {"automaticallyDownloadsUpdates": "setAutomaticallyDownloadsUpdates:",
           "canCheckForUpdate": "setCanCheckForUpdate:"}

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


class Image:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        assert struct.unpack_from("<I", d, 0)[0] == MH_MAGIC_64, "not a thin 64-bit mach-o"
        self.cputype = struct.unpack_from("<i", d, 4)[0]
        self.sections = {}  # name -> (addr, size, offset)
        self.segments = []  # (vmaddr, vmsize, fileoff, filesize)
        ncmds = struct.unpack_from("<I", d, 16)[0]
        p = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, p)
            if cmd == LC_SEGMENT_64:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, p + 24)
                self.segments.append((vmaddr, vmsize, fileoff, filesize))
                nsects = struct.unpack_from("<I", d, p + 64)[0]
                sp = p + 72
                for i in range(nsects):
                    sname = d[sp:sp + 16].rstrip(b"\0").decode()
                    saddr, ssize = struct.unpack_from("<QQ", d, sp + 32)
                    soff = struct.unpack_from("<I", d, sp + 48)[0]
                    self.sections[sname] = (saddr, ssize, soff)
                    sp += 80
            p += cmdsize

    def off(self, va):
        """VA → file offset（本镜像 __TEXT..__DATA 恒 fileoff==vmaddr，仍走段表以防万一）。"""
        for vmaddr, vmsize, fileoff, _fs in self.segments:
            if vmaddr <= va < vmaddr + vmsize:
                o = fileoff + (va - vmaddr)
                if o < len(self.data):
                    return o
        return None

    def in_image(self, va):
        return self.off(va) is not None

    def u64(self, va):
        o = self.off(va)
        return struct.unpack_from("<Q", self.data, o)[0] if o is not None else None

    def u32(self, va):
        o = self.off(va)
        return struct.unpack_from("<I", self.data, o)[0] if o is not None else None

    def cstr(self, va, maxlen=128):
        o = self.off(va)
        if o is None:
            return None
        end = self.data.find(b"\0", o, o + maxlen)
        return self.data[o:end].decode("utf-8", "replace") if end > o else ""

    def decode_ptr(self, raw):
        """chained-fixup 64 位 rebase: 目标在低 36 位；高位是链表 next。
        高位非零才动；解码结果必须落在镜像内，否则视为非 fixup。"""
        if raw >> 36:
            target = raw & 0xF_FFFF_FFFF
            if self.in_image(target):
                return target
        return raw if self.in_image(raw) else None

    def method_list(self, list_va):
        """relative 方法表 → {selector: imp_va}。绝对布局(24B/项)也兼容。"""
        o = self.off(list_va)
        entsize_flags, count = struct.unpack_from("<II", self.data, o)
        relative = bool(entsize_flags & 0x80000000)
        direct_sel = bool(entsize_flags & 0x40000000)
        out = {}
        for i in range(count):
            if relative:
                e = o + 8 + i * 12
                name_rel, _types_rel, imp_rel = struct.unpack_from("<iii", self.data, e)
                entry_va = list_va + 8 + i * 12
                name_va = entry_va + name_rel
                if direct_sel:
                    sel = self.cstr(name_va, 96)
                else:
                    # 间接：name 偏移指向 __objc_selrefs 槽位，槽内是指向字符串的指针
                    slot = self.u64(name_va)
                    sel = self.cstr(self.decode_ptr(slot) or 0, 96) if slot else None
                imp = entry_va + imp_rel
            else:
                e = o + 8 + i * 24
                name_p, _types_p, imp_p = struct.unpack_from("<QQQ", self.data, e)
                sel = self.cstr(self.decode_ptr(name_p) or 0, 96)
                imp = imp_p
            if sel:
                out[sel] = imp
        return out


def classify_ret_method(img, va):
    """入口应为 push 序言。返回 (expected_hex, ok)。"""
    o = img.off(va)
    b = img.data[o:o + 4]
    if b[:3] == b"\x55\x48\x89" or b[0] in (0x55, 0x41, 0x53, 0x56, 0x57):
        return b[:1].hex().upper(), True
    if b[:1] == b"\xC3":
        return "C3", True  # already patched
    return b[:4].hex().upper(), False


def classify_accessor(img, va):
    """getter: movzx eax, byte [rdi+disp]; ret / setter: mov [rdi+disp], sil。
    返回 (kind, disp, expected_hex, ok)。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    o = img.off(va)
    code = img.data[o:o + 16]
    insns = list(md.disasm(code, va))
    if not insns:
        return None, None, "", False
    first = insns[0]
    if first.mnemonic == "movzx" and first.op_str.startswith("eax, byte ptr [rdi"):
        # movzx eax, byte ptr [rdi + 0x18]  (0F B6 47 18 / 0F B6 87 xx xx xx xx)
        disp = first.operands[1].mem.disp
        return "getter", disp, first.bytes.hex().upper(), True
    if first.mnemonic == "mov" and first.op_str.startswith("byte ptr [rdi") and first.op_str.endswith("sil"):
        disp = first.operands[0].mem.disp
        return "setter", disp, first.bytes.hex().upper(), True
    if first.mnemonic == "ret":
        return "ret", None, "C3", True  # already patched
    return None, None, first.bytes.hex().upper(), False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dylib")
    ap.add_argument("--class", dest="klass", default="XAppUpdateManager")
    args = ap.parse_args()

    img = Image(args.dylib)
    cl = img.sections.get("__objc_classlist")
    if not cl:
        sys.exit("no __objc_classlist")
    addr, size, _off = cl
    n = size // 8
    print(f"__objc_classlist: {n} classes")

    found = []
    for i in range(n):
        cls_va = addr + i * 8
        raw = img.u64(cls_va)
        cls = img.decode_ptr(raw)
        if not cls:
            continue
        data_bits = img.u64(cls + 0x20)
        if not data_bits:
            continue
        ro = img.decode_ptr(data_bits & ~7)
        if not ro:
            continue
        name_p = img.u64(ro + 0x18)
        name = img.cstr(img.decode_ptr(name_p) or 0, 64) if name_p else None
        if name != args.klass:
            continue
        methods_va = img.decode_ptr(img.u64(ro + 0x20) or 0)
        found.append((cls, ro, methods_va))

    if not found:
        sys.exit(f"class {args.klass} not found")
    if len(found) > 1:
        sys.exit(f"ambiguous: {len(found)} classes named {args.klass}")
    cls, ro, methods_va = found[0]
    print(f"{args.klass}: class@0x{cls:X} ro@0x{ro:X} methods@0x{methods_va:X}")
    methods = img.method_list(methods_va)
    # 元类（类方法）也并入，实例方法优先
    meta_raw = img.u64(cls)
    meta = img.decode_ptr(meta_raw)
    if meta:
        mbits = img.u64(meta + 0x20)
        mro = img.decode_ptr((mbits or 0) & ~7)
        if mro:
            mlist = img.decode_ptr(img.u64(mro + 0x20) or 0)
            if mlist:
                for k, v in img.method_list(mlist).items():
                    methods.setdefault(k, v)

    entries = []
    problems = []
    for sel in RET_METHODS:
        imp = methods.get(sel)
        if imp is None:
            problems.append(f"missing method {sel}")
            continue
        expected, ok = classify_ret_method(img, imp)
        mark = "" if ok else "  <<< 形态不符!"
        print(f"  ret  {sel:38s} imp 0x{imp:X} expected {expected}{mark}")
        entries.append({"selector": sel, "imp": imp, "expected": expected, "asm": "C3"})
        if not ok:
            problems.append(f"bad shape {sel}")

    accessors = {}
    for getter, setter in GETTERS.items():
        g, s = methods.get(getter), methods.get(setter)
        if not g or not s:
            problems.append(f"missing accessor pair {getter}/{setter}")
            continue
        gk, gd, gexp, gok = classify_accessor(img, g)
        sk, sd, sexp, sok = classify_accessor(img, s)
        print(f"  get  {getter:38s} imp 0x{g:X} {gk} disp={gd} expected {gexp}")
        print(f"  set  {setter:38s} imp 0x{s:X} {sk} disp={sd} expected {sexp}")
        if not gok or not sok:
            problems.append(f"bad accessor shape {getter}")
            continue
        if gk == "getter" and sk == "setter" and gd != sd:
            problems.append(f"field mismatch {getter}: {gd} vs {sd}")
            continue
        entries.append({"selector": getter, "imp": g, "expected": gexp, "asm": "31C0C3"})
        entries.append({"selector": setter, "imp": s, "expected": sexp, "asm": "C3"})
        accessors[getter] = gd

    if problems:
        print("\n!! 问题:", *problems, sep="\n   ")
        sys.exit(1)

    print("\n=== config.json update target（x86_64）===")
    print(json.dumps({
        "identifier": "update",
        "binary": "Contents/Resources/wechat.dylib",
        "entries": [
            {"arch": "x86_64", "addr": format(e["imp"], "x"),
             "expected": e["expected"], "asm": e["asm"],
             "source": f"objc:{e['selector']}"}
            for e in entries
        ],
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
