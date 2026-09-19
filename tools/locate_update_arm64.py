#!/usr/bin/env python3
"""
locate_update_arm64.py — 在 arm64 slice 中按 ObjC 方法名定位 XAppUpdateManager
的 8 个屏蔽更新补丁点（locate_update_x64 的 arm64 孪生）。

方法（与 x64 版共用 ObjC 元数据遍历；arm64 与 x86_64 的 class_t/class_ro_t/
relative 方法表布局相同，chained-fixup 64 位 rebase 编码也相同）:
  - __objc_classlist → class 指针 → class_ro_t: name@0x18, baseMethodList@0x20
  - 对每个 IMP 做 arm64 指令形态校验（zengtianli arm64 条目实证形态）:
      ret_methods 入口 = 栈序言首 4B（stp xN,xM,[sp,#-imm]! / sub sp,sp,#imm）
                        → 补丁 C0035FD6（ret），expected=序言 4B
      getter  = ldrb w0,[x0,#disp]; ret   → 补丁 00008052C0035FD6
                                            （movz w0,#0; ret），expected 8B
      setter  = strb w2,[x0,#disp]        → 补丁 C0035FD6，expected=strb 4B
    getter/setter 的 disp 必须一致（交叉验证，与 x64 版同规则）。
  - 已打补丁态（入口即 ret / movz w0,#0;ret）识别为 ok（幂等重入）。

互证基线：zengtianli/WeChatTweak 已登记 arm64 8 点的构建（269574-579、619、
624、627、628、631）上，本工具派生的 imp 与 expected 需逐字节一致。

只读分析。输出 config.json 风格的 update target JSON。
用法: python3 tools/locate_update_arm64.py <thin-arm64.dylib> [--class XAppUpdateManager]
"""
import argparse
import json
import re
import sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit("需要 capstone: pip3 install capstone")

# 与 locate_update_x64 共享 Image（段表/ObjC 遍历与架构无关）与方法集
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from locate_update_x64 import (  # noqa: E402
    Image, RET_METHODS, GETTERS)

RET_ARM = "C0035FD6"                      # ret
MOVZ_W0_RET = "00008052C0035FD6"           # movz w0, #0; ret
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = False


def classify_ret_method(img, va):
    """入口应为栈序言（stp/sub sp）。返回 (expected_hex, ok)。"""
    o = img.off(va)
    b = img.data[o:o + 8]
    if b[:4] == bytes.fromhex(RET_ARM):
        return RET_ARM, True  # already patched
    ins = next(MD.disasm(b[:4], va), None)
    if ins and ins.mnemonic in ("stp", "sub") and "sp" in ins.op_str \
            and ins.mnemonic != "ldp":
        return b[:4].hex().upper(), True
    return b[:4].hex().upper(), False


def parse_ldstrb(ins):
    """ldrb w0,[x0,#disp] / strb w2,[x0,#disp] → (reg_ok, disp)。"""
    m = re.match(r"^(ldrb|strb) (w\d+), \[x\d+(?:, #(0x[0-9a-f]+|\d+))?\]$",
                 f"{ins.mnemonic} {ins.op_str}")
    if not m:
        return None
    return (int(m.group(3), 0) if m.group(3) else 0)


def classify_accessor(img, va):
    """getter/setter 归类。返回 (kind, disp, expected_hex, ok)。"""
    o = img.off(va)
    b = img.data[o:o + 12]
    # 已打补丁态
    if b[:4] == bytes.fromhex(RET_ARM):
        return "ret", None, RET_ARM, True
    if b[:8] == bytes.fromhex(MOVZ_W0_RET):
        return "ret", None, MOVZ_W0_RET, True
    ins0 = next(MD.disasm(b[:4], va), None)
    if not ins0:
        return None, None, b[:4].hex().upper(), False
    disp = parse_ldstrb(ins0)
    if disp is None:
        return None, None, b[:4].hex().upper(), False
    nxt = next(MD.disasm(b[4:8], va + 4), None)
    if ins0.mnemonic == "ldrb" and ins0.op_str.startswith("w0, [x"):
        if nxt and nxt.mnemonic == "ret":
            return "getter", disp, b[:8].hex().upper(), True
    if ins0.mnemonic == "strb" and ins0.op_str.startswith("w2, [x"):
        return "setter", disp, b[:4].hex().upper(), True
    return None, None, b[:4].hex().upper(), False


def find_class_methods(img, klass):
    cl = img.sections.get("__objc_classlist")
    if not cl:
        sys.exit("no __objc_classlist")
    addr, size, _off = cl
    for i in range(size // 8):
        cls = img.decode_ptr(img.u64(addr + i * 8) or 0)
        if not cls:
            continue
        ro = img.decode_ptr((img.u64(cls + 0x20) or 0) & ~7)
        if not ro:
            continue
        name_p = img.u64(ro + 0x18)
        if not name_p or img.cstr(img.decode_ptr(name_p) or 0, 64) != klass:
            continue
        methods = img.method_list(img.decode_ptr(img.u64(ro + 0x20) or 0) or 0)
        meta = img.decode_ptr(img.u64(cls) or 0)
        if meta:
            mro = img.decode_ptr((img.u64(meta + 0x20) or 0) & ~7)
            if mro:
                mlist = img.decode_ptr(img.u64(mro + 0x20) or 0)
                if mlist:
                    for k, v in img.method_list(mlist).items():
                        methods.setdefault(k, v)
        return methods
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dylib")
    ap.add_argument("--class", dest="klass", default="XAppUpdateManager")
    args = ap.parse_args()

    img = Image(args.dylib)
    assert img.cputype == 0x0100000C, "not an arm64 thin slice"
    methods = find_class_methods(img, args.klass)
    if not methods:
        sys.exit(f"class {args.klass} not found")

    entries, problems = [], []
    for sel in RET_METHODS:
        imp = methods.get(sel)
        if imp is None:
            problems.append(f"missing method {sel}")
            continue
        expected, ok = classify_ret_method(img, imp)
        mark = "" if ok else "  <<< 形态不符!"
        print(f"  ret  {sel:38s} imp 0x{imp:X} expected {expected}{mark}")
        entries.append({"selector": sel, "imp": imp,
                        "expected": expected, "asm": RET_ARM})
        if not ok:
            problems.append(f"bad shape {sel}")

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
            print(f"  !! 访问器形态不符（跳过 {getter} 对，其余条目照常产出）")
            continue
        if gk == "getter" and sk == "setter" and gd != sd:
            problems.append(f"field mismatch {getter}: {gd} vs {sd}")
            continue
        entries.append({"selector": getter, "imp": g,
                        "expected": gexp, "asm": MOVZ_W0_RET})
        entries.append({"selector": setter, "imp": s,
                        "expected": sexp, "asm": RET_ARM})

    if problems:
        print("\n!! 问题:", *problems, sep="\n   ")
        sys.exit(1)

    print("\n=== config.json update target（arm64）===")
    print(json.dumps({
        "identifier": "update",
        "binary": "Contents/Resources/wechat.dylib",
        "entries": [
            {"arch": "arm64", "addr": format(e["imp"], "x"),
             "expected": e["expected"], "asm": e["asm"],
             "source": f"objc:{e['selector']}"}
            for e in entries
        ],
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
