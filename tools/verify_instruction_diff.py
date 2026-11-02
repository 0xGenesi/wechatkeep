#!/usr/bin/env python3
"""
verify_instruction_diff.py — L9 指令级结构证明（125 轮 V5 深度轮）。

L1 证明「目录字节 == pristine 字节」，L2/L6 证明引擎层可逆/确定，但没有任何
一层证明「补丁在指令流层面恰好是声明的语义替换」。本工具补上这一层：

  1. 位点双解码（hard）：asm 写入字节必须在指令边界上完整解码（capstone，
     无残字节）——撕裂/非法编码 = FAIL；pristine 上下文取首若干条宽容解码。
  2. 翻转目标恒等（hard）：arm64 cbz→b 形——patched 无条件跳转目标必须与
     pristine 条件分支目标恒等。**错目标的 B 能通过今天全部字节门**，只有
     这层能抓住（负控钉死）。
  3. 语义类匹配（hard）：retify（末条非 NOP=RET）/ force-flag（xor r,r 精确
     覆写 test r,r 且后续是 jcc）/ store-zero（清零 store）按类断言。
  4. 写入局部性（--patched 模式 hard）：真实补丁件 vs pristine 全文件 diff
     必须 ⊆ 声明位点集。twin 预测模式下局部性对构造恒真（如实入注），真证
     需引擎产物——--patched 对引擎写出的 dylib 直证。

Python 孪生第三例（sweep_ground_truth × ExpectedPattern 之后的复式记账）：
expected 语义/段表换算 import 自既有孪生，不从 Swift 侧复制粘贴。

用法:
  var/venv/bin/python tools/verify_instruction_diff.py              # 全语料
  var/venv/bin/python tools/verify_instruction_diff.py --build 270351
  var/venv/bin/python tools/verify_instruction_diff.py --patched F --build N --variant silent
  var/venv/bin/python tools/verify_instruction_diff.py --negative-controls
退出码 0 = 全部 hard 门通过；非 0 = 存在 FAIL（逐条列址）。
台账: var/logs/isa-diff-<stamp>.txt（Tee 双写）。
"""
import argparse
import io
import json
import os
import re
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WXARM = os.path.join(ROOT, "var", "wxarm")
sys.path.insert(0, HERE)

import machutil  # noqa: E402
from sweep_ground_truth import parse_pattern, pattern_matches  # noqa: E402

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

_md = {
    "arm64": Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "x86_64": Cs(CS_ARCH_X86, CS_MODE_64),
}
# 变体作用域（与 Engine.patch 的变体族规则一比一）：silent→revoke、
# keeptip→revoke-keeptip；revoke 族以外（update/multiInstance/...）恒在
# 作用域；废弃的 revoke-keeptip2 永不入流。
VARIANT_REVOKE_MEMBER = {"silent": "revoke", "keeptip": "revoke-keeptip"}

COND_BRANCH = {"cbz", "cbnz", "tbz", "tbnz", "je", "jne", "jl", "jle", "jg",
               "jge", "jb", "jbe", "ja", "jae", "js", "jns"}
COND_PREFIX = "b."  # arm64 b.cond 族


def is_cond_branch(mnemonic):
    return mnemonic in COND_BRANCH or mnemonic.startswith(COND_PREFIX)


class Tee(io.StringIO):
    """launch_soak.py 的双写惯例：stdout + 台账文件。"""

    def __init__(self, path):
        super().__init__()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.fp = open(path, "w", encoding="utf-8")

    def write(self, s):
        sys.stdout.write(s)
        self.fp.write(s)
        return len(s)

    def close(self):
        self.fp.close()
        super().close()


def decode_strict(arch, code, va):
    """asm 侧专用：全部字节在指令边界上被消费 → [(mnemonic, op_str, size)]；
    撕裂/非法/空 → None（hard 门）。"""
    out = [(i.mnemonic, i.op_str, i.size) for i in _md[arch].disasm(code, va)]
    if not out or sum(i[2] for i in out) != len(code):
        return None
    return out


def decode_head(arch, code, va, count=4):
    """pristine 上下文专用：宽容解码前 count 条（尾部残字节不算错——段尾/
    相邻数据截断是常态，语义只看首条/次条）。零条可解 → None。"""
    out = []
    for insn in _md[arch].disasm(code, va):
        out.append((insn.mnemonic, insn.op_str, insn.size))
        if len(out) >= count:
            break
    return out or None


def branch_target(op_str):
    """capstone arm64/x64 分支 op_str 的绝对目标（最后一个立即数）。
    间接跳转（jmp qword ptr [rip+0x…]）的位移不是目标——拒绝（None）。"""
    if "[" in op_str:
        return None
    m = re.findall(r"0x[0-9a-fA-F]+", op_str)
    return int(m[-1], 16) if m else None


def classify_and_check(arch, pristine_code, asm_bytes, va):
    """返回 (class, ok, detail)。hard 语义类逐一断言；兜底 decoded-clean
    只作结构证明（解码完整），不强称语义。"""
    astream = decode_strict(arch, asm_bytes, va)
    if astream is None:
        return "decode", False, "asm 未在指令边界完整解码（撕裂/非法编码）"
    pstream = decode_head(arch, pristine_code, va)
    if pstream is None:
        return "decode", False, "pristine 首指令不可解码"

    amn0, aop0 = astream[0][0], astream[0][1]
    pmn0, pop0 = pstream[0][0], pstream[0][1]

    # —— branch-flip：pristine 条件分支 → asm 无条件分支，目标恒等 ——
    #（双架构对称：arm64 cbz→b 与 x64 jcc→jmp 同判——后者当前语料 0 例，
    #  目录增长面先关上门。）
    if is_cond_branch(pmn0) and amn0 in ("b", "jmp"):
        pt, at = branch_target(pop0), branch_target(aop0)
        if pt is None or at is None:
            return "branch-flip", False, f"目标不可解（pristine={pt} asm={at}）"
        if pt != at:
            return "branch-flip", False, \
                f"目标漂移 pristine={pt:#x} asm={at:#x}（错目标跳转——字节门不可见）"
        return "branch-flip", True, f"目标恒等 {at:#x}"
    # 反向（restore 形 asm=条件分支）：restore 恒等断言（双评审 P1）——
    # keeptip 还原臂写回的就是原始字节，asm 必须 == pristine 前缀；写回
    # 「另一个目标的条件分支」此前零校验可过（错目标 cbz 与错目标 B 同族）。
    if arch == "arm64" and is_cond_branch(amn0):
        if asm_bytes == pristine_code[:len(asm_bytes)]:
            return "cond-branch", True, "restore 恒等（asm == pristine 原像）"
        return "cond-branch", False, (
            f"restore 漂移：asm={asm_bytes.hex()} pristine="
            f"{pristine_code[:len(asm_bytes)].hex()}（错目标条件分支）")

    # —— retify：末条非 NOP 指令是 RET，且流内不得夹带任何分支 ——
    #（双评审 P1：b+ret 形可夹带错目标跳转冒充 retify——分支目标未被
    #  校验的形态不得获得语义类背书，降级 decoded-clean 如实可见。）
    nonops = [i for i in astream if i[0] != "nop"]
    has_branch = any(i[0] == "b" or i[0].startswith("b.") or i[0] == "jmp"
                     or is_cond_branch(i[0]) for i in astream)
    if nonops and nonops[-1][0] == "ret" and not has_branch:
        return "retify", True, "末条非 NOP = RET（无夹带分支）"

    # —— force-flag：xor r8,r8 精确覆写 test r8,r8（x64），后续必须是 jcc
    #（ZF 恒 1 ⇒ 后续条件跳转无条件化——语义主张依赖后续 jcc 在场）——
    if arch == "x86_64" and pmn0 == "test" and amn0 == "xor":
        nxt = pstream[1][0] if len(pstream) > 1 else None
        if pop0 == aop0 and pstream[0][2] == astream[0][2] and nxt \
                and is_cond_branch(nxt):
            return "force-flag", True, f"寄存器/长度恒等，后续 {nxt} 无条件化"
        return "force-flag", False, (
            f"寄存器/长度/后续漂移（test {pop0}/{pstream[0][2]}B → xor {aop0}/"
            f"{astream[0][2]}B，next={nxt}）")

    # —— nop-out：条件分支整条中性化（multiInstance 多开门族：je rel32 →
    #    全 NOP——分支语义整体移除而非改写，目标不再被消费）——
    if astream and all(i[0] == "nop" for i in astream):
        if pmn0.startswith("j"):
            return "nop-out", True, f"{pmn0} {pop0} → {len(asm_bytes)}B NOP（分支中性化）"
        return "nop-out", False, f"全 NOP 但 pristine 首条非分支（{pmn0}）——语义不明"

    # —— prologue-restore：keeptip 序言恢复形（归一化条目 asm∈expected，
    #    写规范序言 push rbp; mov rbp,rsp——silent→keeptip 切换的还原臂）——
    if arch == "x86_64" and asm_bytes.startswith(b"\x55\x48\x89\xe5"):
        return "prologue-restore", True, "push rbp; mov rbp,rsp 序言恢复（归一化条目）"

    # —— store-zero（arm64 str xzr / x64 xor rax,rax 后随 mov [mem],rax）——
    if arch == "arm64" and amn0 == "str" and "xzr" in aop0:
        return "store-zero", True, f"str xzr, {aop0}"
    if arch == "x86_64" and amn0 == "xor" and aop0.rstrip() in ("rax, rax", "eax, eax"):
        stores = [i for i in astream if i[0] == "mov" and "," in i[1]
                  and i[1].split(",")[-1].strip() in ("rax", "eax")]
        if stores:
            return "zero-store-x64", True, f"清零后 store（{stores[-1][1]}）"

    # —— 兜底：解码完整（结构证明，不强称语义）——
    return "decoded-clean", True, f"asm={amn0} {aop0}（pristine={pmn0} {pop0}）"


CPU_TYPE = {"arm64": 0x0100000C, "x86_64": 0x01000007}


def load_arch_slice(path, arch):
    """fat/thin 均可 → 指定 arch 切片字节（双评审 P1：machutil.segments 对
    fat 头直接 struct.error 崩——引擎合同就是 possibly-fat）。"""
    slices = machutil.load_slices(path)
    if CPU_TYPE[arch] not in slices:
        raise SystemExit(f"{path}: 无 {arch} 切片（含: "
                         f"{sorted(machutil.CPU_NAMES.get(c, hex(c)) for c in slices)}）")
    return slices[CPU_TYPE[arch]]


def locality_diff(orig, patched, ranges, linkedit_off, sample_cap=8):
    """分块局部性（双评审 P2：逐字节物化 int 列表在重签 MB 级 diff 下吃数百
    MB 内存）。返回 (n_changed, n_stray_code, n_stray_tail, head_samples)：
    linkedit_off 之后的差异 = 重签尾差单列；patched 比 orig 长出的尾部
    （codesign 追加块）同归尾差。"""
    declared = set()
    for _va, off, ln in ranges:
        declared.update(range(off, off + ln))
    n_changed = n_stray_code = n_stray_tail = 0
    head = []
    CHUNK = 1 << 20
    for base in range(0, len(orig), CHUNK):
        a = orig[base:base + CHUNK]
        b = patched[base:base + CHUNK]
        if a == b:
            continue
        for i in range(len(a)):
            if a[i] != b[i]:
                n_changed += 1
                off = base + i
                if off in declared:
                    continue
                if linkedit_off is not None and off >= linkedit_off:
                    n_stray_tail += 1
                else:
                    n_stray_code += 1
                    if len(head) < sample_cap:
                        head.append(off)
    if len(patched) > len(orig):
        n_stray_tail += len(patched) - len(orig)
    return n_changed, n_stray_code, n_stray_tail, head


def load_catalog():
    cfg = json.load(open(os.path.join(ROOT, "config.json")))
    per_build = {}
    for v in cfg:
        build = v["version"]
        for t in v["targets"]:
            binary = t.get("binary") or ""
            if "wechat.dylib" not in binary:
                continue  # 切片库只存 wechat.dylib（与 L1 同口径）
            for e in t["entries"]:
                if e.get("addr") is None or e.get("expected") is None:
                    continue  # 运行期解析条目 / 隔离区条目：L1 口径外
                per_build.setdefault(build, []).append(
                    {"identifier": t["identifier"], **e})
    return per_build


def verify_build(build, entries, out, variant="silent"):
    arch_files = {"arm64": os.path.join(WXARM, f"{build}_arm64.dylib"),
                  "x86_64": os.path.join(WXARM, f"{build}_x64.dylib")}
    stats = {"sites": 0, "pass": 0, "fail": 0}
    classes = {}
    for arch, path in arch_files.items():
        if not os.path.exists(path):
            continue
        data = open(path, "rb").read()
        in_scope = [e for e in entries if e["arch"] == arch and (
            not e["identifier"].startswith("revoke")
            or e["identifier"] == VARIANT_REVOKE_MEMBER[variant])]
        for e in in_scope:
            variants = e["expected"] if isinstance(e["expected"], list) else [e["expected"]]
            if any(parse_pattern(s) is None for s in variants):
                stats["fail"] += 1
                out.write(f"FAIL {build}/{arch} {e['identifier']}@{e['addr']} BAD-SPEC\n")
                continue
            va = int(e["addr"], 16)
            off = machutil.va2off(data, va)
            if off is None:
                stats["fail"] += 1
                out.write(f"FAIL {build}/{arch} {e['identifier']}@{e['addr']} va 不落段表\n")
                continue
            n = max(len(parse_pattern(s)[0]) // 2 for s in variants)
            # pristine 原像门（与 L1 同语义：归一化条目匹配任一变体）
            normalized = e["asm"] in variants
            hit = pattern_matches(variants[0], data[off:off + n]) if not normalized \
                else any(pattern_matches(s, data[off:off + n]) for s in variants)
            if not hit:
                stats["fail"] += 1
                out.write(f"FAIL {build}/{arch} {e['identifier']}@{e['addr']} "
                          f"pristine 不匹配 expected（L1 前置门）\n")
                continue
            pristine_ctx = data[off:off + 32]
            asm = bytes.fromhex(e["asm"])
            cls, ok, detail = classify_and_check(arch, pristine_ctx, asm, va)
            classes[cls] = classes.get(cls, 0) + 1
            stats["sites"] += 1
            if ok:
                stats["pass"] += 1
            else:
                stats["fail"] += 1
                out.write(f"FAIL {build}/{arch} {e['identifier']}@{e['addr']} "
                          f"[{cls}] {detail}  asm={e['asm']}\n")
    return stats, classes


def negative_controls(out):
    """三型坏目录必红——证明检测器能报错（V3-DEPTH D3 原则延伸到 L9）。"""
    results = []

    def expect_fail(name, fn):
        try:
            ok, detail = fn()
        except Exception as ex:  # noqa: BLE001 — 负控本身异常也算「报错」
            ok, detail = False, f"异常: {ex}"
        results.append((name, not ok, detail))

    # ① 错目标 B：pristine = cbz w0, #+0x20（0x34000100），asm = b #+0x24
    #    （0x14000009）——目标漂移 4B，字节门全绿，只有目标恒等门能抓。
    def wrong_target():
        pristine = (0x34000100).to_bytes(4, "little") + b"\x1f\x20\x03\xd5" * 4
        wrong = (0x14000009).to_bytes(4, "little")
        cls, ok, detail = classify_and_check("arm64", pristine, wrong, 0x1000)
        return ok, f"{cls}: {detail}"
    expect_fail("错目标 B（翻转目标漂移 +4）", wrong_target)

    # ② 撕裂 asm：x64 三字节 0xFF×3（非法/不完整编码）必须被严格解码拒绝
    def torn():
        cls, ok, detail = classify_and_check(
            "x86_64", b"\x84\xc0\x74\x10\x90", b"\xff\xff\xff", 0x2000)
        return ok, f"{cls}: {detail}"
    expect_fail("撕裂/非法 asm 字节", torn)

    # ③ 局部性：位点外单字节漂移必须被 locality_diff 抓住
    def stray_write():
        orig = bytearray(64)
        patched = bytearray(orig)
        patched[17] ^= 0xFF  # 声明位点 [0,4) 之外
        _c, n_stray_code, _t, head = locality_diff(orig, patched, [(0x1000, 0, 4)], None)
        return n_stray_code == 0, f"stray={head[:4]}"
    expect_fail("位点外写入（局部性）", stray_write)

    # ④ x64 错目标 jmp：je 0x2012 → jmp 0x2014（双架构对称门——语料当前
    #    0 例 x64 翻转，目录增长面先关门）
    def wrong_target_x64():
        pristine = b"\x74\x10\x90\x90"          # je rel8 → 0x2012
        wrong = b"\xe9\x0f\x00\x00\x00\x90"    # jmp rel32 → 0x2014
        cls, ok, detail = classify_and_check("x86_64", pristine, wrong, 0x2000)
        return ok, f"{cls}: {detail}"
    expect_fail("x64 错目标 jmp（翻转目标漂移）", wrong_target_x64)

    all_ok = all(r[1] for r in results)
    for name, caught, detail in results:
        out.write(f"{'✓' if caught else '✗'} 负控 {name} — "
                  f"{'被抓住' if caught else '漏报!'}（{detail}）\n")
    return all_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="append", help="只验指定构建（可多次）")
    ap.add_argument("--variant", choices=list(VARIANT_REVOKE_MEMBER), default="silent")
    ap.add_argument("--patched", help="真实补丁件路径（引擎产物）：全文件局部性直证")
    ap.add_argument("--negative-controls", action="store_true")
    ap.add_argument("--arch", choices=["arm64", "x86_64"],
                    help="--patched 模式必填（不再猜文件名）")
    args = ap.parse_args()
    if args.negative_controls and args.patched:
        ap.error("--negative-controls 与 --patched 互斥（双评审 P2：此前组合"
                 "会静默跳过 patched 检查且退出码 0）")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
    out = Tee(os.path.join(ROOT, "var", "logs", f"isa-diff-{stamp}.txt"))
    fail = False

    if args.negative_controls:
        if not negative_controls(out):
            fail = True
        out.write(f"\nL9 负控结论：{'四型全被抓住' if not fail else '存在漏报——检测器灵敏度不成立'}\n")
        out.close()
        sys.exit(1 if fail else 0)

    catalog = load_catalog()
    total = {"sites": 0, "pass": 0, "fail": 0}
    grand_classes = {}
    builds_checked = 0
    for build in sorted(catalog):
        if args.build and build not in args.build:
            continue
        stats, classes = verify_build(build, catalog[build], out, args.variant)
        if stats["sites"] or stats["fail"]:
            builds_checked += 1
            for k in total:
                total[k] += stats[k]
            for k, v in classes.items():
                grand_classes[k] = grand_classes.get(k, 0) + v
    if total["fail"]:
        fail = True   # 目录验证 FAIL 必须进退出码（双评审 P0：此前永不置位=假绿）
    out.write(f"\n构建 {builds_checked}  位点 {total['sites']}  "
              f"PASS {total['pass']}  FAIL {total['fail']}\n")
    out.write("语义类分布: " + "  ".join(f"{k}={v}" for k, v in sorted(grand_classes.items())) + "\n")

    if args.patched:
        if not args.build or not args.arch:
            out.write("FAIL --patched 需要 --build 与 --arch（arch 不猜文件名——双评审 P1）\n")
            out.close()
            sys.exit(1)
        build = args.build[0]
        arch = args.arch
        pristine_path = os.path.join(WXARM, f"{build}_{arch if arch == 'arm64' else 'x64'}.dylib")
        # fat/thin 均经 load_slices 取切片（双评审 P1：fat 直喂 segments 崩）
        orig = load_arch_slice(pristine_path, arch)
        patched = load_arch_slice(args.patched, arch)
        if len(patched) < len(orig):
            out.write(f"FAIL 局部性前置：patched 比 pristine 短（{len(patched)} < {len(orig)}）\n")
            out.close()
            sys.exit(1)
        entries = [e for e in catalog[build] if e["arch"] == arch and (
            not e["identifier"].startswith("revoke")
            or e["identifier"] == VARIANT_REVOKE_MEMBER[args.variant])]
        ranges = []
        for e in entries:
            off = machutil.va2off(orig, int(e["addr"], 16))
            if off is None:
                out.write(f"FAIL --patched 前置：{e['identifier']}@{e['addr']} va 不落段表\n")
                out.close()
                sys.exit(1)
            ranges.append((int(e["addr"], 16), off, len(bytes.fromhex(e["asm"]))))
        # 重签只动 __LINKEDIT 签名元数据（尾部追加/重写）+ 尾部增长（追加
        # 签名块）——两者单列报告；__TEXT/__DATA 等代码区差异才是局部性 FAIL。
        linkedit = next((fo for n, _va, _vs, fo, _fs in machutil.segments(orig)
                         if n == "__LINKEDIT"), None)
        n_changed, n_stray_code, n_stray_tail, head = locality_diff(
            orig, patched, ranges, linkedit)
        out.write(f"局部性直证：diff 字节 {n_changed}  位点外(代码区) {n_stray_code}  "
                  f"重签尾差 {n_stray_tail}  "
                  f"{'✓ 代码区差异全部落在声明位点' if not n_stray_code else '✗ 存在位点外写入'}\n")
        if n_stray_code:
            out.write(f"  位点外首样: {[hex(i) for i in head]}\n")
            fail = True

    out.write(f"L9 结论：{'指令级结构证明成立' if not fail else '存在 FAIL——见上行逐条'}\n")
    out.close()
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
