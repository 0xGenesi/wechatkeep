#!/usr/bin/env python3
"""
audit_patch.py — per-site 补丁清单的零信任离线复算（125 轮 V5 深度轮）。

wxkeep 写出的三件套：pristine 原件 + patched 补丁件 + <userData>/wxkeep.audit.json。
（合同边界：装了 runtime hooks 的机器含注入器写入面，不在账目语义内——
 本工具复算的是「未装 runtime 或注入前 diff」；重签 __LINKEDIT/尾部追加单列。）
本工具只凭这三样复算，不依赖 wxkeep 二进制（第三方可审计——「check me」
而不是「trust me」）。判据：

  1.（hard）逐位点：patched 在位点偏移处字节 == audit.after（账目→盘直证）。
  2.（warn）pristine 在位点偏移处字节 == audit.before；不等 = 变体切换
     （before=上一变体补丁字节，合法域=expected 变体族）或异常写入——v1
     无 catalog 对照，如实警告不计硬门。
  3.（hard）全文件 diff ⊆ 位点集 ∪ __LINKEDIT（重签只动签名元数据尾巴；
     __LINKEDIT 差异单列报告，位点外（__TEXT/__DATA 等）差异 = FAIL）。

stdlib only（无 capstone 依赖）；Mach-O 解析复用 tools/machutil.py。

用法:
  python3 tools/audit_patch.py --pristine P --patched Q --audit wxkeep.audit.json
退出码 0 = 复算通过。
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import machutil  # noqa: E402

CPU_TYPE = {"arm64": 0x0100000C, "x86_64": 0x01000007}


def load_arch_slice(path, arch):
    """fat/thin 均可 → 指定 arch 切片（双评审 P1：fat 直喂 segments 崩）。"""
    slices = machutil.load_slices(path)
    if CPU_TYPE[arch] not in slices:
        raise SystemExit(f"{path}: 无 {arch} 切片")
    return slices[CPU_TYPE[arch]]


def locality_diff(orig, patched, declared, linkedit_off, sample_cap=8):
    """分块局部性（不物化百万级 int 列表）。返回
    (n_changed, n_stray_code, n_stray_tail, head_samples)。"""
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pristine", required=True)
    ap.add_argument("--patched", required=True)
    ap.add_argument("--audit", required=True, help="wxkeep.audit.json 路径")
    ap.add_argument("--binary", help="只对账此 bundle 相对路径的位点（多 binary 账目必选其一）")
    ap.add_argument("--arch", choices=["arm64", "x86_64"],
                    help="只对账此架构的位点（fat 双架构一次事务的账目必选其一）")
    args = ap.parse_args()

    record = json.load(open(args.audit))
    sites = record.get("sites", [])
    pairs = sorted({(s.get("binary", ""), s.get("arch", "")) for s in sites})
    # 多 binary/多架构过滤（双评审 P1：单一 --pristine 只能验一对——其余
    # 位点混入会把偏移算到错的文件上=假红；不选时如多于一对直接指引）。
    selected = [s for s in sites
                if (not args.binary or s.get("binary") == args.binary)
                and (not args.arch or s.get("arch") == args.arch)]
    skipped = len(sites) - len(selected)
    if pairs and not selected:
        print(f"✗ FAIL 过滤后无位点可对账。账目含 (binary, arch) 对: {pairs}——"
              f"用 --binary/--arch 选一对并给对应 pristine。")
        sys.exit(1)
    if len(pairs) > 1 and not (args.binary or args.arch):
        print(f"✗ FAIL 账目跨多 (binary, arch) 对 {pairs}——单一 pristine 无法"
              f"整体复算；用 --binary/--arch 分次对账。")
        sys.exit(1)
    arch = args.arch or (pairs[0][1] if pairs else "arm64")

    orig = load_arch_slice(args.pristine, arch)
    patched = load_arch_slice(args.patched, arch)
    fail = False
    warns = []
    if len(patched) < len(orig):
        print(f"✗ FAIL patched 比 pristine 短（{len(patched)} < {len(orig)}）")
        sys.exit(1)

    segs = machutil.segments(orig)
    linkedit_off = next((fo for n, _va, _vs, fo, _fs in segs if n == "__LINKEDIT"), None)
    declared = set()
    for s in selected:
        va = int(s["va"], 16)
        off = machutil.va2off(orig, va)
        if off is None:
            print(f"✗ FAIL {s['identifier']}@{s['va']} va 不落 pristine 段表")
            fail = True
            continue
        after = bytes.fromhex(s["after"])
        before = bytes.fromhex(s["before"])
        ln = len(after)
        declared.update(range(off, off + ln))
        got = patched[off:off + ln]
        if got != after:
            print(f"✗ FAIL {s['identifier']}@{s['va']} 账目→盘失配 "
                  f"（after={s['after']} 盘上={got.hex().upper()}）")
            fail = True
        if orig[off:off + len(before)] != before:
            warns.append(f"{s['identifier']}@{s['va']} before≠pristine "
                         f"（变体切换或异常写入，合法域=expected 变体族）")

    n_changed, n_stray_code, n_stray_tail, head = locality_diff(
        orig, patched, declared, linkedit_off)
    if n_stray_code:
        fail = True
        print(f"✗ FAIL 位点外写入（非 __LINKEDIT）{n_stray_code}B——"
              f"首样偏移: {[hex(i) for i in head]}")
        print("  注：装了 runtime hooks 的机器含注入器写入面（stub/__TEXT+"
              "load command），不在账目语义内——本工具的合同是「未装 runtime "
              "或注入前 diff」的复算（见 docs/FMEA.md）。")
    print(f"位点 {len(selected)}（跳过他 binary/arch {skipped}）  "
          f"对账 {'✓ 全吻合' if not fail else '✗ 见上'}  "
          f"全文件 diff {n_changed}B + 重签尾差 {n_stray_tail}B "
          f"+ 位点外 {n_stray_code}B")
    for w in warns:
        print(f"⚠️ warn {w}")
    print("复算结论：" + ("通过——账目、位点字节与写入局部性三方吻合" if not fail else "不通过"))
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
