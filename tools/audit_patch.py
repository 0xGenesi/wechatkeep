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

用法（127 轮遗留④：bundle 级复算）:
  # 单对模式：显式给 pristine/patched（--binary/--arch 选账目对）
  python3 tools/audit_patch.py --pristine P --patched Q --audit wxkeep.audit.json
  # bundle 模式：给 --app（+可选 --userData），逐 binary 自动对账——
  #   pristine 参考 = 该 binary 的最新 .wxkeep-bak-*（patch 写前备份，
  #   Backup 惯例：主可执行在 <userData>/backups/<bundle>/，其余在原目录）
  python3 tools/audit_patch.py --app /Applications/WeChat.app \
      --audit <userData>/wxkeep.audit.json [--userData <userData>]

注意（如实）：最新备份 = 最近一次**写前**状态——变体切换过的机器上它
可能是上一变体的补丁态而非 pristine（before≠备份 时 warn 不 FAIL，与
单对模式同语义）。备份被 prune/删除的 binary 无法复算（FAIL 指路）。
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


def verify_pair(orig, patched, sites, skipped=0):
    """单 (binary, arch) 对复算：位点账目→盘吻合 + before 对照（warn）+
    全文件局部性（__LINKEDIT/尾部追加单列）。返回 (fail, warns)。"""
    fail = False
    warns = []
    if len(patched) < len(orig):
        print(f"✗ FAIL patched 比 pristine 短（{len(patched)} < {len(orig)}）")
        return True, warns

    segs = machutil.segments(orig)
    linkedit_off = next((fo for n, _va, _vs, fo, _fs in segs if n == "__LINKEDIT"), None)
    declared = set()
    for s in sites:
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
    print(f"位点 {len(sites)}（跳过他 binary/arch {skipped}）  "
          f"对账 {'✓ 全吻合' if not fail else '✗ 见上'}  "
          f"全文件 diff {n_changed}B + 重签尾差 {n_stray_tail}B "
          f"+ 位点外 {n_stray_code}B")
    for w in warns:
        print(f"⚠️ warn {w}")
    return fail, warns


def newest_backup_for(binary_path, user_data=None):
    """patch 写前备份（Backup 惯例）：主可执行在 <userData>/backups/<bundle>/，
    其余在 binary 同目录；取最新 .wxkeep-bak-*。无 → None。
    时间戳格式保证字典序即时间序（Backup.prune 同判据）。"""
    name = os.path.basename(binary_path)
    candidates = []
    same_dir = os.path.dirname(binary_path)
    if os.path.isdir(same_dir):
        candidates += [os.path.join(same_dir, f) for f in os.listdir(same_dir)
                       if f.startswith(name + ".wxkeep-bak-")]
    if user_data:
        comps = binary_path.rstrip("/").split("/")
        bundle = comps[-4] if len(comps) >= 4 else "unknown.app"
        bdir = os.path.join(user_data, "backups", bundle)
        if os.path.isdir(bdir):
            candidates += [os.path.join(bdir, f) for f in os.listdir(bdir)
                           if f.startswith(name + ".wxkeep-bak-")]
    return max(candidates) if candidates else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pristine")
    ap.add_argument("--patched")
    ap.add_argument("--app", help="bundle 模式：.app 目录（逐 binary 对最新 .wxkeep-bak-* 复算）")
    ap.add_argument("--userData", help="bundle 模式：userData 目录（主可执行备份在 backups/<bundle>/）")
    ap.add_argument("--audit", required=True, help="wxkeep.audit.json 路径")
    ap.add_argument("--binary", help="只对账此 bundle 相对路径的位点（多 binary 账目必选其一）")
    ap.add_argument("--arch", choices=["arm64", "x86_64"],
                    help="只对账此架构的位点（fat 双架构一次事务的账目必选其一）")
    args = ap.parse_args()
    if bool(args.pristine) != bool(args.patched):
        ap.error("--pristine 与 --patched 必须成对")
    if not ((args.pristine and args.patched) or args.app):
        ap.error("需 --pristine+--patched（单对模式）或 --app（bundle 模式）")
    if args.app and (args.pristine or args.binary or args.arch):
        ap.error("--app 与 --pristine/--binary/--arch 互斥（bundle 模式自动分组）")

    record = json.load(open(args.audit))
    sites = record.get("sites", [])

    # bundle 模式（127 轮遗留④）：逐 binary 自动取最新写前备份做 pristine
    # 参考，逐 arch 复算；任一 binary FAIL → 整体 FAIL。
    if args.app:
        by_binary = {}
        for s in sites:
            by_binary.setdefault(s.get("binary", ""), []).append(s)
        if not by_binary:
            print("✗ FAIL 账目无位点")
            sys.exit(1)
        overall = False
        for rel in sorted(by_binary):
            rel_norm = rel.rstrip("/")
            patched_path = os.path.join(args.app, rel_norm) if rel_norm else args.app
            if not os.path.exists(patched_path):
                print(f"✗ FAIL {rel}: patched 不在 app 内（{patched_path}）")
                overall = True
                continue
            backup = newest_backup_for(patched_path, args.userData)
            if backup is None:
                print(f"✗ FAIL {rel}: 找不到 .wxkeep-bak-* 备份（同目录与 "
                      f"--userData/backups/ 均无）——备份被删/prune，无法零信任复算")
                overall = True
                continue
            print(f"—— {rel}  pristine 参考: {os.path.basename(backup)}")
            for arch in sorted({s.get("arch", "") for s in by_binary[rel]}):
                arch_sites = [x for x in by_binary[rel] if x.get("arch") == arch]
                orig = load_arch_slice(backup, arch)
                patched = load_arch_slice(patched_path, arch)
                pair_fail, _w = verify_pair(orig, patched, arch_sites)
                overall |= pair_fail
        print("bundle 复算结论：" + ("通过——全部 binary 三方吻合" if not overall else "不通过"))
        sys.exit(1 if overall else 0)

    # 单对模式（既有语义）
    pairs = sorted({(s.get("binary", ""), s.get("arch", "")) for s in sites})
    # 多 binary/多架构过滤（双评审 P1：单一 --pristine 只能验一对——其余
    # 位点混入会把偏移算到错的文件上=假红；不选时如多于一对直接指引）。
    selected = [s for s in sites
                if (not args.binary or s.get("binary") == args.binary)
                and (not args.arch or s.get("arch") == args.arch)]
    skipped = len(sites) - len(selected)
    if pairs and not selected:
        print(f"✗ FAIL 过滤后无位点可对账。账目含 (binary, arch) 对: {pairs}——"
              f"用 --binary/--arch 选一对并给对应 pristine；或改用 --app bundle 模式。")
        sys.exit(1)
    if len(pairs) > 1 and not (args.binary or args.arch):
        print(f"✗ FAIL 账目跨多 (binary, arch) 对 {pairs}——单一 pristine 无法"
              f"整体复算；用 --binary/--arch 分次对账，或改用 --app bundle 模式。")
        sys.exit(1)
    arch = args.arch or (pairs[0][1] if pairs else "arm64")

    orig = load_arch_slice(args.pristine, arch)
    patched = load_arch_slice(args.patched, arch)
    fail, _warns = verify_pair(orig, patched, selected, skipped=skipped)
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
