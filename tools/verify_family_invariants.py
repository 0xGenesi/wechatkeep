#!/usr/bin/env python3
"""verify_family_invariants.py — L18 目录自洽审计（V7-DEPTH D22/R22，134 轮）。

语料级不变量学派（Daikon / BinDiff 家族审计脉络）：day-0 派生依赖的
「家族同构」断言此前活在 ROADMAP 散文里——数据被机械改动（watcher
auto-PR / 键序重排事故类威胁）时无人守卫。本工具把它们变成对整个
config.json 常态机检的不变量：

  INV1 变体配对：有 revoke-keeptip 的构建必有 revoke；
  INV2 共享 VA 归一化耦合：revoke ∩ revoke-keeptip 共享位点上，
      revoke.asm 与 revoke pristine（expected[0]）都必须 ∈ keeptip.expected
      （172/172 实测零破例——变体互斥+归一化的结构前提）；
  INV3 restore 可达白名单：三域（revoke/keeptip/update）内不可还原条目
      仅允许出现在 28 个已定案构建（133 续㊃ 永久缺口）；
  INV4 重复 identifier 白名单：同构建同 identifier 多 target 仅限
      per-binary 拆分先例（8 构建）——undo 臂 first-only 语义的已知边界；
  INV5 家族指纹表：每构建的 (identifier, arch, asm 多重集) 指纹必须落在
      固化表内且计数吻合——新指纹（新派生轮）须显式登记后入表，
      计数缩水（条目丢失）即红；
  INV6 target 内 (arch, addr) 唯一（重叠写入运行时另有 Patcher 门，
      config 级先拒）。

用法: python3 tools/verify_family_invariants.py [--config config.json]
判定: "L18 PASS builds=123 fingerprints=23 exceptions=whitelisted" /
      FAIL + 逐项明细（evidence-ledger L18 族判定行）。
"""
import argparse
import collections
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 133 续㊃ 永久缺口定案：quarantined 条目（无归档可回填 expected）的
# 28 构建——三域内不可还原条目仅此白名单合法。
QUARANTINED_BUILDS = {
    "269341", "269340", "269338", "269337", "269335", "269111", "269110",
    "269079", "269077", "268851", "268850", "268831", "268602", "268596",
    "268575", "37342", "37331", "37303", "37293", "36677", "36603", "36559",
    "34817", "34371", "32288", "32281", "31960", "31927",
}

# per-binary 拆分先例（同 identifier 双 target）：3.x 线 keeptip 双位 +
# 37335 revoke 双位。undo 臂按 Engine 语义只还原 first —— 已知边界非缺陷。
DUP_ID_BUILDS = {
    "269363", "269362", "269336", "42530", "41754", "39917", "38959", "37335",
}

EXPECTED_TOTALS = {"builds": 124, "entries": 2003}

# 家族指纹表（134 轮实测固化；新派生轮 = 登记新指纹行 + 注出处）。
EXPECTED_FINGERPRINTS = {
    "automaticallyDownloadsUpdates|arm64|00008052C0035FD6x1;canCheckForUpdate|arm64|00008052C0035FD6x1;checkForUpdates|arm64|00008052C0035FD6x1;enableAutoUpdate|arm64|00008052C0035FD6x1;multiInstance|arm64|20008052C0035FD6x1;revoke|arm64|00008052C0035FD6x1;startBackgroundUpdatesCheck|arm64|00008052C0035FD6x1;startUpdater|arm64|00008052C0035FD6x1": 3,
    "multiInstance|arm64|20008052C0035FD6x1;revoke|arm64|00008052C0035FD6x1": 2,
    "multiInstance|arm64|20008052C0035FD6x1;revoke|arm64|00008052C0035FD6x1;revoke|x86_64|31C0C3909090909090x1;revoke-keeptip|arm64|40100034x1,7FE600F9x1,F44FBEA9FD7B01A9x1;revoke-keeptip|x86_64|4831C06690488983C8010000x1,4889C2x1,554889E553504889FBx1;revoke-keeptip2|x86_64|4831C090909090x1,4889C2x1,48C7C001000000C3x1,554889E553504889FBx1,9090909090x7,E812DC7D01x1;update|arm64|00008052C0035FD6x1;update|x86_64|31C0C3x1": 1,
    "multiInstance|x86_64|909090909090x1;revoke|arm64|7F000014x1;revoke|x86_64|B801000000C3x1;revoke-keeptip|arm64|7FB600F9x1,E00F0034x1": 2,
    "multiInstance|x86_64|909090909090x1;revoke|arm64|7F000014x1;revoke|x86_64|B801000000C3x1;revoke-keeptip|arm64|7FB600F9x1,E00F0034x1;update|arm64|00008052C0035FD6x2,C0035FD6x6": 3,
    "multiInstance|x86_64|909090909090x1;revoke|arm64|7F000014x1;revoke|x86_64|B801000000C3x1;revoke-keeptip|arm64|7FB600F9x1,E00F0034x1;update|arm64|00008052C0035FD6x2,C0035FD6x7": 5,
    "multiInstance|x86_64|909090909090x1;revoke|arm64|82000014x1;revoke|x86_64|30C0x1,31C0C3909090909090x1,B801000000C3x1;revoke-keeptip|arm64|40100034x1,7FE600F9x1;revoke-keeptip|x86_64|4831C06690488983C8010000x1,554889E553504889FBx1;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 5,
    "multiInstance|x86_64|909090909090x1;revoke|arm64|82000014x1;revoke|x86_64|B801000000C3x1;revoke-keeptip|arm64|40100034x1,7FCE00F9x1;update|arm64|00008052C0035FD6x2,C0035FD6x6": 3,
    "multiInstance|x86_64|909090909090x1;revoke|x86_64|31C0C3909090909090x1,B801000000C3x1;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 1,
    "multiInstance|x86_64|909090909090x1;revoke|x86_64|B801000000C3x1": 9,
    "multiInstance|x86_64|B801000000C3x1;revoke|x86_64|31C0909090x1": 1,
    "revoke|arm64|00008052C0035FD6x1;revoke|x86_64|31C0C3909090909090x1": 3,
    "revoke|arm64|7F000014x1": 1,
    "revoke|arm64|7F000014x1;revoke-keeptip|arm64|7FB600F9x1,E00F0034x1": 1,
    "revoke|arm64|7F000014x1;revoke-keeptip|arm64|7FB600F9x1,E00F0034x1;update|arm64|00008052C0035FD6x2,C0035FD6x7": 4,
    "revoke|arm64|7F000014x1;revoke|x86_64|31C0C3909090909090x1;revoke-keeptip|arm64|7FB600F9x5,E00F0034x5;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 3,
    "revoke|arm64|82000014x1;revoke-keeptip|arm64|40100034x1,7FCE00F9x1;update|arm64|00008052C0035FD6x2,C0035FD6x6": 3,
    "revoke|arm64|82000014x1;revoke|x86_64|30C0x1,31C0C3909090909090x1;revoke-keeptip|arm64|40100034x1,7FE600F9x1;revoke-keeptip|x86_64|4831C06690488983C8010000x1,554889E553504889FBx1;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 50,
    "revoke|arm64|82000014x1;revoke|x86_64|30C0x1,31C0C3909090909090x1;revoke-keeptip|arm64|40100034x1,7FE600F9x1;revoke-keeptip|x86_64|4831C06690488983C8010000x1,554889E553504889FBx1;update|x86_64|31C0C3x2,C3x6": 2,
    "revoke|arm64|82000014x1;revoke|x86_64|31C0C3909090909090x1;revoke-keeptip|arm64|40100034x5,7FCE00F9x5;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 4,
    "revoke|arm64|C0035FD6x1;revoke|x86_64|C3x1;revoke-keeptip|arm64|C0035FD6x1;revoke-keeptip|x86_64|C3x1;update|arm64|C0035FD6x2;update|x86_64|C3x2": 8,
    "revoke|arm64|C0035FD6x1;revoke|x86_64|C3x1;revoke-keeptip|arm64|C0035FD6x1;revoke-keeptip|x86_64|C3x1;update|arm64|C0035FD6x3;update|x86_64|C3x3": 8,
    "revoke|x86_64|31C0C3909090909090x1;update|arm64|00008052C0035FD6x2,C0035FD6x6;update|x86_64|31C0C3x2,C3x6": 1,
    # 270353（watcher auto-locate PR #4 首审轮，2026-11-10）：revoke-only 两行
    # = gen3 几何未变代的又一实例；首例无 keeptip/update/multiInstance 伴行
    # 的「纯 revoke 双架构」指纹。出处：CDN xWeChatMac_universal_4.2.0.17_
    # 270353.dmg（sha256 e47d5e1c…），fat wechat.dylib d61eab4f…，expected
    # 字节本地独立复核（arm64@4E7D404=40100034 / x64@516E9F0=
    # 554889E553504889FB，wxkeep locate 本机重跑同址同值）。
    "revoke|arm64|82000014x1;revoke|x86_64|31C0C3909090909090x1": 1,
}


def fingerprint(version_entry):
    per = collections.defaultdict(collections.Counter)
    for t in version_entry["targets"]:
        for e in t["entries"]:
            per[(t["identifier"], e.get("arch"))][e.get("asm", "")] += 1
    return ";".join(f"{i}|{a}|{','.join(f'{x}x{c}' for x, c in sorted(cnt.items()))}"
                    for (i, a), cnt in sorted(per.items()))


def entry_unrestorable(e):
    exp = e.get("expected")
    if not exp:
        return True
    exps = exp if isinstance(exp, list) else [exp]
    asm = e.get("asm", "")
    if asm in exps:
        return False
    first = exps[0]
    n = len(asm) // 2
    if not isinstance(first, str) or len(first) % 2:
        return True
    return any(first[i] == "?" or first[i + 1] == "?"
               for i in range(0, min(len(first), n * 2), 2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(ROOT, "config.json"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "var", "logs"))
    args = ap.parse_args()

    catalog = json.load(open(args.config))
    versions = catalog if isinstance(catalog, list) else catalog.get("versions", catalog)

    problems = []
    seen_fp = collections.Counter()

    for v in versions:
        build = v.get("version", "?")
        tmap = collections.defaultdict(list)
        for t in v["targets"]:
            tmap[t["identifier"]].append(t)

        # INV1 变体配对
        if tmap.get("revoke-keeptip") and not tmap.get("revoke"):
            problems.append(f"INV1 {build}: 有 revoke-keeptip 无 revoke")

        # INV2 共享 VA 归一化耦合
        ridx = {(e.get("arch"), e["addr"]): e
                for ts in tmap.get("revoke", []) for e in ts["entries"]}
        for e in [e for ts in tmap.get("revoke-keeptip", []) for e in ts["entries"]]:
            k = (e.get("arch"), e["addr"])
            if k in ridx:
                r = ridx[k]
                exp = e.get("expected")
                exps = exp if isinstance(exp, list) else ([exp] if exp else [])
                rexp = r.get("expected")
                rpristine = (rexp[0] if isinstance(rexp, list) else rexp) if rexp else None
                if r.get("asm") not in exps or (rpristine and rpristine not in exps):
                    problems.append(f"INV2 {build} {k}: keeptip.expected 未覆盖 "
                                    f"revoke.asm={r.get('asm')} / pristine={rpristine}")

        # INV3 三域 restore 可达白名单
        if build not in QUARANTINED_BUILDS:
            for tid in ("revoke", "revoke-keeptip", "update"):
                for e in [e for ts in tmap.get(tid, []) for e in ts["entries"]]:
                    if entry_unrestorable(e):
                        problems.append(f"INV3 {build} {tid}@{e['addr']}: 不可还原条目"
                                        f"不在 133 续㊃ 白名单")

        # INV4 重复 identifier
        dups = [k for k, c in collections.Counter(
            t["identifier"] for t in v["targets"]).items() if c > 1]
        if dups and build not in DUP_ID_BUILDS:
            problems.append(f"INV4 {build}: 重复 identifier {dups} 不在白名单")

        # INV6 target 内 (arch, addr) 唯一
        for t in v["targets"]:
            keys = collections.Counter((e.get("arch"), e["addr"]) for e in t["entries"])
            for k, c in keys.items():
                if c > 1:
                    problems.append(f"INV6 {build} {t['identifier']}: {k} ×{c} 重叠")

        seen_fp[fingerprint(v)] += 1

    # INV5 指纹表
    for fp_key, count in seen_fp.items():
        if fp_key not in EXPECTED_FINGERPRINTS:
            problems.append(f"INV5 新指纹未登记（新派生轮须显式入表+出处）: "
                            f"{fp_key[:120]}…")
    for fp_key, want in EXPECTED_FINGERPRINTS.items():
        got = seen_fp.get(fp_key, 0)
        if got != want:
            problems.append(f"INV5 指纹计数漂移: 期望 {want} 实测 {got} —— {fp_key[:100]}…")

    # 总量 tripwire
    if len(versions) != EXPECTED_TOTALS["builds"]:
        problems.append(f"总量漂移: builds {len(versions)} ≠ {EXPECTED_TOTALS['builds']}")
    total_entries = sum(len(t["entries"]) for v in versions for t in v["targets"])
    if total_entries != EXPECTED_TOTALS["entries"]:
        problems.append(f"总量漂移: entries {total_entries} ≠ {EXPECTED_TOTALS['entries']}")

    os.makedirs(args.log_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(args.log_dir, f"family-invariants-{ts}.txt")
    with open(log_path, "w") as log:
        for p in problems:
            log.write(p + "\n")
        verdict = "L18 FAIL" if problems else "L18 PASS"
        line = (f"{verdict} builds={len(versions)} fingerprints={len(seen_fp)} "
                f"quarantined_whitelist={len(QUARANTINED_BUILDS)} "
                f"dup_id_whitelist={len(DUP_ID_BUILDS)} entries={total_entries}")
        log.write(line + "\n")
    print(line)
    print(f"台账: {log_path}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
