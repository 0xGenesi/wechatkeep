#!/usr/bin/env python3
"""
gen_matrix.py — 从 config.json 自动生成版本兼容矩阵（docs/COMPATIBILITY.md）。

用法: python3 tools/gen_matrix.py [--config config.json] [--output docs/COMPATIBILITY.md]
"""
import argparse
import json
import os
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 已知构建号 → 展示版本（来自公开更新源与上游 catalog 备注）
KNOWN_DISPLAY = {
    "270100": "4.1.15", "270099": "4.1.15.19", "270098": "4.1.15.18",
    "270097": "4.1.15.17", "270096": "4.1.15.16", "270095": "4.1.15.15",
    "270094": "4.1.15.14", "270093": "4.1.15.13", "270092": "4.1.15.12",
    "270091": "4.1.15.11", "270090": "4.1.15.10",
    # 4.1.13 线：WeChatBundleVersion N ↔ 269568+N（2026-09-19 CDN 归档直链
    # 全线 HEAD 实证；269602=.34 落在 CDN 缺口段，维持 4.1.13 简称）
    "269631": "4.1.13.63", "269630": "4.1.13.62", "269629": "4.1.13.61",
    "269628": "4.1.13.60", "269627": "4.1.13.59", "269626": "4.1.13.58",
    "269625": "4.1.13.57", "269624": "4.1.13.56", "269622": "4.1.13.54",
    "269621": "4.1.13.53", "269620": "4.1.13.52", "269619": "4.1.13.51",
    "269618": "4.1.13.50", "269602": "4.1.13", "269579": "4.1.13.11",
    "269578": "4.1.13.10", "269577": "4.1.13.9", "269576": "4.1.13.8",
    "269575": "4.1.13.7", "269574": "4.1.13.6", "269573": "4.1.13.5",
    "269136": "4.1.11", "269111": "4.1.11", "269110": "4.1.11",
    "268880": "4.1.10", "268575": "4.1.10", "34371": "4.1.5", "32288": "3.8.x",
    "32281": "3.8.x", "31960": "3.8.x", "31927": "3.8.x",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(ROOT, "config.json"))
    ap.add_argument("--output", default=os.path.join(ROOT, "docs", "COMPATIBILITY.md"))
    args = ap.parse_args()

    catalog = json.load(open(args.config))
    rows = []
    for v in catalog:
        build = v["version"]
        targets = defaultdict(set)          # identifier -> {arch}
        quarantined = set()                 # (identifier, arch) 缺 expected
        for t in v["targets"]:
            for e in t["entries"]:
                targets[t["identifier"]].add(e["arch"])
                if not e.get("expected"):
                    quarantined.add((t["identifier"], e["arch"]))

        def mark(ident):
            archs = targets.get(ident, set())
            if not archs:
                return "—"
            cell = "/".join(sorted(archs, reverse=True))
            if (ident, "x86_64") in quarantined or (ident, "arm64") in quarantined:
                cell += " ⚠︎"        # 有条目缺溯源字节（隔离区）
            return cell

        display = v.get("_display") or KNOWN_DISPLAY.get(build, "")
        note = v.get("note", "")
        rows.append((int(build) if build.isdigit() else 0, build, display, mark("revoke"),
                     mark("revoke-keeptip"), mark("revoke-keeptip2"), mark("update"),
                     mark("multiInstance"), note))

    rows.sort(reverse=True)
    out = ["# 版本兼容矩阵", "",
           "> 由 `tools/gen_matrix.py` 从 config.json 自动生成，请勿手改。",
           "> `arm64/x86_64` = 该架构有条目；`⚠︎` = 条目缺 expected 溯源字节（默认隔离，需补验后放行）。",
           "", "| 构建号 | 微信版本 | 防撤回(silent) | keeptip | keeptip2 | 屏蔽更新 | 多开 | 备注 |",
           "|---|---|---|---|---|---|---|---|"]
    for _, build, display, revoke, keeptip, keeptip2, update, multi, note in rows:
        out.append(f"| {build} | {display or '?'} | {revoke} | {keeptip} | {keeptip2} | {update} | {multi} | {note} |")
    out += ["", f"共 {len(rows)} 个构建号。未知构建号可用 `wxkeep locate` / patch 时的 auto-locate 自动适配（配方签名代不变时）。"]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    open(args.output, "w").write("\n".join(out) + "\n")
    print(f"{args.output}: {len(rows)} builds")


if __name__ == "__main__":
    main()
