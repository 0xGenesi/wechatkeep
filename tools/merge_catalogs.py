#!/usr/bin/env python3
"""
merge_catalogs.py — 合并上游补丁库为 wxkeep 的 config.json（带溯源）。

数据源（优先级从高到低，同级有 expected 者胜出）:
  1. vvanglro+wxkeep  — 含 269602 全套（arm64 来自 vvanglro 分支；x64 silent 为本项目自研定位）
     与 zengtianli 同优先级：平手保留先到，因此共享条目标 zengtianli，仅 269602 独有条目归此源
  2. zengtianli fork  — 38 构建号，arm64，全带 expected（安全门完整）
  3. tanranv5 fork    — 34 构建号（29 x64 + 5 上游 3.8.x），全部缺 expected
                        → 合并时标 source，引擎按隔离规则拒绝写入（除非显式放行）

用法: python3 tools/merge_catalogs.py [--output config.json]
"""
import argparse
import json
import os
import sys

SOURCES = [
    # (name, path, priority)  数字越大优先级越高
    ("tanranv5/WeChatTweak",  os.path.expanduser("/tmp/wct-tanranv5/config.json"), 1),
    ("zengtianli/WeChatTweak", os.path.expanduser("/tmp/WeChatTweak-fork/config.json"), 2),
    ("vvanglro+wxkeep",        os.path.expanduser("~/wechattweak-intel/config.json"), 2),
]

SOURCES_PRI = {name: pri for name, _path, pri in SOURCES}


def entry_key(version, target, entry):
    # 同一 target 同 arch 可以有多个补丁点（如 keeptip 三点），key 必须细到 addr。
    # binary 用 `or ""`：显式 null 与缺字段同权（否则 null 存进 key、输出端
    # 按 `or ""` 查找时条目会被静默丢弃——2026-09 审计修复）。
    return (version, target.get("identifier"), target.get("binary") or "", entry["arch"], entry.get("addr"))


def normalize_expected(entry):
    """expected 统一成数组形式（zengtianli 用数组，我们旧条目可能是字符串）。"""
    if "expected" in entry and isinstance(entry["expected"], str):
        entry["expected"] = [entry["expected"]]
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"))
    args = parser.parse_args()

    merged = {}          # key -> entry dict
    provenance = {}      # key -> (winner_source, losers:[(source, reason)])
    versions = {}        # version -> {"targets": {identifier: target}}

    for name, path, priority in SOURCES:
        if not os.path.exists(path):
            print(f"!! 跳过 {name}: {path} 不存在", file=sys.stderr)
            continue
        catalog = json.load(open(path))
        n_taken, n_lost = 0, 0
        for v in catalog:
            version = str(v["version"])
            for t in v["targets"]:
                for e in t["entries"]:
                    e = normalize_expected(dict(e))
                    key = entry_key(version, t, e)
                    has_expected = bool(e.get("expected"))
                    if key not in merged:
                        e["source"] = name
                        merged[key] = e
                        n_taken += 1
                    else:
                        incumbent = merged[key]
                        incumbent_has = bool(incumbent.get("expected"))
                        # 有 expected 的胜出；同级比优先级
                        challenger_wins = (has_expected and not incumbent_has) or \
                                          (has_expected == incumbent_has and priority > SOURCES_PRI[incumbent["source"]])
                        if challenger_wins:
                            e["source"] = name
                            merged[key] = e
                            provenance.setdefault(key, (name, []))[1].append(
                                (incumbent["source"], "replaced by higher-priority/expected-bearing entry"))
                            n_taken += 1
                        else:
                            provenance.setdefault(key, (incumbent["source"], []))[1].append(
                                (name, "duplicate, dropped"))
                            n_lost += 1
                    # 登记版本与 target 容器
                    if version not in versions:
                        versions[version] = {}
                    ident = t.get("identifier")
                    if ident not in versions[version]:
                        versions[version][ident] = {
                            "identifier": ident,
                            "binary": t.get("binary"),
                            "entries": [],
                        }
        print(f"{name}: 采纳/替换 {n_taken} 条, 丢弃重复 {n_lost} 条")

    # 重组输出：每 target 按 entry key 归位
    out = []
    for version in sorted(versions, key=lambda x: int(x) if x.isdigit() else 0, reverse=True):
        targets = []
        for ident in versions[version]:
            target = versions[version][ident]
            entries = [merged[k] for k in merged
                       if k[0] == version and k[1] == ident and k[2] == (target["binary"] or "")]
            target["entries"] = sorted(entries, key=lambda e: (e["arch"], e.get("addr", "")))
            if target["binary"] is None:
                target.pop("binary")
            targets.append(target)
        quarantined = sum(1 for t in targets for e in t["entries"] if not e.get("expected"))
        note = f"{quarantined} entries lack expected bytes (quarantined)" if quarantined else None
        out.append({"version": version, "targets": sorted(targets, key=lambda t: t["identifier"]),
                    **({"note": note} if note else {})})

    with open(args.output, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")

    total = sum(len(t["entries"]) for v in out for t in v["targets"])
    quarantined = sum(1 for v in out for t in v["targets"] for e in t["entries"] if not e.get("expected"))
    print(f"\n输出 {args.output}: {len(out)} 个构建号, {total} 条 entry"
          f"（{quarantined} 条缺 expected 被隔离）")
    archs = {}
    for v in out:
        for t in v["targets"]:
            for e in t["entries"]:
                archs[e["arch"]] = archs.get(e["arch"], 0) + 1
    print("架构分布:", archs)
    # 溯源报告：被替换的条目（此前只收集不输出——2026-09 审计补上）
    replaced = [(k, winner) for k, (winner, losers) in provenance.items()
                if any("replaced" in reason for _loser, reason in losers)]
    if replaced:
        print(f"\n替换决策 {len(replaced)} 条:")
        for (version, ident, _binary, arch, addr), winner in sorted(replaced):
            print(f"  {version} {ident}/{arch}@{addr} → {winner}")


if __name__ == "__main__":
    main()
