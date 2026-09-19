#!/usr/bin/env python3
"""
merge_staging.py — var/staging/<build>.json 合入 config.json。

语义与 Config.load 的本地合并一致（⑫ 轮 catalog 晋升同款）：
  - 目录既有条目优先：同 (identifier, binary, arch, addr) 不覆盖
  - 新 target / 新条目追加；staging 的 version entry 不存在则新建
  - 隔离回填（backfill 列表）对目录条目就地补 expected（值 = CDN 原版实读）
  - 写前备份 config.json；写后报告增量统计

用法: python3 tools/merge_staging.py [--staging-dir var/staging] [--dry-run]
"""
import argparse
import glob
import json
import os
import shutil
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def merge(cfg, report):
    added = backfilled = new_versions = 0
    for path in sorted(glob.glob(
            os.path.join(args.staging_dir, "*.json"))):
        name = os.path.basename(path)
        if "." in name.replace(".json", ""):
            continue   # 验证用的分组文件（build.group.json）跳过
        st = json.load(open(path))
        build = st["build"]
        v = next((x for x in cfg if x["version"] == build), None)
        if v is None:
            v = {"version": build, "targets": []}
            cfg.append(v)
            new_versions += 1
        for t in st["targets"]:
            ct = next((x for x in v["targets"]
                       if x["identifier"] == t["identifier"]
                       and (x.get("binary") or "") == (t.get("binary") or "")), None)
            if ct is None:
                nt = {"identifier": t["identifier"],
                      "binary": t.get("binary", "Contents/Resources/wechat.dylib"),
                      "entries": t["entries"]}
                v["targets"].append(nt)
                added += len(t["entries"])
                continue
            have = {(e["arch"], e.get("addr")) for e in ct["entries"]}
            for e in t["entries"]:
                if (e["arch"], e.get("addr")) not in have:
                    ct["entries"].append(e)
                    added += 1
        for b in st.get("backfill", []):
            if "expected" not in b:
                continue
            for ct in v["targets"]:
                if ct["identifier"] != b["identifier"]:
                    continue
                for e in ct["entries"]:
                    if (e["arch"] == b["arch"] and e.get("addr") == b["addr"]
                            and not e.get("expected")):
                        e["expected"] = b["expected"]
                        backfilled += 1
    return added, backfilled, new_versions


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--staging-dir", default=os.path.join(ROOT, "var/staging"))
    ap.add_argument("--config", default=os.path.join(ROOT, "config.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    added, backfilled, new_versions = merge(cfg, args)
    print(f"新增条目 {added}，隔离回填 {backfilled}，新构建号 {new_versions}")
    if args.dry_run:
        print("dry-run: 不写回")
        raise SystemExit(0)
    # 目录惯例：构建号数值降序
    cfg.sort(key=lambda v: int(v["version"]) if v["version"].isdigit() else 0,
             reverse=True)
    bak = args.config + ".bak." + time.strftime("%Y%m%d%H%M%S")
    shutil.copy(args.config, bak)
    json.dump(cfg, open(args.config, "w"), indent=1, ensure_ascii=False)
    print(f"已写回 {args.config}（备份 {os.path.basename(bak)}）")
