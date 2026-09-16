#!/usr/bin/env python3
"""统计隔离区条目数（backfill workflow 用）。"""
import json
cfg = json.load(open("config.json"))
print(sum(1 for v in cfg for t in v["targets"] for e in t["entries"] if not e.get("expected")))
