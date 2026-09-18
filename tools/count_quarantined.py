#!/usr/bin/env python3
"""统计隔离区条目数（backfill workflow 用）。
用法: python3 tools/count_quarantined.py [config.json 路径]
路径缺省按脚本位置解析仓库根（此前依赖 CWD，从非仓库根调用会 FileNotFoundError）。
"""
import json
import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, 'config.json')
cfg = json.load(open(path))
print(sum(1 for v in cfg for t in v["targets"] for e in t["entries"] if not e.get("expected")))
