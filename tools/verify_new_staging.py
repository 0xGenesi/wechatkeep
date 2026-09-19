#!/usr/bin/env python3
"""
verify_new_staging.py — 对本轮新增的 staging 条目文件跑引擎级往返验证。

针对 2026-09-19 一致性轮的两类新产物（与 verify_staging 的 <build>.json 形态不同，
本驱动消费 <build>.<family>.<arch>.json 单 target 文件）：
  1. locate_update_arm64 派生的 update.arm64（19 构建）
  2. gen3 几何派生的 269629.keeptip.arm64

每组 BackfillRoundtrip 语义不变：pristine 已知 → patch → 幂等 → restore →
字节级一致。防缓存回放三件套（㉚ 教训）：绝对路径、"skipped:" 判失败、
真实执行时长 <1s 判失败。
"""
import glob
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run_group(name, dylib, entries):
    jf = dylib + "." + name + ".verify.json"
    json.dump(entries, open(jf, "w"))
    t0 = time.time()
    r = subprocess.run(
        ["swift", "test", "--filter", "BackfillRoundtrip"],
        capture_output=True, text=True, cwd=ROOT, timeout=600, env=dict(
            os.environ,
            WXKEEP_BACKFILL_DYLIB=dylib, WXKEEP_BACKFILL_JSON=open(jf).read()))
    dur = time.time() - t0
    out = r.stdout + r.stderr
    if "skipped:" in out:
        return False, "harness 静默跳过"
    if dur < 1.0 and "passed" in out:
        return False, f"疑似缓存回放（{dur:.2f}s）"
    if "failed" in out or r.returncode != 0:
        return False, out[out.find("✘"):][:400] if "✘" in out else out[-400:]
    return True, f"{dur:.1f}s"


def main():
    files = sorted(glob.glob(os.path.join(ROOT, "var/staging",
                                          "*.*.arm64.json")))
    files = [f for f in files if ".verify.json" not in f]
    if len(sys.argv) > 1:
        files = [f for f in files if any(a in f for a in sys.argv[1:])]
    fails = 0
    for f in files:
        base = os.path.basename(f)            # <build>.<family>.arm64.json
        build = base.split(".")[0]
        dylib = os.path.join(ROOT, "var/wxarm", f"{build}_arm64.dylib")
        entries = json.load(open(f))["entries"]
        if not os.path.exists(dylib):
            print(f"  [SKIP] {base}: 无 {build}_arm64.dylib")
            continue
        ok, msg = run_group(base, dylib, entries)
        print(f"  [{'PASS' if ok else 'FAIL'}] {base} ({len(entries)} 条) {msg}")
        fails += 0 if ok else 1
    print("ALL:", "PASS" if not fails else f"{fails} FAIL")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
