#!/usr/bin/env python3
"""
verify_staging_batch.py — 对 var/wxarm/ 的 per-family 派生产物
（<build>_<arch>.dylib.<build>.<family>.<arch>.json）逐组跑引擎级往返验证。

分组语义：revoke 与 revoke-keeptip 是互斥变体（同位点相反方向），必须分
族验证——合并必失败（2026-10-29 实证：幂等步互翻）。BackfillRoundtrip
语义：pristine 门→patch→幂等→restore→字节级一致；防缓存回放三件套同
verify_new_staging.py。

用法: python3 tools/verify_staging_batch.py [过滤串 ...]   # 无参=全部
"""
import glob
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TM = ["--disable-sandbox", "-Xswiftc", "-load-plugin-library", "-Xswiftc",
      "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"]


def run_group(dylib, entries, retries=1):
    jf = dylib + ".verifybatch.json"
    json.dump(entries, open(jf, "w"))
    for attempt in range(retries + 1):
        t0 = time.time()
        r = subprocess.run(
            ["swift", "test", "--filter", "BackfillRoundtrip"] + TM,
            capture_output=True, text=True, cwd=ROOT, timeout=600, env=dict(
                os.environ,
                WXKEEP_BACKFILL_DYLIB=dylib, WXKEEP_BACKFILL_JSON=open(jf).read()))
        dur = time.time() - t0
        out = r.stdout + r.stderr
        if "skipped:" in out:
            if attempt < retries:
                continue
            return False, "harness 静默跳过"
        if dur < 1.0 and "passed" in out:
            if attempt < retries:
                continue
            return False, f"疑似缓存回放（{dur:.2f}s）"
        if "failed" in out or r.returncode != 0:
            if attempt < retries:
                continue
            return False, (out[out.find("✘"):][:300] if "✘" in out else out[-300:])
        return True, f"{dur:.1f}s"
    return False, "重试耗尽"


def main():
    pats = sys.argv[1:]
    files = sorted(glob.glob(os.path.join(
        ROOT, "var/wxarm", "*_*.dylib.*.json"))
        + glob.glob(os.path.join(ROOT, "var/wxarm", "*_main_*.json")))
    files = [f for f in files
             if ".verify.json" not in f and ".verifybatch.json" not in f]
    if pats:
        files = [f for f in files if any(p in f for p in pats)]
    fails = total = 0
    for f in files:
        base = os.path.basename(f)          # <b>_<arch>.dylib.<b>.<family>.<arch>.json
        # 或 3.x 主程序切片产物 <b>_main_<arch>.<b>.<family>.<arch>.json
        if "_main_" in base:
            stem = base.split(".", 1)[0]    # <b>_main_<arch>
        else:
            stem = base.split(".dylib", 1)[0] + ".dylib"
        dylib = os.path.join(ROOT, "var/wxarm", stem)
        if not os.path.exists(dylib):
            print(f"  [SKIP] {base}: 无切片")
            continue
        entries = json.load(open(f))
        entries = entries["entries"] if isinstance(entries, dict) else entries
        if not entries:
            continue
        total += 1
        ok, msg = run_group(dylib, entries)
        print(f"  [{'PASS' if ok else 'FAIL'}] {base[8:] if len(base) > 8 else base}"
              f" ({len(entries)} 条) {msg}", flush=True)
        fails += 0 if ok else 1
    print(f"TOTAL: {total} 组, ALL: {'PASS' if not fails else f'{fails} FAIL'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
