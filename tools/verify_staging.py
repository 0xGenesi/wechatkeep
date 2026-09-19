#!/usr/bin/env python3
"""
verify_staging.py — 对 var/staging/<build>.json 跑引擎级往返验证。

分组语义（对应真实引擎的变体选择，互斥条目不得混组——silent 的 revoke
与 keeptip 的归一化恢复型同址互写，混组会在幂等步互相打架）：
  revoke.x64         staging revoke target 的 x86_64 条目（含 guard）
  revoke-keeptip.x64 staging keeptip target 的 x86_64 条目
  update.x64         staging update target 的 x86_64 条目
  revoke.arm         staging arm64 revoke（配方派生）+ 目录既有 arm64 revoke
  revoke-keeptip.arm 目录既有 arm64 keeptip（对 CDN 原版字节的首验）
  update.arm         目录既有 arm64 update

每组以 BackfillRoundtripTests（WXKEEP_BACKFILL_DYLIB/JSON）驱动：
pristine 已知 → patch → 幂等 → restoreAsm 反演 → 字节级一致。
绝对路径强制（相对路径在测试进程 cwd 漂移时静默跳过——2026-09-19 实证）；
输出含 "skipped:" 即判失败（环境变量/文件缺失不得伪装成通过）。

用法: python3 tools/verify_staging.py --build 269627
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run_group(name, dylib, entries):
    if not entries:
        return True, "（无条目，跳过组）"
    jf = dylib + "." + name + ".json"
    json.dump(entries, open(jf, "w"))
    r = subprocess.run(
        ["swift", "test", "--filter", "BackfillRoundtrip"],
        capture_output=True, text=True, cwd=ROOT, timeout=600, env=dict(
            os.environ,
            WXKEEP_BACKFILL_DYLIB=dylib, WXKEEP_BACKFILL_JSON=open(jf).read()))
    out = r.stdout + r.stderr
    if "skipped:" in out:
        return False, "harness 静默跳过（环境变量/路径问题）"
    if "failed" in out or r.returncode != 0:
        return False, out[out.find("✘"):][:600] if "✘" in out else out[-600:]
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True)
    args = ap.parse_args()
    build = args.build
    staging = os.path.join(ROOT, "var/staging", f"{build}.json")
    x64 = os.path.join(ROOT, "var/wxarm", f"{build}_x64.dylib")
    arm = os.path.join(ROOT, "var/wxarm", f"{build}_arm64.dylib")
    st = json.load(open(staging))

    cfg = json.load(open(os.path.join(ROOT, "config.json")))
    v = next((x for x in cfg if x["version"] == build), None)
    old = {t["identifier"]: [e for e in t["entries"] if e["arch"] == "arm64"]
           for t in (v["targets"] if v else [])}

    def stag(identifier, arch):
        for t in st["targets"]:
            if t["identifier"] == identifier:
                return [e for e in t["entries"] if e["arch"] == arch]
        return []

    groups = [
        ("revoke.x64", x64, stag("revoke", "x86_64")),
        ("revoke-keeptip.x64", x64, stag("revoke-keeptip", "x86_64")),
        ("update.x64", x64, stag("update", "x86_64")),
        ("revoke.arm", arm, stag("revoke", "arm64") + old.get("revoke", [])),
        ("revoke-keeptip.arm", arm,
         stag("revoke-keeptip", "arm64") + old.get("revoke-keeptip", [])),
        ("update.arm", arm, stag("update", "arm64") + old.get("update", [])),
    ]
    fails = 0
    for name, dylib, entries in groups:
        if not os.path.exists(dylib):
            continue
        ok, msg = run_group(f"{build}.{name}", dylib, entries)
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {build} {name} ({len(entries)} 条){(' — ' + msg) if msg and not ok else ''}")
        fails += 0 if ok else 1
    print(f"  {build}: {'全部通过' if not fails else f'{fails} 组失败'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
