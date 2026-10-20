#!/usr/bin/env python3
"""
verify_reversibility.py — L2 可逆性穷举驱动（ROADMAP 72·L2）。

扫 var/wxarm 现存全部构建对（arm64+x64 thin 切片），生成计划 JSON 后一次
`swift test --filter L2Reversibility` 跑完（真 Patcher/真切片/真变体切换）。
预言：(a) 每个到达态全位点字节 ∈ 合法集 (b) 任意态 restore 后整文件
sha256 == pristine sha256。输出落 var/logs/l2-reversibility-<date>.txt。

用法: python3 tools/verify_reversibility.py
"""
import datetime
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WXARM = os.path.join(ROOT, "var", "wxarm")


def main():
    builds = sorted({f[:f.index("_")] for f in os.listdir(WXARM)
                     if re.match(r"^\d+_(arm64|x64)\.dylib$", f)})
    plan = []
    for b in builds:
        arm = os.path.join(WXARM, f"{b}_arm64.dylib")
        x64 = os.path.join(WXARM, f"{b}_x64.dylib")
        if os.path.exists(arm) and os.path.exists(x64):
            plan.append({"build": b, "arm": arm, "x64": x64})
    if not plan:
        print("var/wxarm 无成对切片——无事可做")
        sys.exit(1)
    plan_path = os.path.join(ROOT, "var", "l2-plan.json")
    json.dump(plan, open(plan_path, "w"))
    print(f"L2 计划：{len(plan)} 构建 × 双架构 → {plan_path}")

    env = dict(os.environ, WXKEEP_L2_PLAN=plan_path)
    # 可靠调用（2026-10-20 实证）：-load-plugin-library 显式装载绕过
    # TestingMacros 插件发现失效；独立 scratch path 防 Swift Build 变更
    # 检测楔死导致的陈旧二进制假绿。
    tm = ("/Library/Developer/CommandLineTools/usr/lib/swift/host/"
          "plugins/testing/libTestingMacros.dylib")
    scratch = "/tmp/l2-fresh-scratch"
    import shutil
    shutil.rmtree(scratch, ignore_errors=True)
    out = ""
    for attempt in range(5):
        r = subprocess.run(["swift", "test", "--disable-sandbox",
                            "-Xswiftc", "-load-plugin-library", "-Xswiftc", tm,
                            "--scratch-path", scratch,
                            "--filter", "L2Reversibility"],
                           capture_output=True, text=True, cwd=ROOT,
                           timeout=3600, env=env)
        out = r.stdout + r.stderr
        build_flake = "✘" not in out and ("Build failed" in out
                                          or "could not be found for macro" in out)
        if build_flake and attempt < 4:
            print(f"（构建层抖动，重试 {attempt + 1}/4）")
            time.sleep(2)
            continue
        break

    stamp = datetime.date.today().strftime("%Y%m%d")
    log = os.path.join(ROOT, "var", "logs", f"l2-reversibility-{stamp}.txt")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    open(log, "w").write(out)
    oks = len(re.findall(r"^L2 .*sha256 恒等 ✓$", out, re.M))
    fails = len(re.findall(r"✘|Issue recorded|error:", out))
    print(f"构建通过 {oks}/{len(plan)}；证据 → {log}")
    print("\n".join(re.findall(r"^L2 .*$", out, re.M)))
    sys.exit(0 if oks == len(plan) and r.returncode == 0 else 1)


if __name__ == "__main__":
    main()
