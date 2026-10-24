#!/usr/bin/env python3
"""
verify_determinism.py — L6 确定性台账驱动（V3-DEPTH，ROADMAP 73 轮）。

预言：patch(pristine) 是数学函数——同一 pristine 出发的两份独立副本，
引擎输出 sha256 恒等（silent 与 keeptip 两条路径），restore 后各自回到
pristine sha。swift 侧 oracle 在 L6DeterminismTests（WXKEEP_L6_PLAN 注入，
真 Engine/真切片），本脚本只生成计划、驱动测试、落证据台账。

附带实证：codesign ad-hoc 对同一输入是否逐字节确定（两次独立签名比对
sha256）——这是「全管线（patch+resign）确定性」命题的前置事实，结论记入
台账（informational，不作硬门——Apple 未对此作出承诺）。

用法: python3 tools/verify_determinism.py
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WXARM = os.path.join(ROOT, "var", "wxarm")


def build_plan():
    builds = sorted({f[:f.index("_")] for f in os.listdir(WXARM)
                     if re.match(r"^\d+_(arm64|x64)\.dylib$", f)})
    plan = []
    for b in builds:
        arm = os.path.join(WXARM, f"{b}_arm64.dylib")
        x64 = os.path.join(WXARM, f"{b}_x64.dylib")
        if os.path.exists(arm) and os.path.exists(x64):
            plan.append({"build": b, "arm": arm, "x64": x64})
    return plan


def codesign_determinism_probe():
    """ad-hoc 签名确定性实证：同一未签名输入两次独立签名 → sha256 比对。"""
    work = tempfile.mkdtemp(prefix="wxkeep-csdet-")
    try:
        src = os.path.join(WXARM, "270101_arm64.dylib")
        if not os.path.exists(src):
            src = os.path.join(WXARM, sorted(os.listdir(WXARM))[0])
        hashes = []
        for i in range(2):
            copy = os.path.join(work, f"copy{i}.dylib")
            shutil.copyfile(src, copy)
            r = subprocess.run(["/usr/bin/codesign", "-f", "-s", "-", copy],
                               capture_output=True, text=True)
            if r.returncode != 0:
                return f"SKIP（codesign 失败: {r.stderr.strip()[:120]}）"
            h = subprocess.run(["shasum", "-a", "256", copy],
                               capture_output=True, text=True).stdout.split()[0]
            hashes.append(h)
        return ("DETERMINISTIC ✓ " + hashes[0][:16]
                if hashes[0] == hashes[1]
                else f"NON-DETERMINISTIC ✘ {hashes[0][:16]} vs {hashes[1][:16]}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    plan = build_plan()
    if not plan:
        print("var/wxarm 无成对切片——无事可做")
        sys.exit(1)
    plan_path = os.path.join(ROOT, "var", "l6-plan.json")
    json.dump(plan, open(plan_path, "w"))
    print(f"L6 计划：{len(plan)} 构建 × 双架构 → {plan_path}")

    env = dict(os.environ, WXKEEP_L6_PLAN=plan_path)
    # 可靠调用（2026-10-20 实证）：-load-plugin-library 显式装载绕过
    # TestingMacros 插件发现失效；独立 scratch path 防 Swift Build 变更
    # 检测楔死导致的陈旧二进制假绿（72 轮 L4① 教训）。
    tm = ("/Library/Developer/CommandLineTools/usr/lib/swift/host/"
          "plugins/testing/libTestingMacros.dylib")
    scratch = "/tmp/l6-fresh-scratch"
    shutil.rmtree(scratch, ignore_errors=True)
    out = ""
    for attempt in range(5):
        r = subprocess.run(["swift", "test", "--disable-sandbox",
                            "-Xswiftc", "-load-plugin-library", "-Xswiftc", tm,
                            "--scratch-path", scratch,
                            "--filter", "L6Determinism"],
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

    print("---- codesign ad-hoc 确定性实证 ----")
    cs_verdict = codesign_determinism_probe()
    print(cs_verdict)

    stamp = datetime.date.today().strftime("%Y%m%d")
    log = os.path.join(ROOT, "var", "logs", f"l6-determinism-{stamp}.txt")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    header = (f"L6 确定性 oracle — {len(plan)} 构建 × 双架构（{stamp}）\n"
              f"codesign ad-hoc 确定性（informational）: {cs_verdict}\n\n")
    open(log, "w").write(header + out)

    l6_lines = [l for l in out.splitlines() if l.startswith("L6 ")]
    failed = "✘" in out or "failed" in out or len(l6_lines) != len(plan)
    for l in l6_lines:
        print(l)
    if failed:
        print(f"✘ L6 存在失败（详见 {log}）")
        sys.exit(1)
    print(f"✓ L6 全过：{len(l6_lines)}/{len(plan)} 构建确定性成立；台账 {log}")


if __name__ == "__main__":
    main()
