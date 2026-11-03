#!/usr/bin/env python3
"""
verify_reversibility.py — L2 可逆性穷举驱动（ROADMAP 72·L2）。

扫 var/wxarm 现存全部构建对（arm64+x64 thin 切片），生成计划 JSON 后一次
`swift test --filter L2Reversibility` 跑完（真 Patcher/真切片/真变体切换）。
预言：(a) 每个到达态全位点字节 ∈ 合法集 (b) 任意态 restore 后整文件
sha256 == pristine sha256。输出落 var/logs/l2-reversibility-<date>.txt。

用法: python3 tools/verify_reversibility.py
"""
import argparse
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true",
                    help="续跑：跳过当日台账已 ✓ 的构建（长链在内存受压机器上"
                         "分批完成；2026-11-03 实证 21+ 构建后被 jetsam）")
    args = ap.parse_args()
    resume_log = os.path.join(ROOT, "var", "logs",
        f"l2-reversibility-{datetime.date.today().strftime('%Y%m%d')}.txt")
    done = set()
    if args.resume and os.path.exists(resume_log):
        done = {ln.split()[1].rstrip(":") for ln in open(resume_log) if ln.startswith("L2 ")}
    builds = sorted({f[:f.index("_")] for f in os.listdir(WXARM)
                     if re.match(r"^\d+_(arm64|x64)\.dylib$", f)})
    plan = []
    for b in builds:
        if b in done:
            continue
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
    df = subprocess.run(["df", "-g", "/tmp"], capture_output=True, text=True)
    avail = int(df.stdout.strip().split("\n")[-1].split()[3])
    if avail < 8:
        print(f"✗ 磁盘余量 {avail}G < 8G——L2 全链需 ~3G 瞬态（340MB fat×备份轮换），"
              f"ENOSPC 会以「拒无备份补丁」防线打断；先清理后重跑。")
        sys.exit(1)
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
    open(log, "a" if args.resume and done else "w").write(out)
    shutil.rmtree(scratch, ignore_errors=True)   # scratch 自清（2026-11-03 实证遗留 291MB）
    oks = len(re.findall(r"^L2 .*sha256 恒等 ✓$", out, re.M))
    print(f"构建通过 {oks}/{len(plan)}；swift test 退出码 {r.returncode}；证据 → {log}")
    print("\n".join(re.findall(r"^L2 .*$", out, re.M)))
    if oks != len(plan) or r.returncode != 0:
        # 2026-11-03 实证：91% 容量 + swap 9G 机器上 ENOSPC（备份拒写=防线
        # 按设计工作）+ 首跑无摘要硬杀（毒杀进程 defer 不跑 → /tmp 残留）。
        # 失败面三要素如实可见：退出码（负值=信号杀）/✘ 摘要/磁盘水位。
        df = subprocess.run(["df", "-g", "/tmp"], capture_output=True, text=True)
        print(f"失败诊断：✘ 行 {len(re.findall(r'✘', out))}；磁盘余量\n{df.stdout}")
    sys.exit(0 if oks == len(plan) and r.returncode == 0 else 1)


if __name__ == "__main__":
    main()
