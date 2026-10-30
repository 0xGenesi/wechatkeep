#!/usr/bin/env python3
"""
launch_soak.py — 补丁后启动浸泡门槛（V3-DEPTH，ROADMAP 73 轮；89 轮控制组臂）。

唯一用户可感的端到端客观标准：「打完补丁的微信能启动、活着、相对控制组
零新增崩溃」。此前该证明是手工动作（真机行为验证）；本工具把它做成可
重复的自动化对照实验，全程不碰 /Applications 装机件：

  1. 前置检查（app 存在 / 装机微信未运行 / 磁盘余量 / wxkeep 二进制在位）
  2. 控制组臂：clonefile 副本 → **原样启动**（不补丁不重签）→ 浸泡 →
     收集崩溃集 C（环境噪声基线——2026-10-31 实证：AppEx 组件热更新后
     任何副本语境沙盒初始化即崩，与补丁无关，绝对断言会假红）
  3. 补丁臂：clonefile 副本 → wxkeep patch（字节写入+重签+strict verify）
  4. open -n 启动补丁副本 → 浸泡 N 秒 → 断言主进程存活
  5. 归因：补丁臂新增 .ips 减控制组集合 = **可归因崩溃**；归因集空=门槛
     通过。每个 .ips 按 procPath 分类（副本/真机实例——真机崩溃非本
     实验归因，注记排除）
  6. 干净收场（TERM → 等待退出）+ 副本按 --keep 决定去留

--plan 只做前置与计划打印（不启动 GUI）——CI/无人值守可安全验证工具
链路。真实浸泡（弹登录窗）是用户触发动作：
    python3 tools/launch_soak.py --seconds 45
--no-control 跳过控制组臂（快迭代用；门槛退化为绝对零新增）。

退出码：0=门槛通过；1=检查失败/浸泡失败；2=可归因新崩溃报告。
"""
import argparse
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
DEFAULT_APP = "/Applications/WeChat.app"
REPORTS_DIR = os.path.expanduser("~/Library/Logs/DiagnosticReports")
MIN_FREE_GB = 8.0
LOG_DIR = os.path.join(ROOT, "var", "logs")


class Tee:
    """stdout 双写：终端 + 证据台账 var/logs/launch-soak-<stamp>.txt。
    与 l1/l2/l6 台账同惯例（var/ 不入库）——「跑过且全绿」的声称自此
    有盘上工件可审计，不依赖会话 stdout。"""

    def __init__(self, path):
        self._f = open(path, "w", encoding="utf-8", buffering=1)
        self._stdout = sys.stdout

    def write(self, s):
        self._stdout.write(s)
        self._f.write(s)

    def flush(self):
        self._stdout.flush()
        self._f.flush()


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def pgrep_escaped(path):
    """pgrep -f 的 ERE 转义（与 WeChatApp.pgrepPattern 同义：合法路径里的
    正则元字符不得让检测假阴性——「WeChat (1).app」类目录名）。"""
    out = re.escape(path)
    # re.escape 对 ERE 基本够用，但 macOS pgrep 是 ERE：re.escape 不会转义的
    # 部分 ERE 元字符补齐
    for ch in "(){}+?|":
        out = out.replace(ch, "\\" + ch)
    return out


def wechat_running():
    r = sh(["pgrep", "-f", pgrep_escaped(DEFAULT_APP + "/Contents/MacOS")])
    return r.returncode == 0


def snapshot_reports():
    if not os.path.isdir(REPORTS_DIR):
        return set()
    return {f for f in os.listdir(REPORTS_DIR)
            if "wechat" in f.lower() and f.endswith(".ips")}


def ips_proc_path(report_file):
    """读 .ips 的 procPath（首行 meta + 次行 body JSON；解析失败 = None）。"""
    try:
        with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        _, body = raw.split("\n", 1)
        return json.loads(body).get("procPath")
    except Exception:
        return None


def crash_signature(report_file):
    """崩溃身份签名：procName+procPath+异常类型+首故障帧（镜像+符号）。
    控制组与补丁臂的同一类崩溃**文件名必不同**（pid/时间戳后缀）——
    集合对冲必须按身份而非文件名（89 轮实误：按名减法把同类环境崩
    全判成可归因，5 份基线与 5 份补丁臂互不能抵）。解析失败 = None。"""
    try:
        with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        _, body = raw.split("\n", 1)
        b = json.loads(body)
        exc = str(b.get("exception", {}).get("type", "?"))
        ft = b.get("faultingThread", 0)
        threads = b.get("threads", [])
        imgs = b.get("usedImages", [])
        frame_sig = "?"
        if ft < len(threads):
            frs = threads[ft].get("frames", [])
            if frs:
                fr = frs[0]
                idx = fr.get("imageIndex", 0)
                img = imgs[idx] if idx < len(imgs) else {}
                frame_sig = f'{img.get("name", "?")}+{fr.get("symbol", "?")}'
        return f'{b.get("procName", "?")}|{b.get("procPath", "?")}|{exc}|{frame_sig}'
    except Exception:
        return None


def classify_reports(names, quarantine):
    """崩溃报告归因分类：副本进程 / 真机实例 / 未知（解析失败按副本算，
    保守计入门槛）。真机实例崩溃 = 非本实验归因（soak 全程不碰
    /Applications，真机窗口期自身崩溃属环境事件）。"""
    copy_names, real_names, unknown = [], [], []
    for n in names:
        path = ips_proc_path(os.path.join(REPORTS_DIR, n))
        if path is None:
            unknown.append(n)
        elif quarantine in path or "/var/folders/" in path:
            copy_names.append(n)
        else:
            real_names.append(n)
    return copy_names, real_names, unknown


def find_wxkeep():
    for cand in [os.path.join(ROOT, ".build/release/wxkeep"),
                 os.path.join(ROOT, ".build/debug/wxkeep"),
                 os.path.join(ROOT, ".build/arm64-apple-macosx/debug/wxkeep"),
                 shutil.which("wxkeep")]:
        if cand and os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def preconditions(args):
    problems = []
    if not os.path.exists(os.path.join(args.app, "Contents/Info.plist")):
        problems.append(f"{args.app} 不是 app bundle")
    if wechat_running() and not args.plan:
        problems.append("装机微信正在运行——浸泡副本与主实例的登录态/单实例语义会互相干扰，请先退出")
    free = shutil.disk_usage("/tmp").free / 2**30
    if free < MIN_FREE_GB:
        problems.append(f"磁盘余量不足（{free:.1f}GiB < {MIN_FREE_GB}GiB，副本≈1.5GiB）")
    wxkeep = find_wxkeep()
    if not wxkeep:
        problems.append("找不到 wxkeep 二进制（.build/release|debug 或 PATH）")
    return problems, wxkeep


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--app", default=DEFAULT_APP)
    ap.add_argument("--seconds", type=int, default=45, help="浸泡时长（默认 45s）")
    ap.add_argument("--variant", default="silent", choices=["silent", "keeptip"])
    ap.add_argument("--plan", action="store_true",
                    help="只打印计划并跑前置检查+隔离打补丁，不启动 GUI")
    ap.add_argument("--keep", action="store_true", help="保留隔离副本（排障）")
    ap.add_argument("--no-control", action="store_true",
                    help="跳过控制组臂（快迭代；门槛退化为绝对零新增）")
    args = ap.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    quarantine = os.path.join(tempfile.gettempdir(), f"wxkeep-soak-{stamp}")
    copy_app = os.path.join(quarantine, "WeChat.app")

    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"launch-soak-{stamp}.txt")
    sys.stdout = Tee(log_path)

    print("== 启动浸泡门槛 ==")
    print(f"app:      {args.app}")
    print(f"变体:     {args.variant}   浸泡: {args.seconds}s   模式: {'plan(不启动GUI)' if args.plan else 'soak'}")
    print(f"隔离区:   {quarantine}")
    print(f"台账:     {log_path}")

    problems, wxkeep = preconditions(args)
    for p in problems:
        print(f"  ✘ {p}")
    if problems:
        sys.exit(1)
    print(f"  ✓ 前置检查通过（wxkeep={wxkeep}）")

    if args.plan:
        print("\n[plan] 后续步骤（soak 模式将执行）：")
        if not args.no_control:
            print("  0. 控制组臂：clonefile 副本原样启动（不补丁不重签）→ 浸泡 → 崩溃集 C（环境噪声基线）")
        print("  1. clonefile 副本 → 隔离区")
        print(f"  2. {wxkeep} patch --app <副本> --variant {args.variant}（全链：expected 门+备份+重签+strict verify+WAL journal）")
        print("  3. snapshot DiagnosticReports(WeChat .ips)")
        print("  4. open -n 副本 → 浸泡 → pgrep 存活断言")
        print("  5. 归因：补丁臂新增 .ips 减控制组集合（--no-control=绝对零新增）→ TERM 收场")
        sys.exit(0)

    # ---- soak ----
    os.makedirs(quarantine, exist_ok=True)

    # ---- 控制组臂：环境噪声基线（pristine 副本原样启动） ----
    control_crashes = set()
    control_copy = os.path.join(quarantine, "control-WeChat.app")
    if not args.no_control:
        t0 = time.time()
        r = sh(["cp", "-cR", args.app, control_copy])   # -c = clonefile（CoW）
        if r.returncode != 0:
            print(f"✘ 控制组副本失败: {r.stderr.strip()}")
            sys.exit(1)
        cbefore = snapshot_reports()
        r = sh(["open", "-n", control_copy])
        if r.returncode != 0:
            print(f"✘ 控制组 open 失败: {r.stderr.strip()}")
            sys.exit(1)
        print(f"✓ 控制组副本已启动（pristine，{time.time()-t0:.1f}s），浸泡 {args.seconds}s …")
        time.sleep(args.seconds)
        cprobe = sh(["pgrep", "-f", pgrep_escaped(control_copy + "/Contents/MacOS")])
        print(f"  控制组进程{'存活（pid ' + cprobe.stdout.strip().split().__str__() + '）' if cprobe.returncode == 0 else '消失'}")
        for pid in cprobe.stdout.split():
            sh(["kill", "-TERM", pid])
        for _ in range(10):
            time.sleep(1)
            if sh(["pgrep", "-f", pgrep_escaped(control_copy + "/Contents/MacOS")]).returncode != 0:
                break
        else:
            for pid in cprobe.stdout.split():
                sh(["kill", "-KILL", pid])
        time.sleep(2)   # 崩溃报告落盘窗口
        cfresh = snapshot_reports() - cbefore
        cc, cr, _ = classify_reports(cfresh, quarantine)
        control_crashes = set(cc) | set(cr) | set(cfresh)
        print(f"✓ 控制组收场：环境噪声基线 {len(cfresh)} 份"
              f"（副本 {len(cc)} / 真机实例 {len(cr)}）")
        shutil.rmtree(control_copy, ignore_errors=True)

    # ---- 补丁臂 ----
    t0 = time.time()
    r = sh(["cp", "-cR", args.app, copy_app])   # -c = clonefile（CoW，秒级）
    if r.returncode != 0:
        print(f"✘ 副本失败: {r.stderr.strip()}")
        sys.exit(1)
    print(f"✓ 副本就绪（{time.time()-t0:.1f}s）")

    r = sh([wxkeep, "patch", "--app", copy_app, "--variant", args.variant])
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr)
        print("✘ 副本补丁失败（隔离区内，装机件无损）")
        sys.exit(1)
    print("✓ 副本补丁+重签+strict verify 全链通过")

    before = snapshot_reports()
    r = sh(["open", "-n", copy_app])
    if r.returncode != 0:
        print(f"✘ open 失败: {r.stderr.strip()}")
        sys.exit(1)
    print(f"✓ 已启动副本（open -n），浸泡 {args.seconds}s …")

    time.sleep(args.seconds)
    probe = sh(["pgrep", "-f", pgrep_escaped(copy_app + "/Contents/MacOS")])
    alive = probe.returncode == 0
    if not alive:
        print("✘ 浸泡期内进程消失（启动即崩或被杀）")
    else:
        print(f"✓ 进程存活（pid {probe.stdout.strip().split()}）")

    time.sleep(2)   # 给崩溃报告落盘留窗口
    after = snapshot_reports()
    fresh = after - before
    copy_fresh, real_fresh, unknown_fresh = classify_reports(fresh, quarantine)
    if real_fresh:
        print(f"  ↳ 真机实例崩溃 {len(real_fresh)} 份（非本实验归因——soak 全程不碰 /Applications，注记排除）")
    # 归因（按崩溃身份签名）：可归因 = 副本新增 − 控制组同签名复现；
    # 签名解析失败的报告保守计为可归因
    control_sigs = {crash_signature(os.path.join(REPORTS_DIR, n))
                    for n in control_crashes}
    control_sigs.discard(None)
    attributable, env_matched = [], []
    for n in sorted(set(copy_fresh) | set(unknown_fresh)):
        sig = crash_signature(os.path.join(REPORTS_DIR, n))
        if sig is not None and sig in control_sigs:
            env_matched.append(n)
        else:
            attributable.append(n)
    if attributable:
        print(f"✘ 可归因新崩溃 {len(attributable)} 份: {attributable[:3]}")
    elif fresh:
        detail = f"（环境噪声 {len(env_matched)} 份已被控制组同签名复现对冲"
        if real_fresh:
            detail += f"；真机实例 {len(real_fresh)} 份非本实验归因"
        print(f"✓ DiagnosticReports 相对控制组零可归因新增（原始新增 {len(fresh)} 份{detail}）")
    else:
        print("✓ DiagnosticReports 零新增（WeChat .ips 对照为空集）")

    # 收场：TERM 副本进程，等待退出
    if alive:
        for pid in probe.stdout.split():
            sh(["kill", "-TERM", pid])
        for _ in range(10):
            time.sleep(1)
            if sh(["pgrep", "-f", pgrep_escaped(copy_app + "/Contents/MacOS")]).returncode != 0:
                break
        else:
            for pid in probe.stdout.split():
                sh(["kill", "-KILL", pid])
        print("✓ 副本进程已收场")

    if not args.keep:
        shutil.rmtree(quarantine, ignore_errors=True)
        print("隔离区已清理（--keep 可保留）")

    if not alive:
        sys.exit(1)
    if attributable:
        sys.exit(2)
    print("== 门槛通过：补丁后可启动、存活、相对控制组零可归因崩溃 ==")
    sys.exit(0)


if __name__ == "__main__":
    main()
