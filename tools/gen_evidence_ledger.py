#!/usr/bin/env python3
"""
gen_evidence_ledger.py — L14 证明随行：证据台账生成（V6-DEPTH D18/R17，133 轮）。

「全绿」的读者此前只有作者：证据 = release notes 散文 + var/logs/ 散落台账，
无统一 schema、无一致性引用（台账文件可能被后续轮覆盖）。本工具把各 L 族
台账收敛为机器可核验的 evidence-ledger.json：
  · 每 L 族 → 最新台账文件 + sha256 + 结论行（PASS/FAIL/计数）+ git HEAD；
  · 结论行缺失或 FAIL → 退出非零（发版门红）；
  · 台账文件的结论行按族约定正则提取（见 LEDGERS 表）。

发版 SOP 接线（MAINTAINING「发版策略」）：tag 前 `make evidence-ledger`，
ledger 随 release notes 引用；第三方复算 = 对每个文件重算 sha256 + 重跑
对应 L 族工具。

用法: python3 tools/gen_evidence_ledger.py [--out var/logs/evidence-ledger.json]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOGS = os.path.join(ROOT, "var", "logs")

# L 族 → (台账文件 glob, 成功判定正则列表——任一命中即 PASS；全文件无
# 失败标志)。判定正则按各族台账的**实际产出格式**（133 轮实测对齐）：
# L2/L6 = swift Suite passed 行；L9 = 结论行/FAIL 0；L1 = 失配数 0；
# SOAK = 门槛通过行；L10/L12/L13 = 工具自写的 "Lx PASS" 汇总行。
LEDGERS = {
    "L1": (r"l1-ground-truth.*\.txt", [r"结论：失配数 = 0"]),
    "L2": (r"l2-reversibility.*\.txt", [r"Suite L2ReversibilityTests passed"]),
    "L6": (r"l6-determinism.*\.txt", [r"Suite L6DeterminismTests passed"]),
    "L9": (r"isa-diff.*\.txt", [r"L9 结论：指令级结构证明成立", r"FAIL\s+0"]),
    # L10 无独立台账族（合成矩阵在 swift test 全量 CI 双腿常跑，归入
    # 「测试绿」判据面；台账索引见 V6-DEPTH §6）。
    "L12": (r"confusion-matrix.*\.txt", [r"L12 PASS"]),
    "L13": (r"bundle-effect.*\.txt", [r"L13 PASS"]),
    "SOAK": (r"launch-soak.*\.txt", [r"门槛通过"]),
}
# 精确失败形态（计数为 0 的 FAIL 是成功形态——L9 台账 "PASS 660 FAIL 0"）：
FAIL_MARKERS = (r"FAIL\s+[1-9]", r"FAIL=[1-9]", r"MISMATCH=[1-9]",
                r"失配数 = [1-9]", r"✘\s+(Test|Suite)")

# 分层（133 轮）：CI 合成面已覆盖判据的族缺失不阻塞发版（OPTIONAL——如实
# 登记不假装跑过）；真件深度族（L2/L6/L9/SOAK）缺失 = 发版门红——源码-only
# 发版策略下它们是「全绿」的实体。L10 崩溃矩阵/L12+L13 合成矩阵在 swift
# test 全量（CI 双腿）常跑，其真件腿台账在场时验 PASS、缺席降级登记。
OPTIONAL = {"L1", "L12", "L13"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head():
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def latest_ledger(family, pattern):
    """该族最新（按文件名字典序 = 日期戳序）台账路径，无则 None。"""
    rx = re.compile(pattern)
    best = None
    for name in os.listdir(LOGS) if os.path.isdir(LOGS) else []:
        if rx.fullmatch(name):
            if best is None or name > best:
                best = name
    return os.path.join(LOGS, best) if best else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(LOGS, "evidence-ledger.json"))
    args = ap.parse_args()

    ledger = {
        "schema": 1,
        "generated_at": datetime.datetime.now().isoformat(),
        "git_head": git_head(),
        "families": {},
    }
    missing_required, failing = [], []
    for family, (pattern, verdict_rxs) in sorted(LEDGERS.items()):
        path = latest_ledger(family, pattern)
        entry = {"status": "missing", "optional": family in OPTIONAL}
        if path:
            entry.update({
                "status": "present",
                "file": os.path.relpath(path, ROOT),
                "sha256": sha256(path),
            })
            text = open(path, errors="replace").read()
            # L2/L6 的 --resume 语义：同日台账里旧失败批与恢复批并存
            #（133 轮实测：L6 20261103 首批 ENOSPC 12 issues、resume 批
            # 32 构建 passed）——判定取**最后一个** Suite 结果行，不全文
            # 并集（否则 resume 永远红）。其余族全文匹配 + 失败标志。
            suite_name = {"L2": "L2ReversibilityTests",
                          "L6": "L6DeterminismTests"}.get(family)
            suite_runs = re.findall(
                r"(✘|✔)\s+Suite (\w+Tests) (passed|failed)", text)
            suite_runs = [r for r in suite_runs if r[1] == suite_name]
            if suite_name and suite_runs:
                last_mark, last_suite, last_result = suite_runs[-1]
                if last_mark == "✔" and last_result == "passed":
                    entry["result"] = "PASS"
                    entry["verdict_lines"] = [f"{last_suite} {last_result}"]
                else:
                    entry["result"] = "FAIL"
                    failing.append(family)
            else:
                hits = [rx for rx in verdict_rxs if re.search(rx, text)]
                has_fail = any(re.search(m, text) for m in FAIL_MARKERS)
                if hits and not has_fail:
                    entry["result"] = "PASS"
                    # 落台账**命中行原文**而非正则串（双评审 P3：正则被当
                    # 证据行收录会让消费方困惑）。
                    entry["verdict_lines"] = [
                        next(ln.strip() for ln in text.splitlines()
                             if re.search(rx, ln))
                        for rx in hits]
                elif hits:
                    entry["result"] = "FAIL-MARKERS-PRESENT"
                    failing.append(family)
                else:
                    entry["result"] = "NO-VERDICT-LINE"
                    # 判定行缺失 = 台账 schema 漂移——按 FAIL 处理（防「有
                    # 文件就算绿」的空洞收录）。
                    failing.append(family)
        else:
            if family not in OPTIONAL:
                missing_required.append(family)
        ledger["families"][family] = entry

    ledger["result"] = "FAIL" if (failing or missing_required) else "PASS"
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ledger, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, args.out)

    print(f"证据台账：{args.out}")
    for family, entry in sorted(ledger["families"].items()):
        line = f"  {family}: {entry.get('result', entry['status'])}"
        if entry.get("file"):
            line += f" ({entry['file']})"
        if entry.get("optional"):
            line += " [optional]"
        print(line)
    if missing_required:
        print(f"✗ 缺必需族台账：{', '.join(missing_required)}——先跑对应 L 族工具"
              f"（真件深度族是发版门实体，见 V6-DEPTH §3）。")
    if failing:
        print(f"✗ FAIL/无结论行族：{', '.join(failing)}")
    sys.exit(0 if ledger["result"] == "PASS" else 1)


if __name__ == "__main__":
    main()
