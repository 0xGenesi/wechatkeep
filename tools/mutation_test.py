#!/usr/bin/env python3
"""
mutation_test.py — L4 变异测试（ROADMAP 72·L4①）。

对安全关键路径注入单行变异（翻转条件/删校验/改常量），逐个跑全量测试
套件：任何失败/崩溃 = 变异被杀灭；全绿 = 存活（需逐条给出「可接受暴露」
或补测试）。还原用精确 old→new 字符串替换（出现次数必须恰为 1）。

用法: python3 tools/mutation_test.py [index ...]   # 无参 = 全部
"""
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TM = "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"
TEST_CMD = ["swift", "test", "--disable-sandbox",
            "-Xswiftc", "-load-plugin-library", "-Xswiftc", TM]

# (id, 文件, 原文, 变异, 说明)
MUTATIONS = [
    ("M01", "Sources/wxkeep/Patcher.swift",
     "guard variants.contains(where: { $0.matches(current) }) else {",
     "guard true || variants.contains(where: { $0.matches(current) }) else {",
     "expected 门失效（任何字节都接受写入）"),
    ("M02", "Sources/wxkeep/Patcher.swift",
     "if current.prefix(plan.asm.count) == plan.asm {",
     "if false && current.prefix(plan.asm.count) == plan.asm {",
     "alreadyPatched 判定失效（幂等重打必写入）"),
    ("M03", "Sources/wxkeep/Patcher.swift",
     "guard !dryRun else { return outcomes }",
     "guard false else { return outcomes }",
     "dry-run 也落盘（预演变实写）"),
    ("M04", "Sources/wxkeep/Config.swift",
     "if asmLen > provenance {",
     "if asmLen > provenance + 4096 {",
     "写入跨度≤溯源跨度校验放宽"),
    ("M05", "Sources/wxkeep/Config.swift",
     "if Data(hex: e.asm) == nil {",
     "if false && Data(hex: e.asm) == nil {",
     "坏 hex asm 装载期不拒"),
    ("M06", "Sources/wxkeep/ExpectedPattern.swift",
     "guard data.count >= byteCount else { return false }",
     "guard data.count + 8 >= byteCount else { return false }",
     "短数据放行（越界读风险）"),
    ("M07", "Sources/wxkeep/Engine.swift",
     'if set.contains("revoke") {',
     'if false {',
     "--only revoke 域别名失效"),
    ("M08", "Sources/wxkeep/Engine.swift",
     "                summary.wroteAnything = true",
     "                summary.wroteAnything = false",
     "变体切换还原写入不计入重签决策（67 轮缺陷复活）"),
    ("M09", "Sources/wxkeep/Engine.swift",
     'if target.identifier == "revoke-keeptip2" {\n                continue',
     'if false {\n                continue',
     "废弃变体 keeptip2 可被自动应用"),
    ("M10", "Sources/wxkeep/Backup.swift",
     "guard originalSize == backupSize, originalSize >= 0 else {",
     "guard originalSize >= 0 else {",
     "截断备份不拒绝"),
    ("M11", "Sources/wxkeep/Backup.swift",
     "        return exe == binary.lastPathComponent",
     "        return false",
     "主可执行识别失效（备份落 bundle 内=双杀缺陷复活）"),
    ("M12", "Sources/wxkeep/Resigner.swift",
     "            if plistsEqual(inspectEntitlements(entry.url), intended) { return nil }",
     "            if true { return nil }",
     "entitlements 漂移检测失效"),
    ("M13", "Sources/wxkeep/MachOInjector.swift",
     "        guard removedAny else {",
     "        guard false else {",
     "LC 未找到也报成功（remove 假成功=删 dylib 必崩）"),
    ("M14", "Sources/wxkeep/Manifest.swift",
     "        guard pubKey.isValidSignature(signature, for: canonical) else {",
     "        guard true || pubKey.isValidSignature(signature, for: canonical) else {",
     "Ed25519 签名校验失效（供应链门洞开）"),
    ("M15", "Sources/wxkeep/WeChatApp.swift",
     '            if metachars.contains(ch) { out.append("\\\\") }',
     '            if false { out.append("\\\\") }',
     "pgrep ERE 转义失效（71 轮缺陷复活）"),
    ("M16", "Sources/wxkeep/Verifier.swift",
     "            return status == SIGKILL ? .environmentBlocked : .workerCrashed(signal: status)",
     "            return .workerCrashed(signal: status)",
     "SIGKILL 误判为 crash（㊶ 缺陷复活）"),
    ("M17", "Sources/wxkeep/SafeWrite.swift",
     "        try data.write(to: url, options: .atomic)",
     "        try data.write(to: url)",
     "原子覆写降级为直写（撕裂窗口复活）"),
    ("M18", "Sources/wxkeep/Engine.swift",
     "        return pattern.concretePrefix(asm.count)?.hexUppercase",
     "        return first",
     "通配条目 restore 原样透传 spec（Data(hex:) 解析失败）"),
    ("M19", "Sources/wxkeep/Doctor.swift",
     '            return resolvable.contains(.unknown) ? "unknown" : "mixed"',
     '            return "mixed"',
     "doctor 聚合把 unknown 误报成 mixed（㊳ 缺陷复活）"),
    ("M20", "Sources/wxkeep/Engine.swift",
     '        let variantID = variant == "keeptip" ? "revoke-keeptip" : "revoke"\n        let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"',
     '        let variantID = "revoke"\n        let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"',
     "变体切换还原错目标（keeptip 切换不再还原 silent）"),
]


def run_tests(scratch):
    # 每变异独立 scratch path 全新构建：本机 Swift Build 的文件变更检测
    # 会楔死（改文件/rename/未来 mtime 全都不触发重编，跑旧二进制——
    # 2026-10-20 实锤「0.95s Build complete + 变异在盘 + 测试全过」），
    # 共享构建目录的变异结果两个方向都不可信（假存活=跑回退态旧件、
    # 假杀死=跑上一变异旧件）。全新 scratch 是唯一可靠隔离。
    cmd = TEST_CMD[:2] + ["--scratch-path", scratch] + TEST_CMD[2:]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=1800)
    out = r.stdout + r.stderr
    plugin_wedge = "plugin for module 'TestingMacros' not found" in out
    return r.returncode, out, plugin_wedge


import time as _time

_mtime_clock = [int(_time.time())]


def apply(path, old, new):
    p = os.path.join(ROOT, path)
    s = open(p).read()
    if s.count(old) != 1:
        return False, f"anchor 计数 {s.count(old)} != 1"
    open(p, "w").write(s.replace(old, new))
    # 强制重编：apply/revert 快速循环可能落在同一 mtime 刻度，Swift Build
    # 按 mtime 判陈旧会跳过重编 → 跑旧二进制 → 假存活（2026-10-20 两轮
    # 实锤：同批变异单独跑全杀、连跑全「存活」）。mtime 单调前移。
    _mtime_clock[0] += 10
    os.utime(p, (_mtime_clock[0], _mtime_clock[0]))
    return True, ""


def main():
    wanted = set(sys.argv[1:])
    results = []
    for mid, path, old, new, desc in MUTATIONS:
        if wanted and mid not in wanted:
            continue
        ok, err = apply(path, old, new)
        if not ok:
            print(f"[{mid}] 跳过：anchor 问题（{err}）")
            results.append((mid, desc, "SKIP"))
            continue
        scratch = f"/tmp/mut-scratch-{mid}"
        subprocess.run(["rm", "-rf", scratch], capture_output=True)
        try:
            for attempt in range(5):
                rc, out, wedge = run_tests(scratch)
                if not wedge:
                    break
                subprocess.run(["bash", "-c",
                                "find ${TMPDIR:-/tmp} -maxdepth 1 -name 'org.swift*' "
                                "-exec rm -rf {} + 2>/dev/null; "
                                "rm -rf ~/Library/Caches/org.swift.swiftpm"],
                               capture_output=True)
                import time
                time.sleep(3)
            killed = rc != 0
            results.append((mid, desc, "KILLED" if killed else "SURVIVED"))
            print(f"[{mid}] {'杀死 ✓' if killed else '存活 ✗'} — {desc}")
        finally:
            apply(path, new, old)   # 还原（anchor 唯一性对反向同样成立）
            subprocess.run(["rm", "-rf", scratch], capture_output=True)
    total = [r for r in results if r[2] != "SKIP"]
    killed = [r for r in total if r[2] == "KILLED"]
    rate = len(killed) / len(total) * 100 if total else 0
    print(f"\n杀灭率：{len(killed)}/{len(total)} = {rate:.0f}%"
          f"（验收线 ≥90%）")
    for mid, desc, st in results:
        if st != "KILLED":
            print(f"  存活/跳过：{mid} {desc}")


if __name__ == "__main__":
    main()
