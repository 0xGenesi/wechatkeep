#!/usr/bin/env python3
"""
mutation_test.py — L4 变异测试（ROADMAP 72·L4①）。

对安全关键路径注入单行变异（翻转条件/删校验/改常量），逐个跑全量测试
套件：任何失败/崩溃 = 变异被杀灭；全绿 = 存活（需逐条给出「可接受暴露」
或补测试）。还原用精确 old→new 字符串替换（出现次数必须恰为 1）。

用法: python3 tools/mutation_test.py [index ...]   # 无参 = 全部

护栏（125 轮 V5 深度轮）：in-place 变异最大的风险是「进程被 SIGKILL → 变异
态泄漏进工作树 → 下次构建/提交吃到变异源码」（2026-11-03 实证：M23 变异态
在树上存活到脚本 finally 才还原，期间任何 swift build 都会读到它）。三重门：
  1. sentinel（var/.mutation-in-flight.json）在首个 apply 前落盘、finally
     移除——泄漏可在盘上被检见；
  2. 启动自愈：sentinel 残留 = 上次运行未走完 finally → 按记录反向还原、
     醒目告警、拒跑（结果不可信，需人工重启）；
  3. pre-commit 钩子（tools/hooks/pre-commit）+ CI canonical-anchor 步：
     sentinel 在场或任一锚点不在 canonical 态 → 拒提交/拒绿。
"""
import subprocess
import sys
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SENTINEL = os.path.join(ROOT, "var", ".mutation-in-flight.json")
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
    # M05/M12/M20 于 125 轮刷新锚点：123/124 轮代码演进使原锚点漂移 →
    # 变异器静默 SKIP（杀灭率分母悄悄缩水）。canonical-anchor 护栏
    #（tools/hooks/pre-commit + CI Guard 步）即此漂移的首个捕获。
    ("M05", "Sources/wxkeep/Config.swift",
     "if e.asm.isEmpty || Data(hex: e.asm) == nil {",
     "if e.asm.isEmpty || false {",
     "坏 hex asm 装载期不拒（与 M22 同锚异半：M22 剥空串门、本行剥 hex 门）"),
    ("M06", "Sources/wxkeep/ExpectedPattern.swift",
     "guard data.count >= byteCount else { return false }",
     "guard data.count + 8 >= byteCount else { return false }",
     "短数据放行（越界读风险）"),
    ("M07", "Sources/wxkeep/Engine.swift",
     'if set.contains("revoke") {',
     'if false {',
     "--only revoke 域别名失效"),
    # M08 于 126 轮三刷：restoreTargets 调用改显式 partialWrite: 标签后
    # 锚点随缩进迁移。可杀性同轮落地——Patcher 写故障注入缝（DEBUG，
    # URL 限定）+ Resigner 入场观测缝：undoMidWriteFailureTriggersRecoveryResign
    # 断言「undo 臂中途写失败 → 外层必须尝试恢复重签」（本行是外层
    # summary 在该失败路径的唯一标记源——restoreTargets 内层保守记账只落
    # 其局部 summary，throw 即弃）。
    ("M08", "Sources/wxkeep/Engine.swift",
     "                        partialWrite: { relative in\n                            summary.wroteAnything = true",
     "                        partialWrite: { relative in\n                            summary.wroteAnything = false",
     "变体切换还原写入不计入重签决策（undo 臂中断→恢复重签被跳过=必崩态）"),
    ("M09", "Sources/wxkeep/Engine.swift",
     'if target.identifier == "revoke-keeptip2" {\n                continue',
     'if false {\n                continue',
     "废弃变体 keeptip2 可被自动应用"),
    # M10 于 126 轮换锚：I/O 后校验抽 verifySizes 纯函数（ENOSPC 形截断
    # 不可注入——72 轮以来无稳定杀面，全量重基线实证存活），判定获得直测。
    ("M10", "Sources/wxkeep/Backup.swift",
     "guard sourceSize == backupSize, sourceSize >= 0 else {",
     "guard sourceSize >= 0 else {",
     "截断备份不拒绝"),
    ("M11", "Sources/wxkeep/Backup.swift",
     "        return exe == binary.lastPathComponent",
     "        return false",
     "主可执行识别失效（备份落 bundle 内=双杀缺陷复活）"),
    ("M12", "Sources/wxkeep/Resigner.swift",
     "            if plistsEqual(actual, intended) { return nil }",
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
    # M17 可接受暴露（126 轮全量重基线实证存活）：.atomic 的失效形态是
    # 「写中途进程被杀」——进程级故障，无文件系统级注入缝则撕裂写不可在
    # 测试进程内复现。纵深兜底：撕裂写在每个消费端都有检测（journal 不可
    # 解码→interrupted 判读；备份截断→M10 门；config 撕裂→装载失败干净
    # 拒绝；dylib 撕裂→expected 门/codesign 拒）。.atomic 是减害层，检测
    # 才是安全合同——按纵深防御登记暴露，计入分母。
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
     '            let variantID = variant == "keeptip" ? "revoke-keeptip" : "revoke"\n            let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"',
     '            let variantID = "revoke"\n            let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"',
     "变体切换还原错目标（keeptip 切换不再还原 silent）"),
    # —— 123 轮新门（SOP：新增安全防线补变异行）——
    ("M21", "Sources/wxkeep/WxkeepCLI.swift",
     "        if error is Engine.PartialWriteFailure { return false }",
     "        if error is Engine.PartialWriteFailure { return true }",
     "journal 误清（部分写入后失败被当写前收口——必崩态失去 interrupted 判读）"),
    ("M22", "Sources/wxkeep/Config.swift",
     "if e.asm.isEmpty || Data(hex: e.asm) == nil {",
     "if Data(hex: e.asm) == nil {",
     "空 asm 假成功（Data(hex:\"\")==空 Data 过门 → 条目恒 alreadyPatched）"),
    ("M23", "Sources/WxkeepRuntime/runtime.m",
     "            && (uintptr_t)obj_head >= g_image_base\n            && (uintptr_t)obj_head - g_image_base < 0x20000000ULL) {",
     "            && 1) {",
     "keyctor 模块成员门整体失效（镜像外头照样直调宿主——复用对象崩溃面；单侧变异会被另一侧下溢回环补位，须整门移除才代表真实失效形态）"),
    # —— 125 轮新面（V5 深度轮：审计账目/对账门）——
    # M24 于 125 续再刷新：交付改 enumerated 单行门（zip 耦合事故后——
    # sink nil 时 zip 会把写入一并清零，全量测试当场抓获）。
    ("M24", "Sources/wxkeep/Patcher.swift",
     "            if index < audits.count { auditSink?(audits[index]) }",
     "            if false { auditSink?(audits[index]) }",
     "审计账目丢弃（per-site 台账恒空——离线三件套复算与 doctor 对账失去数据源）"),
    ("M25", "Sources/wxkeep/Doctor.swift",
     "            let matches = procName.caseInsensitiveCompare(appName) == .orderedSame",
     "            let matches = procName.caseInsensitiveCompare(appName) != .orderedSame",
     ".ips 崩溃扫描身份匹配反转（Safari 报告算微信、微信被剔——外部判据面失真；"
     "杀例=DoctorTests 无 procPath 夹具，`|| procPath` 子clause 救不回）"),
    ("M26", "Sources/wxkeep/Doctor.swift",
     '               (term["namespace"] as? String)?.uppercased() == "CODESIGNING" {',
     '               (term["namespace"] as? String)?.uppercased() != "CODESIGNING" {',
     ".ips CODESIGNING 分类反转（签名击杀证据被隐/普通崩溃误计——外部判据面失真）"),
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
    if new in s:
        return False, f"变异形态已在盘（count={s.count(new)}）——文件恐处变异态"
    open(p, "w").write(s.replace(old, new))
    # 强制重编：apply/revert 快速循环可能落在同一 mtime 刻度，Swift Build
    # 按 mtime 判陈旧会跳过重编 → 跑旧二进制 → 假存活（2026-10-20 两轮
    # 实锤：同批变异单独跑全杀、连跑全「存活」）。mtime 单调前移。
    _mtime_clock[0] += 10
    os.utime(p, (_mtime_clock[0], _mtime_clock[0]))
    return True, ""


def write_sentinel(entries):
    """原子写（tempfile+replace）：SIGKILL 落在半写会留下坏 JSON，而自愈
    路径对坏 JSON 必须 fail-closed 而不是崩（双评审 P2）。"""
    os.makedirs(os.path.dirname(SENTINEL), exist_ok=True)
    tmp = SENTINEL + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"pid": os.getpid(), "entries": entries}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, SENTINEL)


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True   # 别的用户进程也算活


def heal_and_abort_if_leaked():
    """sentinel 残留三态（双评审 P1/P2）：
    ① 坏 JSON → fail-closed：保哨兵、指路 git diff、拒跑（不猜怎么修）；
    ② pid 仍活 → 另一实例运行中，拒跑（自愈会把活运行当泄漏还原=竞态）；
    ③ pid 已死 → 泄漏：按记录反向还原后拒跑（结果不可信需人工重启）。"""
    if not os.path.exists(SENTINEL):
        return
    try:
        rec = json.load(open(SENTINEL))
    except (json.JSONDecodeError, OSError) as ex:
        print(f"⚠️⚠️ 哨兵损坏（{ex}）——状态不可知，拒绝猜测。请人工核对："
              f"git status / git diff，按 MUTATIONS 锚点确认无变异态后删除 "
              f"{SENTINEL} 再重跑。")
        sys.exit(2)
    if _pid_alive(rec.get("pid", 0)):
        print(f"⚠️ 另一 mutation_test 实例（pid={rec.get('pid')}）运行中——"
              f"拒绝并发（自愈会把活运行误判为泄漏）。")
        sys.exit(2)
    print(f"⚠️⚠️ 检见泄漏的变异运行（pid={rec.get('pid')}）——上次未走完 finally，"
          f"工作树可能带变异源码。逐项反向还原：")
    healed = skipped = 0
    for mid, path, old, new in rec.get("entries", []):
        p = os.path.join(ROOT, path)
        try:
            s = open(p).read()
        except OSError:
            print(f"  [{mid}] ⚠️ {path} 不可读——人工核对")
            skipped += 1
            continue
        if new in s:
            open(p, "w").write(s.replace(new, old))
            print(f"  [{mid}] 已还原变异态（{path}）")
            healed += 1
        elif old in s:
            print(f"  [{mid}] 已是 canonical 态（{path}）")
        else:
            print(f"  [{mid}] ⚠️ 锚点双向均不在盘——人工核对 {path}")
            skipped += 1
    os.remove(SENTINEL)
    print(f"自愈完成（还原 {healed}，人工待核 {skipped}）。本次拒跑——上次结果"
          f"不可信；确认 `git diff` 干净后重跑。")
    sys.exit(2)


def main():
    heal_and_abort_if_leaked()
    wanted = set(sys.argv[1:])
    results = []
    sentinel_live = []   # (mid, path, old, new) 已 apply 的活跃变异
    for mid, path, old, new, desc in MUTATIONS:
        if wanted and mid not in wanted:
            continue
        # 哨兵先行（双评审 P2：apply→write 间被杀 = 变异在盘无哨兵，自愈
        # 失明）：预测记录含本条；apply 失败（SKIP）时回滚到前一状态。
        prev_live = list(sentinel_live)
        sentinel_live.append((mid, path, old, new))
        write_sentinel(sentinel_live)
        ok, err = apply(path, old, new)
        if not ok:
            print(f"[{mid}] 跳过：anchor 问题（{err}）")
            results.append((mid, desc, "SKIP"))
            sentinel_live = prev_live
            if sentinel_live:
                write_sentinel(sentinel_live)
            else:
                try:
                    os.remove(SENTINEL)
                except FileNotFoundError:
                    pass
            continue
        scratch = f"/tmp/mut-scratch-{mid}"
        subprocess.run(["rm", "-rf", scratch], capture_output=True)
        try:
            wedge = False
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
            if wedge:
                # 楔死 5 连：结果不可判（既非杀死也非存活）——如实计 WEDGE
                # （双评审 P3：此前 rc!=0 的楔死被记成 KILLED=杀灭率虚高）。
                results.append((mid, desc, "WEDGE"))
                print(f"[{mid}] 楔死 5 连 — 环境故障，结果不判")
            else:
                killed = rc != 0
                results.append((mid, desc, "KILLED" if killed else "SURVIVED"))
                print(f"[{mid}] {'杀死 ✓' if killed else '存活 ✗'} — {desc}")
        finally:
            reverted, rerr = apply(path, new, old)   # 还原；失败=泄漏，必须响
            if reverted:
                sentinel_live = [e for e in sentinel_live if e[0] != mid]
                if sentinel_live:
                    write_sentinel(sentinel_live)
                else:
                    try:
                        os.remove(SENTINEL)
                    except FileNotFoundError:
                        pass
            else:
                # 还原失败（双评审 P1）：哨兵保留（泄漏可检）、醒目告警、
                # 立即中止（后续变异会在带变异树上跑=数据全失真）。
                print(f"⚠️⚠️ [{mid}] 还原失败（{rerr}）——变异态恐在盘！"
                      f"哨兵保留；人工 `git diff` 核对修复后重跑。")
            subprocess.run(["rm", "-rf", scratch], capture_output=True)
            if not reverted:
                sys.exit(3)
    total = [r for r in results if r[2] not in ("SKIP", "WEDGE")]
    killed = [r for r in total if r[2] == "KILLED"]
    rate = len(killed) / len(total) * 100 if total else 0
    print(f"\n杀灭率：{len(killed)}/{len(total)} = {rate:.0f}%"
          f"（验收线 ≥90%）")
    for mid, desc, st in results:
        if st != "KILLED":
            print(f"  存活/跳过：{mid} {desc}")


if __name__ == "__main__":
    main()
