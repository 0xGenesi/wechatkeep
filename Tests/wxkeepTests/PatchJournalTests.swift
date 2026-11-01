import Foundation
import Testing
@testable import wxkeep

/// 崩溃一致性 journal（WAL）：事务生命周期 + doctor 判读矩阵。
/// 对应威胁：多点写入中途 SIGKILL/断电（catch 型恢复重签覆盖不到的路径）
/// 留下「半套字节 + 旧签名」，此前 doctor 只能报 mixed、无法区分事故。
final class PatchJournalTests {
    let userData: URL

    init() throws {
        userData = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-journal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: userData, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: userData) }

    // MARK: 生命周期

    @Test func beginPendingCompleteLifecycle() throws {
        #expect(PatchJournal.pending(userData: userData).exists == false,
                "干净目录不得有无中生有的 journal")
        try PatchJournal.begin(kind: .patch, build: "270100", variant: "keeptip",
                               app: "/Applications/WeChat.app", userData: userData)
        let pending = PatchJournal.pending(userData: userData)
        #expect(pending.exists)
        #expect(pending.record?.kind == .patch)
        #expect(pending.record?.build == "270100")
        #expect(pending.record?.variant == "keeptip")
        #expect(pending.record?.app == "/Applications/WeChat.app")
        #expect(pending.record?.v == 1)
        // 原子性副产品：begin 覆写旧事务（不留第二份文件）
        try PatchJournal.begin(kind: .restore, build: "270100", variant: nil,
                               app: "/Applications/WeChat.app", userData: userData)
        let pending2 = PatchJournal.pending(userData: userData)
        #expect(pending2.record?.kind == .restore)
        #expect(pending2.record?.variant == nil)
        PatchJournal.complete(userData: userData)
        #expect(PatchJournal.pending(userData: userData).exists == false)
        PatchJournal.complete(userData: userData)   // 幂等：重复收口不抛
        #expect(!FileManager.default.fileExists(atPath: PatchJournal.url(userData: userData).path))
    }

    @Test func markResignedLifecycle() throws {
        // 110 轮洗白链防线：resigned 位的三态生命周期——begin 后 nil（未确认，
        // doctor 按陈旧签名嫌疑处理）；markResigned 后 true（良性收口分支）；
        // journal 不在时静默无操作。
        try PatchJournal.begin(kind: .patch, build: "270100", variant: nil,
                               app: "/Applications/WeChat.app", userData: userData)
        #expect(PatchJournal.pending(userData: userData).record?.resigned == nil)
        PatchJournal.markResigned(userData: userData)
        #expect(PatchJournal.pending(userData: userData).record?.resigned == true)
        PatchJournal.markResigned(userData: userData)   // 幂等
        #expect(PatchJournal.pending(userData: userData).record?.resigned == true)
        PatchJournal.complete(userData: userData)
        PatchJournal.markResigned(userData: userData)   // journal 不在：静默
        #expect(PatchJournal.pending(userData: userData).exists == false)
    }

    @Test func pendingToleratesUnreadableJournal() throws {
        try Data("[not json".utf8)
            .write(to: PatchJournal.url(userData: userData))
        let pending = PatchJournal.pending(userData: userData)
        #expect(pending.exists, "journal 在场就是证据——坏 JSON 不能把检测静默吞掉")
        #expect(pending.record == nil)
        // doctor 判读：不可读 journal 走保守恢复路径
        let guidance = Doctor.interruptedTxGuidance(
            journalExists: pending.exists, record: pending.record,
            gatingStates: ["revoke": "patched"], sudoRequired: false,
            appPath: "/Applications/WeChat.app")
        #expect(guidance.verdictLines.first?.contains("UNREADABLE") == true)
        #expect(guidance.nextCommand == "wxkeep restore")
    }

    // MARK: doctor 判读矩阵（journal 态 × 字节态合读）

    private let patched = ["revoke": "patched", "update": "patched"]
    private let pristine = ["revoke": "pristine", "revoke-keeptip": "pristine", "update": "pristine"]
    private let mixed = ["revoke": "mixed", "update": "patched"]
    private let unknown = ["revoke": "unknown", "update": "patched"]
    private let appPath = "/Applications/WeChat.app"

    private func record(_ kind: PatchJournal.Kind, app: String = "/Applications/WeChat.app") -> PatchJournal.Record {
        .init(v: 1, kind: kind, build: "270100", variant: kind == .patch ? "silent" : nil,
              app: app, startedAt: "2026-10-23T00:00:00Z", pid: 1)
    }

    @Test func guidanceNoJournalIsSilent() {
        let g = Doctor.interruptedTxGuidance(
            journalExists: false, record: nil, gatingStates: mixed, sudoRequired: true,
            appPath: appPath)
        #expect(g.verdictLines.isEmpty)
        #expect(g.journalSummary == nil)
        #expect(g.nextCommand == nil)
    }

    @Test func guidanceForeignAppJournalDoesNotHijackThisApp() {
        // clone/多 bundle 机器：别的 app 的中断事务不得劫持本 app 的 nextCommand
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch, app: "/tmp/clone/WeChat.app"),
            gatingStates: mixed, sudoRequired: true, appPath: appPath)
        #expect(g.verdictLines.first?.contains("DIFFERENT app bundle") == true)
        #expect(g.nextCommand == nil)
    }

    @Test func guidancePatchFullyAppliedSuggestsIdempotentPatch() {
        // 重签已确认（110 轮洗白链修复后的良性分支）：死于收口前。111 轮修：
        // 处方从 `wxkeep verify` 改为幂等 patch——verify 不清 journal，照做后
        // doctor 每次仍给同一处方，PENDING 永不收敛；verify 降为人读确认步骤。
        var r = record(.patch)
        r.resigned = true
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: r, gatingStates: patched, sudoRequired: false,
            appPath: appPath)
        #expect(g.verdictLines.first?.contains("fully applied") == true)
        #expect(g.verdictLines.first?.contains("verify") == true,
                "verify 作为人读确认步骤仍在 verdict 行内")
        #expect(g.nextCommand == "wxkeep patch")
        #expect(g.journalSummary?.hasPrefix("patch@") == true)
    }

    @Test func guidancePatchFullyAppliedWithoutResignLeadsRestoreFirst() {
        // 110 轮修的判读契约：字节完好但重签从未确认（v1 旧记录 nil 同判）——
        // 「重跑 patch 即收口」的旧处方会把陈旧签名洗白成 protected（全部
        // alreadyPatched → 跳过重签）。指引 = 先 restore 归一（同治签名）。
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch), gatingStates: patched, sudoRequired: false,
            appPath: appPath)
        #expect(g.verdictLines.first?.contains("RE-SIGNING was never confirmed") == true)
        #expect(g.nextCommand == "wxkeep restore")
        // sudo 语境同款
        let gs = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch), gatingStates: patched, sudoRequired: true,
            appPath: appPath)
        #expect(gs.nextCommand == "sudo wxkeep restore")
    }

    @Test func guidancePatchPristineSuggestsRerunNotRestore() {
        // 写前失败（权限/TCC/错版）是最高频的 journal 残留来源——字节全
        // pristine 时指引应指向「修因重跑」而非吓人的「中断恢复」。
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch), gatingStates: pristine, sudoRequired: false,
            appPath: appPath)
        #expect(g.verdictLines.first?.contains("pristine") == true)
        #expect(g.nextCommand == "wxkeep patch")
    }

    @Test func guidanceInterruptedPatchDemandsRestoreFirst() {
        for states in [mixed, unknown] {
            let g = Doctor.interruptedTxGuidance(
                journalExists: true, record: record(.patch), gatingStates: states, sudoRequired: true,
                appPath: appPath)
            #expect(g.verdictLines.first?.contains("INTERRUPTED PATCH") == true)
            #expect(g.nextCommand == "sudo wxkeep restore")
        }
    }

    @Test func guidanceRestoreJournalAlwaysConvergesViaRestore() {
        // restore 幂等：无论字节态，重跑 restore 都是收敛动作（也收口 journal）
        for states in [patched, pristine, mixed] {
            let g = Doctor.interruptedTxGuidance(
                journalExists: true, record: record(.restore), gatingStates: states, sudoRequired: false,
            appPath: appPath)
            #expect(g.nextCommand == "wxkeep restore")
            #expect(g.journalSummary?.hasPrefix("restore@") == true)
        }
    }

    @Test func guidanceSudoPrefixFollowsWritability() {
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch), gatingStates: mixed, sudoRequired: false,
            appPath: appPath)
        #expect(g.nextCommand == "wxkeep restore")
    }

    /// runtime 事务（新 kind）：组件一致 → 幂等 install 收口；LC 在而 dylib
    /// 缺（必崩混合态）→ 指向 remove 清理而非再 install。
    @Test func guidanceRuntimeInstallByComponentConsistency() {
        let g1 = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.runtimeInstall), gatingStates: pristine,
            sudoRequired: false, appPath: appPath,
            runtimeInjected: true, runtimeDylibExists: true)
        #expect(g1.nextCommand == "wxkeep runtime install")
        #expect(g1.verdictLines.first?.contains("consistent") == true)

        let g2 = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.runtimeInstall), gatingStates: pristine,
            sudoRequired: false, appPath: appPath,
            runtimeInjected: true, runtimeDylibExists: false)
        #expect(g2.nextCommand == "wxkeep runtime remove",
                "LC 在而 dylib 缺 = 启动必崩混合态，必须先 remove 清干净")
        #expect(g2.verdictLines.first?.contains("mixed state") == true)
    }

    @Test func guidanceRuntimeRemoveAlwaysConvergesViaRemove() {
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.runtimeRemove), gatingStates: pristine,
            sudoRequired: false, appPath: appPath)
        #expect(g.nextCommand == "wxkeep runtime remove")
        #expect(g.journalSummary?.hasPrefix("runtimeRemove@") == true)
    }
}
