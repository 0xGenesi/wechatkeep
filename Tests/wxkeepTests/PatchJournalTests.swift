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

    @Test func guidancePatchFullyAppliedSuggestsVerify() {
        let g = Doctor.interruptedTxGuidance(
            journalExists: true, record: record(.patch), gatingStates: patched, sudoRequired: false,
            appPath: appPath)
        #expect(g.verdictLines.first?.contains("fully applied") == true)
        #expect(g.nextCommand == "wxkeep verify")
        #expect(g.journalSummary?.hasPrefix("patch@") == true)
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
}
