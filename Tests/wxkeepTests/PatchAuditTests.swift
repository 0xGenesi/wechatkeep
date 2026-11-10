import Foundation
import Testing
@testable import wxkeep

/// per-site 审计清单（125 轮 V5 深度轮）：Patcher auditSink 收集语义、
/// PatchAudit 生命周期、doctor 对账三面回归。
final class PatchAuditTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-audit-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    private func writeBinary(_ data: Data, name: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func makeRecord(sites: [PatchAudit.Site], app: String = "/fake/App.app") -> PatchAudit.Record {
        PatchAudit.Record(v: 1, build: "270351", variant: "silent", app: app,
                          completedAt: "2026-11-03T00:00:00Z", sites: sites)
    }

    // MARK: - Patcher auditSink 语义

    @Test func sinkCollectsBeforeAfterAndProvenance() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]),
            name: "audit-collect.dylib")
        var collected: [Patcher.SiteAudit] = []
        let outcome = try Patcher.patch(
            binary: binary,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3",
                                         expected: ["554889E553504889FB"])],
            identifier: "revoke",
            auditSink: { collected.append($0) })
        #expect(outcome == [.written])
        #expect(collected.count == 1, "written 位点恰好记账一次")
        let site = collected[0]
        #expect(site.va == 0x100)
        #expect(site.arch == .x86_64)
        #expect(site.identifier == "revoke")
        // before = 被替换的 asm 跨度实读（3B），after = asm
        #expect(site.before.hexUppercase == "554889")
        #expect(site.after.hexUppercase == "31C0C3")
    }

    @Test func dryRunAndAlreadyPatchedKeepLedgerEmpty() throws {
        // alreadyPatched：无写入无账目
        let patched = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x31, 0xC0, 0xC3, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]),
            name: "audit-idem.dylib")
        var collected: [Patcher.SiteAudit] = []
        _ = try Patcher.patch(
            binary: patched,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3",
                                         expected: ["554889E553504889FB", "31C0C3"])],
            identifier: "revoke",
            auditSink: { collected.append($0) })
        #expect(collected.isEmpty, "alreadyPatched 不记账")

        // dry-run：规划期读到、写前返回——账目不得交付
        let pristine = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]),
            name: "audit-dry.dylib")
        _ = try Patcher.patch(
            binary: pristine,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3",
                                         expected: ["554889E553504889FB"])],
            identifier: "revoke",
            dryRun: true,
            auditSink: { collected.append($0) })
        #expect(collected.isEmpty, "dry-run 不交付账目（未落盘不得入账）")
        #expect(try Data(contentsOf: pristine).subdata(in: 0x100..<0x104)
                == Data([0x55, 0x48, 0x89, 0xE5]), "dry-run 不写字节")
    }

    @Test func preWriteFailureDeliversNoLedger() throws {
        // expected 失配 = Phase-1 写前抛错：规划到的位点不得入账
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0xDE, 0xAD, 0xBE, 0xEF, 0x53, 0x50, 0x48, 0x89]),
            ]),
            name: "audit-mismatch.dylib")
        var collected: [Patcher.SiteAudit] = []
        #expect(throws: (any Error).self) {
            _ = try Patcher.patch(
                binary: binary,
                entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3",
                                             expected: ["554889E553504889FB"])],
                identifier: "revoke",
                auditSink: { collected.append($0) })
        }
        #expect(collected.isEmpty, "写前失败不交付账目")
    }

    // MARK: - PatchAudit 生命周期

    @Test func lifecycleWritePendingClearRoundTrips() throws {
        let userData = workDir.appendingPathComponent("userData", isDirectory: true)
        try FileManager.default.createDirectory(at: userData, withIntermediateDirectories: true)
        let record = makeRecord(sites: [PatchAudit.Site(
            binary: "Contents/Resources/wechat.dylib", arch: "arm64",
            identifier: "revoke", va: "4e795a4",
            before: "40100034", after: "82000014", source: "recipe:revoke_arm64_gen3")])

        #expect(PatchAudit.pending(userData: userData).exists == false, "初始无账")
        try PatchAudit.write(record: record, userData: userData)
        let pending = PatchAudit.pending(userData: userData)
        #expect(pending.exists && pending.record == record, "写入后可读回且逐字段恒等")
        PatchAudit.clear(userData: userData)
        #expect(PatchAudit.pending(userData: userData).exists == false, "clear 幂等收口")

        // 坏 JSON：在场即证据（exists=true, record=nil）——检测不能被坏文件吞掉
        try Data("not json".utf8).write(to: PatchAudit.url(userData: userData))
        let corrupt = PatchAudit.pending(userData: userData)
        #expect(corrupt.exists && corrupt.record == nil)
        PatchAudit.clear(userData: userData)
    }

    // MARK: - doctor 对账

    /// 最小 app 目录 + wechat.dylib；位点 va 与 fixture 布局（VA==fileoff）。
    private func makeApp(patchedBytes: [UInt8]) throws -> URL {
        let app = workDir.appendingPathComponent("FakeApp.app", isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        try MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: [(0x100, patchedBytes)])
            .write(to: resources.appendingPathComponent("wechat.dylib"))
        return app
    }

    @Test func doctorReconciliationFreshStaleAndForeignArch() throws {
        let site = PatchAudit.Site(
            binary: "Contents/Resources/wechat.dylib", arch: "arm64",
            identifier: "revoke", va: "100",
            before: "F44FBEA9", after: "C0035FD6", source: nil)

        // fresh：盘上 == after
        let freshApp = try makeApp(patchedBytes: [0xC0, 0x03, 0x5F, 0xD6])
        let fresh = Doctor.auditSiteStates(record: makeRecord(sites: [site]), app: freshApp)
        #expect(fresh.fresh && fresh.checked == 1)

        // stale：外改一位字节 → 对账必失配（负控：检测器能报错）
        let staleApp = try makeApp(patchedBytes: [0xC1, 0x03, 0x5F, 0xD6])
        let stale = Doctor.auditSiteStates(record: makeRecord(sites: [site]), app: staleApp)
        #expect(!stale.fresh && stale.mismatches.count == 1)

        // 坏 arch 字串：保守计失配，不假绿
        let badArch = PatchAudit.Site(
            binary: "Contents/Resources/wechat.dylib", arch: "arm64e",
            identifier: "revoke", va: "100", before: "F44FBEA9", after: "C0035FD6", source: nil)
        let foreign = Doctor.auditSiteStates(record: makeRecord(sites: [badArch]), app: freshApp)
        #expect(!foreign.fresh && foreign.mismatches.first?.state == "bad-arch")

        // binary 缺失：inspect 失败 = 失配（对账面不假绿）
        let recordMissingBinary = makeRecord(sites: [PatchAudit.Site(
            binary: "Contents/MacOS/WeChat", arch: "arm64",
            identifier: "revoke", va: "100", before: "F44FBEA9", after: "C0035FD6", source: nil)])
        let missing = Doctor.auditSiteStates(record: recordMissingBinary, app: freshApp)
        #expect(!missing.fresh)
    }

    @Test func auditRecordSchemaIsStableAndCodable() throws {
        // 三件套离线复算（tools/audit_patch.py）依赖字段名稳定——锁 schema
        let record = makeRecord(sites: [])
        let json = try JSONEncoder().encode(record)
        let text = String(decoding: json, as: UTF8.self)
        for key in ["\"v\":1", "\"build\":\"270351\"", "\"app\":", "\"sites\":[]",
                    "\"completedAt\"", "\"variant\":\"silent\""] {
            #expect(text.contains(key), "schema 键 \(key) 在编码输出在场")
        }
        #expect(try JSONDecoder().decode(PatchAudit.Record.self, from: json) == record)
    }
}

// MARK: - 账本合并（126 轮 B6：--only/部分重跑的覆盖语义收口）

extension PatchAuditTests {
    private func anySite(_ va: String, arch: String = "arm64",
                         binary: String = "Contents/Resources/wechat.dylib",
                         id: String = "revoke") -> PatchAudit.Site {
        PatchAudit.Site(binary: binary, arch: arch, identifier: id, va: va,
                        before: "00112233", after: "AABBCCDD", source: nil)
    }

    /// 先 --only update（账=update@140）→ 再全量（revoke@100 新写、update
    /// alreadyPatched 不入账）——合并后两键俱在。覆盖式写账曾把 update 挤出
    /// 账本 = 离线复算对合法机器报位点外写入（诬告为篡改）。
    @Test func mergedRecordKeepsSitesFromPartialReruns() {
        let prev = makeRecord(sites: [anySite("140", id: "update")])
        let merged = PatchAudit.mergedRecord(
            previous: prev, build: "270351", variant: "silent", app: "/fake/App.app",
            written: [anySite("100")], restored: [])
        #expect(merged.sites.map(\.va).sorted() == ["100", "140"])
        #expect(merged.sites.first { $0.va == "100" }?.after == "AABBCCDD",
                "新写键内容以本次为准")
    }

    /// 变体切换：undo 还原的键出账（bytes==pristine 留键 = doctor 假 stale）；
    /// 归一化共享位点「还原后重写」经先删后增存活。
    @Test func mergedRecordRemovesRestoredKeysOnVariantSwitch() {
        let prev = makeRecord(sites: [anySite("100"), anySite("140", arch: "x86_64")])
        let switched = PatchAudit.mergedRecord(
            previous: prev, build: "270351", variant: "keeptip", app: "/fake/App.app",
            written: [anySite("180", id: "revoke-keeptip")],
            restored: [anySite("100"), anySite("140", arch: "x86_64")])
        #expect(switched.sites.map(\.va) == ["180"], "undo 键全部出账")
        let shared = PatchAudit.mergedRecord(
            previous: prev, build: "270351", variant: "keeptip", app: "/fake/App.app",
            written: [anySite("100", id: "revoke-keeptip")],
            restored: [anySite("100")])
        #expect(shared.sites.map(\.va).sorted() == ["100", "140"],
                "共享位点还原后重写 → 先删后增 → 存活且内容为新写")
    }

    /// 旧账 app/build 漂移即弃（微信自更新后旧键字节已消失 = 留键假 stale；
    /// 跨 app 与 journal 同哲学：新事务意图即当前事实）。
    @Test func mergedRecordDropsPreviousOnBuildOrAppDrift() {
        let prev = makeRecord(sites: [anySite("100")])
        #expect(PatchAudit.mergedRecord(
            previous: prev, build: "999999", variant: nil, app: "/fake/App.app",
            written: [anySite("200")], restored: []).sites.map(\.va) == ["200"],
            "build 漂移 → 旧账弃")
        #expect(PatchAudit.mergedRecord(
            previous: prev, build: "270351", variant: nil, app: "/other/App.app",
            written: [], restored: []).sites.isEmpty,
            "app 漂移 → 旧账弃")
    }
}

// MARK: - 136 轮评审：restore 收口的台账 app 守卫

extension PatchAuditTests {
    // MARK: - 136 轮评审：restore 收口的台账 app 守卫

    /// P3 回归锁：restore 的台账清理必须带 app 守卫——单槽台账可能记的是
    /// 另一 app（patch 本体 → clone → restore 克隆体）；无守卫的 clear 会
    /// 抹掉本体账目（本体仍 patched 但 doctor 对账能力丢失）。patch 侧同名
    /// 清理自始有守卫。三分支：他 app → 保留；本 app → 收口；无账 → 无操作。
    @Test func restoreLedgerClearIsAppGuarded() throws {
        let userData = workDir.appendingPathComponent("userData-guard", isDirectory: true)
        try FileManager.default.createDirectory(at: userData, withIntermediateDirectories: true)
        let site = PatchAudit.Site(
            binary: "Contents/Resources/wechat.dylib", arch: "arm64",
            identifier: "revoke", va: "4e795a4",
            before: "40100034", after: "82000014", source: "recipe:revoke_arm64_gen3")
        let record = makeRecord(sites: [site], app: "/Applications/WeChat.app")

        // 他 app 的账：restore 克隆体不得清本体的账
        try PatchAudit.write(record: record, userData: userData)
        Wxkeep.closeAuditLedgerIfOwn(app: "/Applications/WeChat wxkeep 1.app", userData: userData)
        #expect(PatchAudit.pending(userData: userData).record == record,
                "外 app 台账必须保留")

        // 本 app 的账：restore 收口清理
        Wxkeep.closeAuditLedgerIfOwn(app: "/Applications/WeChat.app", userData: userData)
        #expect(PatchAudit.pending(userData: userData).exists == false,
                "本 app 台账随 pristine 收口")

        // 无账：幂等无操作
        Wxkeep.closeAuditLedgerIfOwn(app: "/Applications/WeChat.app", userData: userData)
    }
}
