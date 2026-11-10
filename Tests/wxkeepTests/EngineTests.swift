import Foundation
import Testing
@testable import wxkeep

/// Drives the real Engine.patch / Engine.restore against a synthetic .app
/// directory — the same "test the real thing, not a re-derivation" stance as
/// the predecessor project's RestoreTests.
final class EngineTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-engine-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: workDir.appendingPathComponent("Contents/Resources"), withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    private func makeApp() throws -> URL {
        // Fat wechat.dylib with both arch patch points pristine.
        let (image, _, _) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]))
        try image.write(to: workDir.appendingPathComponent("Contents/Resources/wechat.dylib"))
        return workDir
    }

    private let catalogJSON = """
    [{"version":"999999","targets":[
        {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
            {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3","source":"wxkeep-analysis"}
        ]}
    ]}]
    """

    @Test func patchThenRestoreRoundTrip() throws {
        let app = try makeApp()
        let config = try Config(data: Data(catalogJSON.utf8), origin: "inline")
        let resources = app.appendingPathComponent("Contents/Resources")

        let patchSummary = try Engine.patch(
            app: app, build: "999999", config: config, variant: "silent",
            dryRun: false, allowUnverified: false, only: nil)
        #expect(patchSummary.wroteAnything)
        let dylib = try Data(contentsOf: resources.appendingPathComponent("wechat.dylib"))
        #expect(dylib.range(of: Data([0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6])) != nil)
        #expect(dylib.range(of: Data([0x31, 0xC0, 0xC3])) != nil)
        // A timestamped backup was created.
        #expect(try FileManager.default.contentsOfDirectory(atPath: resources.path)
            .filter { $0.contains(".wxkeep-bak-") }.count == 1)

        // Patch again → idempotent: no writes, no new backup.
        let second = try Engine.patch(
            app: app, build: "999999", config: config, variant: "silent",
            dryRun: false, allowUnverified: false, only: nil)
        #expect(!second.wroteAnything)
        #expect(try FileManager.default.contentsOfDirectory(atPath: resources.path)
            .filter { $0.contains(".wxkeep-bak-") }.count == 1)

        // Restore returns both slices to pristine bytes.
        _ = try Engine.restore(app: app, build: "999999", config: config, dryRun: false)
        let restored = try Data(contentsOf: resources.appendingPathComponent("wechat.dylib"))
        #expect(restored.range(of: Data([0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9])) != nil)
        #expect(restored.range(of: Data([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB])) != nil)

        // Restore is idempotent too.
        let restoreAgain = try Engine.restore(app: app, build: "999999", config: config, dryRun: false)
        #expect(!restoreAgain.wroteAnything)
    }

    @Test func restoreRefusesWhenAnyTargetLacksExpected() throws {
        let app = try makeApp()
        let json = """
        [{"version":"999999","targets":[
            {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
                {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"}
            ]},
            {"identifier":"multiInstance","binary":"Contents/Resources/wechat.dylib","entries":[
                {"arch":"x86_64","addr":"100","asm":"909090909090"}
            ]}
        ]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        expectThrows(try Engine.restore(app: app, build: "999999", config: config, dryRun: false))
        // The restorable first target stays untouched (preflight guarantee).
        let dylib = try Data(contentsOf: app.appendingPathComponent("Contents/Resources/wechat.dylib"))
        #expect(dylib.range(of: Data([0xF4, 0x4F, 0xBE, 0xA9])) != nil)
    }

    @Test func variantSelection() throws {
        let json = """
        [{"version":"999999","targets":[
            {"identifier":"revoke","entries":[{"arch":"arm64","addr":"40","expected":"AABB","asm":"CC"}]},
            {"identifier":"revoke-keeptip","entries":[{"arch":"arm64","addr":"100","expected":"CCDD","asm":"EE"}]},
            {"identifier":"update","entries":[{"arch":"arm64","addr":"C0","expected":"EEFF","asm":"AB"}]}
        ]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        let entry = config.entry(build: "999999")!
        #expect(try Engine.targets(for: entry, variant: "silent").map(\.identifier) == ["revoke", "update"])
        #expect(try Engine.targets(for: entry, variant: "keeptip").map(\.identifier) == ["revoke-keeptip", "update"])
    }

    /// 269602 x64 实证过的回归：keeptip 在同一 VA 上的「归一化条目」
    /// （asm=原始字节, expected[0]=另一变体的补丁字节）。restore 曾把
    /// expected[0]（silent 字节）当原始字节写回——revoke 目标先还原、
    /// keeptip 目标再覆盖，静默补丁复活。
    @Test func restoreDoesNotReapplyOtherVariantOnNormalizerEntries() throws {
        let app = try makeApp()
        let json = """
        [{"version":"999999","targets":[
            {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
                {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"}
            ]},
            {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
                {"arch":"x86_64","addr":"100","expected":["31C0C3909090909090","554889E553504889FB"],"asm":"554889E553504889FB"}
            ]}
        ]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        let dylibURL = app.appendingPathComponent("Contents/Resources/wechat.dylib")
        let orig = Data([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB])
        let silent = Data([0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90])

        // silent → keeptip 切换：归一化条目保证 x64 回到原始
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "silent",
                             dryRun: false, allowUnverified: false, only: nil)
        #expect(try Data(contentsOf: dylibURL).range(of: silent) != nil)
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip",
                             dryRun: false, allowUnverified: false, only: nil)
        #expect(try Data(contentsOf: dylibURL).range(of: orig) != nil)

        // 回归核心：restore 之后必须仍是原始字节
        _ = try Engine.restore(app: app, build: "999999", config: config, dryRun: false)
        let restored = try Data(contentsOf: dylibURL)
        #expect(restored.range(of: orig) != nil)
        #expect(restored.range(of: silent) == nil)
    }
}

extension EngineTests {
    /// `--only` 子集解析：逗号后空白必须被修剪——标识符按精确比对，
    /// "--only revoke, update" 不修剪会静默落空成 variantUnavailable。
    @Test func parseOnlyListTrimsWhitespace() {
        #expect(Engine.parseOnlyList(nil) == nil)
        #expect(Engine.parseOnlyList("revoke") == ["revoke"])
        #expect(Engine.parseOnlyList("revoke,update") == ["revoke", "update"])
        #expect(Engine.parseOnlyList("revoke, update") == ["revoke", "update"])
        #expect(Engine.parseOnlyList(" update , revoke ") == ["update", "revoke"])
    }

    /// `--only` 的「revoke」= 当前变体的防撤回域：keeptip 用户照抄帮助示例
    /// `--only revoke,update` 时纯精确匹配会把 revoke-keeptip 静默滤掉
    /// （只剩 update 在打，防撤回没生效）。显式全名与 update-only 等
    /// 既有拼写行为不变；silent 下无行为变化。
    @Test func onlyListRevokeMeansVariantDomain() {
        #expect(Engine.effectiveOnlySet(nil, variant: "silent") == nil)
        #expect(Engine.effectiveOnlySet([], variant: "keeptip") == nil)
        // silent：revoke 本就是变体目标，无变化
        #expect(Engine.effectiveOnlySet(["revoke", "update"], variant: "silent")
                == ["revoke", "update"])
        // keeptip：revoke 别名展开到 revoke-keeptip
        #expect(Engine.effectiveOnlySet(["revoke", "update"], variant: "keeptip")
                == ["revoke", "update", "revoke-keeptip"])
        #expect(Engine.effectiveOnlySet(["revoke"], variant: "keeptip")
                == ["revoke", "revoke-keeptip"])
        // update-only（README 进阶工作流）不受影响；显式全名仍精确生效
        #expect(Engine.effectiveOnlySet(["update"], variant: "keeptip") == ["update"])
        #expect(Engine.effectiveOnlySet(["revoke-keeptip", "update"], variant: "keeptip")
                == ["revoke-keeptip", "update"])
    }

    /// 123 轮 P1-1 回归锁：部分写入后的失败（跨 binary「A 已写→B Phase-1
    /// PatchError」）不得按写前失败收口 journal——盘上是「字节已改+陈旧签名」
    /// 必崩态，journal 必须留给 doctor 的 interrupted 判读。包装类型优先于
    /// 底层错误类型判别；裸 PatchError（真写前）保持原语义。
    @Test func partialWriteFailureIsNotPreWrite() {
        let wrapped = Engine.PartialWriteFailure(
            underlying: Patcher.PatchError.overlappingEntries(
                first: 0, second: 1, va: 0x1000, identifier: "revoke"),
            summary: Engine.RunSummary())
        #expect(Wxkeep.isPreWriteFailure(wrapped) == false,
                "已写字节的失败必须保留 journal")
        #expect(Wxkeep.isPreWriteFailure(Patcher.PatchError.noArchMatched) == true,
                "裸 PatchError（写前）语义不变")
        #expect("\(wrapped)".contains("overlapping"), "description 透传底层错误（CLI 输出不变）")
    }
}

// MARK: - 126 轮遗留⑦：写故障注入缝下的 M08 杀例（十四轮来首次可杀）

extension EngineTests {
    /// 变体切换 undo 臂 Phase-2 中途写故障（注入缝 fail-at-0）：restoreTargets
    /// 内层的保守记账只落其**局部** summary（throw 即弃）——外层 summary 的
    /// 唯一标记源是 partialWrite 闭包（M08 锚点行）。外层 catch 必须①尝试
    /// 恢复重签（Resigner 观测缝；字节已改+旧签名 = 启动必崩态防线）②以
    /// PartialWriteFailure 重抛（journal 保留给 doctor interrupted 判读）。
    /// M08 变异（闭包体写 false）→ 恢复重签被跳过 → 观测缝不触发 → 红。
    @Test func undoMidWriteFailureTriggersRecoveryResign() throws {
        #if DEBUG
        let _seamGate = PatcherSeamGate()   // 跨套件互斥（136 轮）：与 CrashMatrix 的用缝用例串行
        let app = try makeApp()
        // 双变体目录：keeptip 目标只需非空（触发切换还原臂）即可
        let json = """
        [{"version":"999999","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
            {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3"}
          ]},
          {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"x86_64","addr":"100","expected":["31C0C3909090909090","554889E553504889FB"],"asm":"554889E553504889FB"}
          ]}
        ]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        // silent 先打满（两条写入，无注入）
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "silent",
                             dryRun: false, allowUnverified: false, only: nil)
        let dylib = app.appendingPathComponent("Contents/Resources/wechat.dylib")
        let silentBytes = Data([0x31, 0xC0, 0xC3])
        #expect(try Data(contentsOf: dylib).range(of: silentBytes) != nil, "silent 已打")

        struct InjectedWriteFailure: Error {}
        var resignAttempted = false
        Resigner.debugAttemptHook = { resignAttempted = true }
        // URL 限定（并行套件下进程全局缝会误伤并发用例）：只打本夹具 dylib
        let targetPath = dylib.path
        Patcher.debugWriteFailureAt = { url, idx in
            url.path == targetPath && idx == 0 ? InjectedWriteFailure() : nil
        }
        defer {
            Resigner.debugAttemptHook = nil
            Patcher.debugWriteFailureAt = nil
        }
        do {
            _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip",
                                 dryRun: false, allowUnverified: false, only: nil)
            Issue.record("undo 臂写故障必须以 PartialWriteFailure 抛出")
        } catch is Engine.PartialWriteFailure {
            // 预期路径（restoreTargets 内层包装 + 外层再包均属本类型族）
        } catch {
            Issue.record("错误类型不对（应 PartialWriteFailure，得 \(error)）")
        }
        #expect(resignAttempted,
                "undo 臂中途写失败 → 外层必须尝试恢复重签（M08：必崩态防线，字节已改+旧签名）")
        // fail-at(0) 注入语义自证：第一条还原写之前抛——盘面未动
        #expect(try Data(contentsOf: dylib).range(of: silentBytes) != nil,
                "fail-at(0) = 前 0 条已落盘（silent 字节原样）")
        #endif
    }

    /// 135 轮体检 P1 回归锁：Phase-2 中途写故障（fail-at(k)）时，
    /// **已落盘位点的审计账目必须经 PartialWriteFailure.summary 带出**。
    /// 此前 CLI 从 `summaryOrNil = try Engine.patch(…)` 取账——try 抛错时
    /// 赋值不发生，catch 里恒 nil，125/126 轮宣称的失败路径账目保全是
    /// 死代码（字节在盘、audit 无记录 → 离线复算假红）。本锁在 Engine
    /// 出错口断言「盘上 k 条 = summary.auditSites k 条」。
    @Test func partialWriteFailureCarriesAuditAccount() throws {
        #if DEBUG
        let _seamGate = PatcherSeamGate()   // 跨套件互斥（136 轮）：同上
        let app = try makeApp()
        let json = """
        [{"version":"999998","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
            {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3"}
          ]}
        ]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        let dylib = app.appendingPathComponent("Contents/Resources/wechat.dylib")
        let targetPath = dylib.path
        struct InjectedWriteFailure: Error {}
        // fail-at(1)：第 1 条（arm64）写入成功并交付账目，第 2 条抛错。
        Patcher.debugWriteFailureAt = { url, idx in
            url.path == targetPath && idx == 1 ? InjectedWriteFailure() : nil
        }
        defer { Patcher.debugWriteFailureAt = nil }
        do {
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: "silent",
                                 dryRun: false, allowUnverified: false, only: nil)
            Issue.record("fail-at(1) 必须抛 PartialWriteFailure")
        } catch let pwf as Engine.PartialWriteFailure {
            #expect(pwf.summary.auditSites.count == 1,
                    "盘上 1 条已写位点 = summary 账目恰 1 条（字节在盘 = 账目在场）")
            #expect(pwf.summary.auditSites.first?.arch == "arm64",
                    "账目对应第 1 条（成功落盘的 arm64 位点）")
        } catch {
            Issue.record("错误类型不对（应 PartialWriteFailure，得 \(error)）")
        }
        // fail-at(1) 注入语义自证：第 1 条（arm64 asm 前缀 00008052）确已落盘
        #expect(try Data(contentsOf: dylib).range(of: Data([0x00, 0x00, 0x80, 0x52])) != nil,
                "fail-at(1) = 前 1 条已落盘（arm64 asm 前缀在盘）")
        #endif
    }
}
