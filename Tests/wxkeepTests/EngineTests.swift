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
