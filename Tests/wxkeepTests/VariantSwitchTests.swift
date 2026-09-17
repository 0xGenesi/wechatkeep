import Foundation
import Testing
@testable import wxkeep

/// 变体切换语义：silent ↔ keeptip 切换时，先还原另一变体的写入再应用本变体，
/// 最终每架构的补丁点处于本变体的目标状态（合成 fat fixture 端到端）。
struct VariantSwitchTests {
    private func makeAppAndCatalog() throws -> (app: URL, config: Config) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-vswitch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let (image, _, _) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),   // silent 位：原始
                (0x140, [0x40, 0x10, 0x00, 0x34]),                            // cbz：原始
                (0x180, [0x60, 0xE6, 0x00, 0xF9]),                            // str x0：原始
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),  // silent 位：原始
                (0x140, [0x48, 0x89, 0xC2]),                                       // keeptip 长度传参：原始
            ]))
        let dylib = dir.appendingPathComponent("Contents/Resources/wechat.dylib")
        try FileManager.default.createDirectory(at: dylib.deletingLastPathComponent(), withIntermediateDirectories: true)
        try image.write(to: dylib)
        let app = dir
        let json = """
        [{"version":"999999","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
            {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"}
          ]},
          {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":["00008052C0035FD6","F44FBEA9FD7B01A9"],"asm":"F44FBEA9FD7B01A9"},
            {"arch":"arm64","addr":"140","expected":["40100034","82000014"],"asm":"40100034"},
            {"arch":"arm64","addr":"180","expected":["60E600F9"],"asm":"7FE600F9"},
            {"arch":"x86_64","addr":"140","expected":["4889C2"],"asm":"31D290"}
          ]}
        ]}]
        """
        return (app, try Config(data: Data(json.utf8), origin: "inline"))
    }

    @Test func silentThenKeeptipThenSilentRoundTrip() throws {
        let (app, config) = try makeAppAndCatalog()
        let dylib = app.appendingPathComponent("Contents/Resources/wechat.dylib")
        let data = { try Data(contentsOf: dylib) }

        // silent：arm64 写 00008052…，x64 写 31C0C3…
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "silent",
                             dryRun: false, allowUnverified: false, only: nil)
        #expect(try data().range(of: Data([0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6])) != nil)
        #expect(try data().range(of: Data([0x31, 0xC0, 0xC3])) != nil)

        // 切 keeptip：还原 silent 的两个点 + x64 keeptip 清零生效
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip",
                             dryRun: false, allowUnverified: false, only: nil)
        #expect(try data().range(of: Data([0xF4, 0x4F, 0xBE, 0xA9])) != nil, "silent 位已还原")
        #expect(try data().range(of: Data([0x7F, 0xE6, 0x00, 0xF9])) != nil, "arm64 keeptip str xzr")
        #expect(try data().range(of: Data([0x31, 0xD2, 0x90])) != nil, "x64 keeptip 清零")

        // 切回 silent：还原 keeptip 各点 + x64 静默位重新写入
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "silent",
                             dryRun: false, allowUnverified: false, only: nil)
        #expect(try data().range(of: Data([0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6])) != nil)
        #expect(try data().range(of: Data([0x31, 0xC0, 0xC3])) != nil)
        #expect(try data().range(of: Data([0x7F, 0xE6, 0x00, 0xF9])) == nil, "keeptip x64 点被还原")
    }
}

/// 今日实测回归：v2–v7 实验变体（revoke-keeptip2）已废弃——
/// ① 不能再应用；② 盘上有它的遗留字节时，应用其他变体必须拒绝并指引 restore。
struct DeprecatedVariantTests {
    private func makeAppAndCatalog(leaveLeftover: Bool) throws -> (app: URL, config: Config) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-deprecated-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let (image, arm64Offset, _) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),   // keeptip 位：原始
                (0x140, [0x60, 0xE6, 0x00, 0xF9]),                            // keeptip2 位：原始（或预置遗留）
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: []))
        let dylib = dir.appendingPathComponent("Contents/Resources/wechat.dylib")
        try FileManager.default.createDirectory(at: dylib.deletingLastPathComponent(), withIntermediateDirectories: true)
        try image.write(to: dylib)
        if leaveLeftover {
            // 预置 keeptip2 遗留字节（模拟跑过实验变体的机器）
            let leftover = Data([0x82, 0x00, 0x00, 0x14])
            var data = try Data(contentsOf: dylib)
            // VA 0x140 在 arm64 切片内：文件偏移 = arm64Offset + 0x140（vmaddr=0）
            data.replaceSubrange((arm64Offset + 0x140)..<(arm64Offset + 0x144), with: leftover)
            try data.write(to: dylib)
        }
        let app = dir
        let json = """
        [{"version":"999999","targets":[
          {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"100","expected":["00008052C0035FD6","F44FBEA9FD7B01A9"],"asm":"F44FBEA9FD7B01A9"}
          ]},
          {"identifier":"revoke-keeptip2","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"arm64","addr":"140","expected":["60E600F9"],"asm":"82000014"}
          ]}
        ]}]
        """
        return (app, try Config(data: Data(json.utf8), origin: "inline"))
    }

    @Test func keeptip2IsDeprecated() throws {
        let (app, config) = try makeAppAndCatalog(leaveLeftover: false)
        do {
            _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip2",
                                 dryRun: false, allowUnverified: false, only: nil)
            Issue.record("keeptip2 must be refused")
        } catch let e as Engine.EngineError {
            guard case .variantDeprecated = e else {
                Issue.record("wrong error: \(e)")
                return
            }
        }
    }

    @Test func foreignLeftoverRefusesThenRestoreCleanUnwinds() throws {
        let (app, config) = try makeAppAndCatalog(leaveLeftover: true)
        let dylib = app.appendingPathComponent("Contents/Resources/wechat.dylib")

        // 有遗留 → 应用 keeptip 被拒
        do {
            _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip",
                                 dryRun: false, allowUnverified: false, only: nil)
            Issue.record("foreign leftover must refuse keeptip")
        } catch let e as Engine.EngineError {
            guard case .foreignVariantPatched = e else {
                Issue.record("wrong error: \(e)")
                return
            }
        }

        // restore 清理遗留 → keeptip 可应用
        // restore 清理遗留 → keeptip 可应用
        _ = try Engine.restore(app: app, build: "999999", config: config, dryRun: false)
        _ = try Engine.patch(app: app, build: "999999", config: config, variant: "keeptip",
                             dryRun: false, allowUnverified: false, only: nil)
        let data = try Data(contentsOf: dylib)
        #expect(data.range(of: Data([0xF4, 0x4F, 0xBE, 0xA9])) != nil, "keeptip 位已写")
        #expect(data.range(of: Data([0x82, 0x00, 0x00, 0x14])) == nil, "遗留字节已被 restore 清理")
    }
}
