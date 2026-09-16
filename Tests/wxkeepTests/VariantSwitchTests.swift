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
