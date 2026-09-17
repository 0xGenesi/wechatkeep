
import Foundation
import Testing
@testable import wxkeep

/// 本地定位文件（config.local.json）设计：签名目录与用户派生数据分信任域。
/// 本地文件固定位于 userDataURL（brew Cellar 用户也可写）；测试用 override 注入。
@Suite(.serialized)
struct ConfigLocalTests {
    @Test func localEntriesMergeIntoSignedCatalog() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-local-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // 签名目录：269602 一个条目
        let signed = """
        [{"version":"269602","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"x86_64","addr":"100","expected":"AAAA","asm":"BBBB"}
          ]}
        ]}]
        """
        try signed.write(to: dir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)

        // 本地定位：新构建 270099 + 同构建新位点
        let local = """
        [{"version":"270099","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"x86_64","addr":"200","expected":"CCDD","asm":"EEFF"}
          ]}
        ]},
        {"version":"269602","targets":[
          {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"x86_64","addr":"100","expected":"AAAA","asm":"BBBB"},
            {"arch":"x86_64","addr":"300","expected":"AABB","asm":"CCDD"}
          ]}
        ]}]
        """
        try local.write(to: dir.appendingPathComponent("config.local.json"), atomically: true, encoding: .utf8)
        let config = try Config.load(
            explicit: dir.appendingPathComponent("config.json").path,
            localOverride: dir.appendingPathComponent("config.local.json"))
        #expect(config.entry(build: "270099") != nil, "本地新构建已并入")
        let v = config.entry(build: "269602")
        #expect(v?.targets.first?.entries.count == 2, "同构建位点去重合并（原1+新1）")
        #expect(config.entry(build: "270099")?.targets.first?.entries.count == 1)
    }

    @Test func malformedLocalFileIsRejected() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-local-bad-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "[]".write(to: dir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        try "{broken".write(to: dir.appendingPathComponent("config.local.json"), atomically: true, encoding: .utf8)
        #expect(throws: (any Error).self) {
            _ = try Config.load(
                explicit: dir.appendingPathComponent("config.json").path,
                localOverride: dir.appendingPathComponent("config.local.json"))
        }
    }
}
