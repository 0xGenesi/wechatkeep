import Foundation
import Testing
@testable import wxkeep

final class UpdateDataTests {
    init() { Config._userDataURLOverride = nil }
    deinit { Config._userDataURLOverride = nil }

    @Test func userDataDirWinsOverBundledConfig() throws {
        // cwd 无 config 的场景：用户数据目录优先于可执行文件旁的随包数据
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wxkeep-ud-\(UUID().uuidString)")
        let userDir = tmp.appendingPathComponent("user")
        let exeDir = tmp.appendingPathComponent("bundled/bin")
        try FileManager.default.createDirectory(at: userDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: exeDir, withIntermediateDirectories: true)
        try #" [{"version":"888888","targets":[]}] "#.write(to: userDir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        try #" [{"version":"777777","targets":[]}] "#.write(to: exeDir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        Config._userDataURLOverride = userDir
        let emptyCwd = tmp.appendingPathComponent("empty")
        try FileManager.default.createDirectory(at: emptyCwd, withIntermediateDirectories: true)
        let cfg = try Config.load(explicit: nil, cwd: emptyCwd.path)
        #expect(cfg.versions.first?.version == "888888")
        try? FileManager.default.removeItem(at: tmp)
    }
}
