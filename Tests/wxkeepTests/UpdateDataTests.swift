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

    /// update-data 的旧值口径：只数签名 config.json 本体（安装位优先），
    /// 不合并 config.local.json——否则旧值虚高、显示增量失真（2026-09-19 修正）
    @Test func catalogBuildCountCountsOnlySignedCatalog() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wxkeep-cnt-\(UUID().uuidString)")
        let userDir = tmp.appendingPathComponent("user")
        try FileManager.default.createDirectory(at: userDir, withIntermediateDirectories: true)
        // 安装位目录：2 构建 + 1 个 local 合并构建（不应计入）
        try #" [{"version":"270099","targets":[]},{"version":"270100","targets":[]}] "#
            .write(to: userDir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        try #" [{"version":"271000","targets":[]}] "#
            .write(to: userDir.appendingPathComponent("config.local.json"), atomically: true, encoding: .utf8)
        #expect(UpdateData.installedCatalogBuildCount(candidates: [
            userDir.appendingPathComponent("config.json"),
        ]) == 2)
        // 安装位无文件 → 回落候选（cwd），仍不合并 local
        let cwd = tmp.appendingPathComponent("cwd")
        try FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
        try #" [{"version":"269602","targets":[]},{"version":"269631","targets":[]},{"version":"270090","targets":[]}] "#
            .write(to: cwd.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        #expect(UpdateData.installedCatalogBuildCount(candidates: [
            userDir.appendingPathComponent("config-missing.json"),
            cwd.appendingPathComponent("config.json"),
        ]) == 3)
        // 全无 → nil（不显示对比行）
        #expect(UpdateData.installedCatalogBuildCount(candidates: []) == nil)
        try? FileManager.default.removeItem(at: tmp)
    }
}
