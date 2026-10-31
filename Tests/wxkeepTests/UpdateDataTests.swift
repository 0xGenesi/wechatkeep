import Foundation
import Testing
import CryptoKit
@testable import wxkeep

/// serialized：`Config._userDataURLOverride` 是进程级全局（非隔离 unsafe
/// static），并发实例的 init/deinit 会互相清掉 override——本套件内测试必须
/// 串行（既有测试同款窗口，此前步骤短未炸）。
@Suite(.serialized)
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

    /// 显式 --config 不存在必须即时报错：静默回落候选链 = 拿另一份目录的
    /// expected 基准打补丁（P1 修复回归）。
    @Test func explicitConfigMustExist() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wxkeep-ud-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        Config._userDataURLOverride = tmp
        defer { try? FileManager.default.removeItem(at: tmp) }
        #expect(throws: Config.LoadError.self) {
            _ = try Config.load(explicit: "/nonexistent/path/config.json", cwd: tmp.path)
        }
    }

    /// legacy 迁移种子（writeTip 专线）：双目标全空而旧位置带 hooks/
    /// rewrite_self 时，首写必须并入 legacy 内容——dylib 是「首个可读文件」
    /// 选径，无种子的新文件会整体遮蔽旧位置 = hooks 外部表静默降级
    /// （P1 修复回归）。
    @Test func tipWriteSeedsLegacyWhenTargetsEmpty() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wxkeep-ud-\(UUID().uuidString)")
        let userDir = tmp.appendingPathComponent("user")
        try FileManager.default.createDirectory(at: userDir, withIntermediateDirectories: true)
        Config._userDataURLOverride = userDir
        defer { try? FileManager.default.removeItem(at: tmp) }
        let legacyDict: [String: Any] = [
            "hooks": [["build": "270099", "uuid": "legacy-row", "arch": "x86_64",
                       "hook_off": "0x1000", "expected": "deadbeef"]],
            "rewrite_self": true,
        ]
        let legacyData = try PropertyListSerialization.data(fromPropertyList: legacyDict, format: .xml, options: 0)
        try legacyData.write(to: userDir.appendingPathComponent("runtime.json"))
        let t1 = tmp.appendingPathComponent("t1.json")
        let t2 = tmp.appendingPathComponent("t2.json")

        _ = try RuntimeConfig.writeTip(text: "\"⚠️\" 撤回了一条消息", rewriteSelf: nil, at: [t1, t2])
        for target in [t1, t2] {
            let dict = try PropertyListSerialization.propertyList(
                from: Data(contentsOf: target), options: [], format: nil) as? [String: Any]
            #expect((dict?["hooks"] as? [[String: Any]])?.count == 1,
                    "\(target.lastPathComponent): legacy hooks 行必须随种子保留")
            #expect((dict?["rewrite_self"] as? Bool) == true,
                    "\(target.lastPathComponent): legacy rewrite_self 必须随种子保留")
            #expect((dict?["tip_text"] as? String) == "\"⚠️\" 撤回了一条消息")
        }
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

    /// update-data 的 signatures 数据通道：安装位（用户级数据目录）必须在
    /// Signatures.load 搜索序里（与 Config.load 同序）——否则 OTA 下发的
    /// 配方与 verify 规格永远不被消费，brew 用户拿到「新 catalog + 随包冻结
    /// 旧 signatures」的混代数据。隐式发现的 signatures 同步过清单门：
    /// 无清单 = 旧分发（提示后装载）；清单不符 = 拒载；显式路径不做门。
    @Test func signaturesLoadSearchesUserDataDirAndHonorsManifest() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-sigsearch-\(UUID().uuidString)")
        let userDir = tmp.appendingPathComponent("user")
        let exeDir = tmp.appendingPathComponent("bundled/bin")
        let emptyCwd = tmp.appendingPathComponent("empty")
        for d in [userDir, exeDir, emptyCwd] {
            try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        }
        defer { try? FileManager.default.removeItem(at: tmp) }
        func sig(_ name: String) -> String {
            #"{"recipes":{"\#(name)":{"arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary","expected":"554889E5","asm":"31C0C3","binary":null}}}"#
        }
        try sig("from_user_dir").write(to: userDir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)
        try sig("from_bundled").write(to: exeDir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)
        Config._userDataURLOverride = userDir

        // 1) 安装位优先于随包数据（两处均无 manifest → legacy 提示后装载）
        let loaded = try Signatures.load(explicit: nil, cwd: emptyCwd.path)
        #expect(loaded.recipes["from_user_dir"] != nil, "安装位的 signatures 必须胜出")
        #expect(loaded.recipes["from_bundled"] == nil)

        // 2) 安装位出现清单但签名不符（无关键 = 篡改/不同源）→ 拒载
        let key = Curve25519.Signing.PrivateKey()
        let manifest = Manifest.LoadedManifest(
            schema: 1, generatedAt: "2026-09-23T00:00:00Z",
            files: ["config.json": String(repeating: "0", count: 64),
                    "signatures.json": String(repeating: "1", count: 64)])
        let sigBytes = try key.signature(for: Manifest.canonicalData(manifest)!)
        let obj: [String: Any] = ["schema": 1, "generated_at": "2026-09-23T00:00:00Z",
                                  "files": manifest.files]
        try String(data: JSONSerialization.data(withJSONObject: obj), encoding: .utf8)!
            .write(to: userDir.appendingPathComponent("manifest.json"), atomically: true, encoding: .utf8)
        try sigBytes.base64EncodedString()
            .write(to: userDir.appendingPathComponent("manifest.sig"), atomically: true, encoding: .utf8)
        #expect(throws: (any Error).self) {
            _ = try Signatures.load(explicit: nil, cwd: emptyCwd.path)
        }

        // 3) 显式路径是用户自己的选择，不做清单门
        let explicit = try Signatures.load(
            explicit: userDir.appendingPathComponent("signatures.json").path, cwd: emptyCwd.path)
        #expect(explicit.recipes["from_user_dir"] != nil)
    }
}
