
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

/// 安全不变量回归：asm 写入跨度不得超过 expected 溯源跨度。
/// expected 门只校验 expected 长度的前缀——asm 更长的条目会覆盖无出处的
/// 尾部字节且 restore 无法回补（catalog 拒载是唯一安全侧）。
extension ConfigLocalTests {
    @Test func asmSpanBeyondProvenanceIsRejected() {
        // asm 6B > expected 4B：必须拒载
        let over = """
        [{"version":"900001","targets":[
          {"identifier":"revoke","binary":"x","entries":[
            {"arch":"x86_64","addr":"100","expected":"AABBCCDD","asm":"112233445566"}]}]}]
        """
        #expect(throws: (any Error).self) {
            _ = try Config(data: Data(over.utf8), origin: "inline")
        }
        // 通配 expected 同规（通配不影响字节计数）
        let wild = """
        [{"version":"900002","targets":[
          {"identifier":"revoke","binary":"x","entries":[
            {"arch":"x86_64","addr":"100","expected":"84C00F84????????","asm":"30C0CCDDEEFF00112233"}]}]}]
        """
        #expect(throws: (any Error).self) {
            _ = try Config(data: Data(wild.utf8), origin: "inline")
        }
        // 等长（silent 形态 9B=9B）与短于（守卫形态 2B≤8B）均放行
        let ok = """
        [{"version":"900003","targets":[
          {"identifier":"revoke","binary":"x","entries":[
            {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"},
            {"arch":"x86_64","addr":"200","expected":"84C00F84????????","asm":"30C0"}]}]}]
        """
        do { _ = try Config(data: Data(ok.utf8), origin: "inline") }
        catch { Issue.record("等长/短于溯源跨度必须放行: \(error)") }
    }

    /// 目录数据不变量：silent 与 keeptip 共享位点（同构建同 arch 同 addr）上，
    /// keeptip 条目的 expected 必须包含 silent 的 asm（pristine + 已打补丁双态）。
    /// 单 expected 会让 keeptip 在 silent 补丁态上过不了 expected 门——变体切换
    /// 的 dry-run 预览误报「wrong WeChat build」，`--only` 路径无法直接过渡
    /// （2026-09-23 实测 23 构建全是 arm64 cbz 条目缺 silent 翻转字节 82000014；
    /// fzlzjerry 导入的 270090/269628 与全部 x64 normalize 条目本就是双态）。
    /// 锁死目录数据防未来派生轮（derive_build_from_cdn）重新引入单 expected。
    @Test func catalogCrossVariantExpectedIsComplete() throws {
        let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: here.appendingPathComponent("config.json"))
        let config = try Config(data: data, origin: "repo catalog")
        var gaps: [String] = []
        for version in config.versions {
            guard let revoke = version.targets.first(where: { $0.identifier == "revoke" }),
                  let keeptip = version.targets.first(where: { $0.identifier == "revoke-keeptip" })
            else { continue }
            var revokeBySite: [String: Config.PatchEntry] = [:]
            for e in revoke.entries {
                if let addr = e.addr {
                    revokeBySite["\(e.arch.rawValue):\(addr.lowercased())"] = e
                }
            }
            for entry in keeptip.entries {
                guard let addr = entry.addr, let variants = entry.expected else { continue }
                let key = "\(entry.arch.rawValue):\(addr.lowercased())"
                guard let sibling = revokeBySite[key] else { continue }
                let siblingAsm = sibling.asm.uppercased()
                if !variants.values.contains(where: { $0.uppercased() == siblingAsm }) {
                    gaps.append("\(version.version) \(key)")
                }
            }
        }
        #expect(gaps.isEmpty, "共享位点缺跨变体 expected: \(gaps.joined(separator: ", "))")
    }
}
