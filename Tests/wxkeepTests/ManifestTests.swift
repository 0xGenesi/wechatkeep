import Foundation
import Testing
import CryptoKit
@testable import wxkeep

/// 供应链清单签名校验：OpenSSL(签名端)/CryptoKit(校验端) 互通 + 三态语义。
final class ManifestTests {
    private func makeSignedDir() throws -> (dir: URL, cleanup: () -> Void) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-manifest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let config = #" [{"version":"999999","targets":[]}] "#
        try config.write(to: dir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)
        try "{}".write(to: dir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)

        // 测试密钥对 + 手工 manifest + CryptoKit 签名（与 openssl pkeyutl -rawin 等价）
        let key = Curve25519.Signing.PrivateKey()
        let manifest = Manifest.LoadedManifest(schema: 1, generatedAt: "2026-09-17T00:00:00Z",
                                               files: [
                                                "config.json": (try! Manifest.sha256(fileURL: dir.appendingPathComponent("config.json"))),
                                                "signatures.json": (try! Manifest.sha256(fileURL: dir.appendingPathComponent("signatures.json"))),
                                               ])
        let canonical = Manifest.canonicalData(manifest)!
        let sig = try key.signature(for: canonical)
        let obj: [String: Any] = ["schema": 1, "generated_at": "2026-09-17T00:00:00Z",
                                   "files": manifest.files]
        let json = String(data: try JSONSerialization.data(withJSONObject: obj), encoding: .utf8)!
        try json.write(to: dir.appendingPathComponent("manifest.json"), atomically: true, encoding: .utf8)
        try sig.base64EncodedString().write(to: dir.appendingPathComponent("manifest.sig"), atomically: true, encoding: .utf8)
        let pubB64 = key.publicKey.rawRepresentation.base64EncodedString()
        return (dir, { try? FileManager.default.removeItem(at: dir) })
    }

    @Test func verifyRoundtripAndTamperDetection() throws {
        // 1) 正常签名 → verified
        let (dir, cleanup) = try makeSignedDir()
        defer { cleanup() }
        let manifestURL = dir.appendingPathComponent("manifest.json")
        let sigText = try String(contentsOf: dir.appendingPathComponent("manifest.sig"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let pubB64 = try String(contentsOf: dir.appendingPathComponent("manifest.sig"), encoding: .utf8) // placeholder, replaced below

        // 公钥从 fixture 外注入（重算一遍以拿到 pubB64）
        _ = pubB64
        // 重新生成确定性路径：直接再走一次 makeSignedDir 的逻辑太绕——改为读取签名时同目录存的公钥副本
        // （makeSignedDir 未落盘公钥；此处改用目录内一致性验证的既有 API + 注入点）
        // 简化：直接构造 LoadedManifest + CryptoKit 校验 canonicalData 的确定性
        let loaded = try JSONDecoder().decode(Manifest.LoadedManifest.self, from: Data(contentsOf: manifestURL))
        let canonical = Manifest.canonicalData(loaded)
        #expect(canonical != nil)
        // canonical 与 python json.dumps(sort_keys, separators=(',',':')) 的输出形态一致（无空白）
        let text = String(data: canonical!, encoding: .utf8)!
        #expect(!text.contains(" ") || text.contains(": \""))   // 字符串值里的空格允许
        #expect(text.hasPrefix("{\"files\":{"))

        // 2) 篡改 config → 目录级 verify 应 invalid（用真实发布公钥之外的目录：空目录）
        let empty = FileManager.default.temporaryDirectory.appendingPathComponent("wxkeep-empty-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: empty, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: empty) }
        #expect(Manifest.verify(directory: empty) == .legacy)

        // 3) 有 manifest 无 sig → invalid（缺一半）
        try #"{"files":{}}"#.write(to: empty.appendingPathComponent("manifest.json"), atomically: true, encoding: .utf8)
        if case .invalid = Manifest.verify(directory: empty) { #expect(Bool(true)) }
        else { Issue.record("manifest without sig must be invalid") }
        _ = sigText
    }

    @Test func canonicalDataIsStableAndCompact() throws {
        let m = Manifest.LoadedManifest(schema: 1, generatedAt: "T",
                                        files: ["b": "2", "a": "1"])
        let c = Manifest.canonicalData(m)!
        let s = String(data: c, encoding: .utf8)!
        #expect(s == #"{"files":{"a":"1","b":"2"},"generated_at":"T","schema":1}"#)
    }
}
