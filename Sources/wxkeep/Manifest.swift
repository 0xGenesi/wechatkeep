import Foundation
import CryptoKit

/// 发布清单校验（供应链防篡改）。
///
/// `manifest.json` 记录受保护数据文件（config.json / signatures.json）的 sha256，
/// `manifest.sig` 是对清单规范字节串的 Ed25519 签名；公钥内嵌于本二进制
/// （keys/release.pub 的 raw 32 字节 base64）。
///
/// 验证语义：
/// - 清单缺失 → `.legacy`（旧版本分发包，仅提示，不阻塞——门是从新版本开始守的）
/// - 签名不成立 / 文件哈希不符 → `.invalid`（数据被篡改或与清单不同源——拒绝消费）
/// - 两者皆过 → `.verified`
///
/// 策略（Config.load 消费）：随可执行文件分发的隐式 config 走硬门（invalid 即拒载）；
/// 用户显式 `--config` 指定的文件是用户自己的选择，不做门。
enum Manifest {
    /// 与 keys/release.pub 同源的 Ed25519 公钥（raw 32 字节，base64）。
    /// 轮换密钥 = 换此常量 + keys/release.pub + 重发版。
    static let releasePublicKeyB64 = "BVnWvvWOEZNzMtr1oheBh4Oamd8F13W9/6RDFV7J5TU="

    static let protectedFiles = ["config.json", "signatures.json"]

    enum Status: Equatable {
        case verified
        case legacy
        case invalid(String)
    }

    struct LoadedManifest: Codable {
        let schema: Int
        let generatedAt: String?
        let files: [String: String]
        enum CodingKeys: String, CodingKey {
            case schema
            case generatedAt = "generated_at"
            case files
        }
    }

    /// 规范字节串——必须与 tools/sign_manifest.py 的 json.dumps(sort_keys, separators) 一致。
    static func canonicalData(_ manifest: LoadedManifest) -> Data? {
        var obj: [String: Any] = ["schema": manifest.schema, "files": manifest.files]
        if let at = manifest.generatedAt { obj["generated_at"] = at }
        guard JSONSerialization.isValidJSONObject(obj),
              let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) else {
            return nil
        }
        // JSONSerialization 无紧凑分隔符选项：手工去空白等价于 separators=(',',':')
        var out = Data(capacity: data.count)
        var inString = false, escape = false
        for b in data {
            let c = Character(UnicodeScalar(b))
            if escape { escape = false; out.append(b); continue }
            if inString {
                if c == "\\" { escape = true }
                inString = c != "\""
                out.append(b); continue
            }
            if c == "\"" { inString = true; out.append(b); continue }
            if b == 0x20 || b == 0x0A || b == 0x09 || b == 0x0D { continue }
            out.append(b)
        }
        return out
    }

    static func sha256(fileURL: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// 校验 `dir` 下的 manifest.json / manifest.sig 与受保护文件。
    /// `publicKeyB64` 参数化以便测试注入；默认内嵌发布公钥。
    static func verify(directory: URL, publicKeyB64: String = releasePublicKeyB64) -> Status {
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let sigURL = directory.appendingPathComponent("manifest.sig")
        guard FileManager.default.fileExists(atPath: manifestURL.path) ||
              FileManager.default.fileExists(atPath: sigURL.path) else {
            return .legacy
        }
        guard let manifestData = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(LoadedManifest.self, from: manifestData),
              let sigB64 = (try? String(contentsOf: sigURL, encoding: .utf8))?
                  .trimmingCharacters(in: .whitespacesAndNewlines),
              let signature = Data(base64Encoded: sigB64),
              let pubRaw = Data(base64Encoded: publicKeyB64),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubRaw),
              let canonical = canonicalData(manifest)
        else {
            return .invalid("manifest 格式/签名不可读")
        }
        guard pubKey.isValidSignature(signature, for: canonical) else {
            return .invalid("签名校验失败（清单被改动或密钥不符）")
        }
        for rel in protectedFiles {
            guard let expected = manifest.files[rel] else {
                return .invalid("清单缺少 \(rel) 的哈希")
            }
            let fileURL = directory.appendingPathComponent(rel)
            guard FileManager.default.fileExists(atPath: fileURL.path),
                  let actual = try? sha256(fileURL: fileURL), actual == expected else {
                return .invalid("\(rel) 与清单不符（被改动或不同源）")
            }
        }
        return .verified
    }

    // MARK: - 141 轮 P1-2（verify→read TOCTOU 收口）

    /// 带字节回收的校验结果：`verified` 携带**校验时刻单次读入内存**的
    /// 原始字节（受保护文件 + manifest.json/manifest.sig 本体）——消费/
    /// 安装方一律使用返回字节，杜绝「签名门验盘上 A、引擎再读换身 B」
    /// 的竞窗（用户级攻击者在 sudo patch 的毫秒窗内换文件即可让 Ed25519
    /// 门形同虚设；Signatures/Config/UpdateData 三消费点 141 轮全部改道）。
    enum Collected: Equatable {
        case verified([String: Data])
        case legacy
        case invalid(String)
    }

    /// verify 的免竞窗变体：受保护文件**单次读入内存**后对内存字节做
    /// sha256（不再二次开路径），manifest 双件一并回收（update-data 的
    /// 换位安装从内存写——安装后再验的盘读同样免竞窗；manifest.json 的
    /// 完整性由签名自证，manifest.sig 回收仅为安装同源）。
    static func verifyCollecting(directory: URL,
                                 publicKeyB64: String = releasePublicKeyB64) -> Collected {
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let sigURL = directory.appendingPathComponent("manifest.sig")
        guard FileManager.default.fileExists(atPath: manifestURL.path) ||
              FileManager.default.fileExists(atPath: sigURL.path) else {
            return .legacy
        }
        guard let manifestData = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(LoadedManifest.self, from: manifestData),
              let sigData = try? Data(contentsOf: sigURL),
              let sigB64 = String(data: sigData, encoding: .utf8)?
                  .trimmingCharacters(in: .whitespacesAndNewlines),
              let signature = Data(base64Encoded: sigB64),
              let pubRaw = Data(base64Encoded: publicKeyB64),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubRaw),
              let canonical = canonicalData(manifest)
        else {
            return .invalid("manifest 格式/签名不可读")
        }
        guard pubKey.isValidSignature(signature, for: canonical) else {
            return .invalid("签名校验失败（清单被改动或密钥不符）")
        }
        var collected: [String: Data] = [
            "manifest.json": manifestData,
            "manifest.sig": sigData,
        ]
        for rel in protectedFiles {
            guard let expected = manifest.files[rel] else {
                return .invalid("清单缺少 \(rel) 的哈希")
            }
            let fileURL = directory.appendingPathComponent(rel)
            guard let bytes = try? Data(contentsOf: fileURL) else {
                return .invalid("\(rel) 不可读（被改动或不同源）")
            }
            let actual = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            guard actual == expected else {
                return .invalid("\(rel) 与清单不符（被改动或不同源）")
            }
            collected[rel] = bytes
        }
        return .verified(collected)
    }
}
