import Foundation

/// signatures.json — the SSOT for locator recipes (methodology as data).
/// Precise-VA entries in config.json remain the curated representation; these
/// recipes adapt to uncatalogued builds on day 0, and every derived address
/// still passes the Patcher's expected-byte gate before anything is written.
struct Signatures: Codable {
    struct RecipeSpec: Codable {
        let arch: Config.Arch
        let anchor: String
        let derive: String
        var confirm: String?
        /// Expected pristine bytes at the derived site (the WHAT to the recipe's WHERE).
        let expected: String
        let asm: String
        var binary: String?
        /// Optional behavioral-verification data (mini-loader route).
        var verify: Verifier.VerifySpec?
    }

    var recipes: [String: RecipeSpec]

    enum LoadError: Error, CustomStringConvertible {
        case notFound
        case malformed(String)

        var description: String {
            switch self {
            case .notFound: return "signatures.json not found (searched ./, user data dir, and next to the executable)"
            case .malformed(let d): return "signatures.json malformed: \(d)"
            }
        }
    }

    /// 搜索序与 Config.load 同构：显式 > cwd > **update-data 安装位（用户级
    /// 数据目录）** > 可执行文件向上 8 级。安装位不可漏：update-data 会把
    /// signatures.json 装到那里，漏掉它 OTA 下发的配方与 verify 规格就永远
    /// 不被消费——brew 随包 signatures 冻结在安装时刻，用户会拿到「新
    /// catalog + 旧配方/旧 verify spec」的混代数据（verify spec 的 stubs/
    /// zero 区按构建漂移，旧 spec 在新镜像上必错）。
    static func searchOrder(explicit: String?, cwd: String, exePath: String) -> [String] {
        var candidates: [String] = []
        if let explicit { candidates.append(explicit) }
        candidates.append(cwd + "/signatures.json")
        candidates.append(Config.userDataURL.appendingPathComponent("signatures.json").path)
        let exeDir = URL(fileURLWithPath: exePath).deletingLastPathComponent()
        var dir = exeDir
        for _ in 0..<8 {
            candidates.append(dir.appendingPathComponent("signatures.json").path)
            dir.deleteLastPathComponent()
        }
        return candidates
    }

    static func load(explicit: String?, cwd: String = FileManager.default.currentDirectoryPath) throws -> Signatures {
        let exePath = URL(fileURLWithPath: CommandLine.arguments[0],
                          relativeTo: nil).resolvingSymlinksInPath().path
        let candidates = searchOrder(explicit: explicit, cwd: cwd, exePath: exePath)
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw LoadError.notFound
        }
        // 供应链门（与 Config.load 同语义）：隐式发现的 signatures 做发布
        // 清单校验（manifest 同时守护 config+signatures）；显式 --signatures
        // 是用户自己的选择，不做门。清单缺失 = 旧分发（brew Cellar 随包无
        // manifest），提示不阻塞。
        if explicit == nil {
            switch Manifest.verify(directory: URL(fileURLWithPath: path).deletingLastPathComponent()) {
            case .legacy:
                print("note: no signed manifest next to \(path) — pre-v0.1.3 data or dev copy")
            case .invalid(let reason):
                throw LoadError.malformed("manifest check FAILED for \(path): \(reason). "
                    + "Refusing to load data that does not match its signed manifest.")
            case .verified:
                break
            }
        }
        do {
            let signatures = try JSONDecoder().decode(Signatures.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
            // 与 Config.validate 同规：asm/expected 坏 hex 不许进入补丁链路。
            // auto-locate 合成的条目绕过 Config 的校验直达 Patcher，坏数据
            // 会让 buildPlans 的 Data(hex:) 强解包 trap 而非报干净错误。
            for (name, spec) in signatures.recipes {
                if Data(hex: spec.asm) == nil {
                    throw LoadError.malformed("recipe \(name): bad hex asm \"\(spec.asm)\" (\(path))")
                }
                if ExpectedPattern(spec: spec.expected) == nil {
                    throw LoadError.malformed("recipe \(name): bad expected \"\(spec.expected)\" (\(path))")
                }
            }
            return signatures
        } catch let e as LoadError {
            throw e
        } catch {
            throw LoadError.malformed("\(error.localizedDescription) (\(path))")
        }
    }
}
