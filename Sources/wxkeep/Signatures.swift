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
        /// 按构建绑定的 verify spec 变体：stubs/zero_regions 是绝对 VA，逐
        /// 构建漂移——legacy `verify` 只覆盖 270099 族，其余构建各自派生
        /// （gen_verify_spec*.py 从 thin 切片反解）。选中规则：本构建命中
        /// 变体优先；未命中回落 `verify`（不适用镜像由 worker 形态门
        /// exit 4 优雅跳过，语义不变）。旧 CLI 忽略未知 JSON 键，新字段
        /// 不破坏 update-data 的向后兼容。
        var verifyVariants: [VerifyVariant]?

        enum CodingKeys: String, CodingKey {
            case arch, anchor, derive, confirm, expected, asm, binary
            case verify, verifyVariants = "verify_variants"
        }

        /// 谓词变体只做选址：stubs/probes 的解码与校验复用 VerifySpec。
        struct VerifyVariant: Codable {
            /// 适用构建号（点分营销线无构建号，变体一律按构建号绑定）。
            let builds: [String]
            let stubs: [String: String]
            let zeroRegions: [[String]]
            let probes: [[String]]

            enum CodingKeys: String, CodingKey {
                case builds, stubs, probes
                case zeroRegions = "zero_regions"
            }
        }

        /// 行为验证 spec 的按构建选择：变体命中优先，回落 legacy `verify`。
        func verifySpec(for build: String) -> Verifier.VerifySpec? {
            if let hit = verifyVariants?.first(where: { $0.builds.contains(build) }) {
                return Verifier.VerifySpec(
                    stubs: hit.stubs, zeroRegions: hit.zeroRegions, probes: hit.probes)
            }
            return verify
        }
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
        let explicitPath = explicit.map { ($0 as NSString).expandingTildeInPath }
        let candidates = searchOrder(explicit: explicitPath, cwd: cwd, exePath: exePath)
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw LoadError.notFound
        }
        // 供应链门（sudo 面，与 Config.load 同规）：root 语境下隐式命中 cwd 的
        // signatures = expected 基准可被工作目录内容供给。
        if explicit == nil, geteuid() == 0, path.hasPrefix(cwd + "/") {
            throw LoadError.malformed(
                "refusing implicit cwd signatures under sudo: \(path). "
                + "sudo 下 cwd 文件不在清单信任域——用 --signatures <path> 显式指定。")
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
                guard let pattern = ExpectedPattern(spec: spec.expected) else {
                    throw LoadError.malformed("recipe \(name): bad expected \"\(spec.expected)\" (\(path))")
                }
                // 与 Config.validate 的「asm 跨度 ≤ expected 可复原面」同规：
                // auto-locate 合成条目绕过 Config 校验直达 Patcher——asm 比每
                // 个 expected 变体都长 = 写得进.restore 不回（不可复原写入面）。
                if let asmBytes = Data(hex: spec.asm), asmBytes.count > pattern.byteCount {
                    throw LoadError.malformed(
                        "recipe \(name): asm (\(asmBytes.count)B) longer than every expected variant "
                        + "(\(pattern.byteCount)B) — write would touch unrestorable bytes (\(path))")
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
