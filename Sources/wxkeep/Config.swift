import Foundation

/// Patch catalog: `config.json`, a JSON array of per-build entries.
///
/// Two entry modes coexist:
/// - precise: `addr` (hex VA into the arch slice) — curated, verified data
/// - recipe:  `recipe` (M2) — resolved to a VA at patch time by RecipeEngine,
///            then gated by `expected` exactly like precise entries
///
/// Safety invariant: an entry without `expected` (original bytes) is quarantined —
/// `Patcher` refuses to write it unless explicitly overridden, and `restore`
/// can never invert it.
struct Config {
    var versions: [VersionEntry]

    // MARK: - Model

    struct VersionEntry: Codable {
        let version: String
        var targets: [Target]
        var note: String?
    }

    struct Target: Codable {
        let identifier: String
        /// Path inside the .app bundle. Missing = "Contents/MacOS/WeChat".
        var binary: String?
        var entries: [PatchEntry]
    }

        struct PatchEntry: Codable {
            let arch: Arch
            /// Hex VA within the arch slice (precise mode). Nil for recipe entries.
            var addr: String?
            /// Locator recipe (M2). Reserved now so the schema is stable.
            var recipe: [String: String]?
            /// Original bytes accepted before patching, hex. May list several
            /// variants (pristine + already-patched states). Nil = quarantined.
            var expected: ExpectedVariants?
            /// Bytes to write, hex. (`var`: restore inverts asm/expected in a copy.)
            var asm: String
            /// Provenance: which upstream catalog / analysis produced this entry.
            var source: String?
        }

    struct ExpectedVariants: Codable, Equatable {
        let values: [String]

        init(_ values: [String]) { self.values = values }
        init(_ single: String) { self.values = [single] }

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let single = try? container.decode(String.self) {
                values = [single]
            } else {
                values = try container.decode([String].self)
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(values)
        }
    }

    enum Arch: String, Codable {
        case arm64
        case x86_64

        var cpuType: Int32 {
            switch self {
            case .arm64: return 0x0100000C
            case .x86_64: return 0x01000007
            }
        }
    }

    // MARK: - Errors

    enum LoadError: Error, CustomStringConvertible {
        case notFound(searched: [String])
        case malformed(String)

        var description: String {
            switch self {
            case .notFound(let searched):
                "config.json not found. Searched: \(searched.joined(separator: ", ")). "
                + "Pass --config <path> or place config.json next to the executable."
            case .malformed(let detail):
                "config.json is malformed: \(detail)"
            }
        }
    }

    // MARK: - Loading

    /// Local-first resolution: explicit flag > ./config.json > next to the
    /// executable (resolving symlinks — brew's /usr/local/bin/wxkeep points
    /// into the Cellar) > walk up from it (max 8 levels).
    static func load(explicit: String?, cwd: String = FileManager.default.currentDirectoryPath,
                     localOverride: URL? = nil) throws -> Config {
        var candidates: [String] = []
        if let explicit { candidates.append(explicit) }
        candidates.append(cwd + "/config.json")
        // update-data 的安装位（用户级、免 sudo）：优先于随包分发 的旧数据
        candidates.append(Self.userDataURL.appendingPathComponent("config.json").path)
        // Resolve the executable's symlink: brew's /usr/local/bin/wxkeep →
        // ../Cellar/wxkeep/<ver>/bin/wxkeep, where config.json is staged.
        let exePath = URL(fileURLWithPath: CommandLine.arguments[0],
                          relativeTo: nil).resolvingSymlinksInPath().path
        let exeDir = URL(fileURLWithPath: exePath).deletingLastPathComponent()
        var dir = exeDir
        for _ in 0..<8 {
            candidates.append(dir.appendingPathComponent("config.json").path)
            dir.deleteLastPathComponent()
        }
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw LoadError.notFound(searched: candidates)
        }
        // 供应链门：隐式发现的 config（非用户显式指定）做发布清单校验。
        // 清单缺失 = 旧分发（提示但不阻塞）；清单存在且校验不过 = 数据被改动，拒载。
        if explicit == nil {
            let dir = URL(fileURLWithPath: path).deletingLastPathComponent()
            switch Manifest.verify(directory: dir) {
            case .legacy:
                print("note: no signed manifest next to \(path) — pre-v0.1.3 data or dev copy")
            case .invalid(let reason):
                throw LoadError.malformed("manifest check FAILED for \(path): \(reason). "
                    + "Refusing to load data that does not match its signed manifest.")
            case .verified:
                break
            }
        }
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw LoadError.malformed("unreadable at \(path): \(error.localizedDescription)") }
        var config = try Config(data: data, origin: path)

        // 本地定位条目（locate --append 产物）：与签名目录分文件、不走清单门——
        // 它们派生自用户自己的二进制，expected 门在 patch 时仍然校验真实字节。
        // 本地定位文件固定在用户级数据目录：brew（Cellar root 目录）用户也可写
        let localURL = localOverride ?? Self.userDataURL.appendingPathComponent("config.local.json")
        if FileManager.default.fileExists(atPath: localURL.path) {
            do {
                let ldata = try Data(contentsOf: localURL)
                let local = try Config(data: ldata, origin: localURL.path)
                config.merge(local: local)
            } catch let e as LoadError {
                throw LoadError.malformed("config.local.json: \(e.localizedDescription)")
            } catch {
                throw LoadError.malformed("config.local.json unreadable: \(error.localizedDescription)")
            }
        }
        return config
    }


    /// 合并本地定位条目：同构建→同 identifier+binary 目标按 (arch, addr) 去重追加；
    /// 新构建→整条插入。
    mutating func merge(local: Config) {
        for lver in local.versions {
            if let idx = versions.firstIndex(where: { $0.version == lver.version }) {
                for lt in lver.targets {
                    let key = "\(lt.identifier)|\(lt.binary ?? "Contents/MacOS/WeChat")"
                    if let tidx = versions[idx].targets.firstIndex(
                        where: { "\($0.identifier)|\($0.binary ?? "Contents/MacOS/WeChat")" == key }) {
                        let existing = Set(versions[idx].targets[tidx].entries.map {
                            "\($0.arch.rawValue)|\($0.addr ?? "")"
                        })
                        versions[idx].targets[tidx].entries += lt.entries.filter {
                            !existing.contains("\($0.arch.rawValue)|\($0.addr ?? "")")
                        }
                    } else {
                        versions[idx].targets.append(lt)
                    }
                }
            } else {
                versions.append(lver)
            }
        }
    }

    /// 用户级数据目录（wxkeep update-data 的安装位；测试可注入）。
    static var userDataURL: URL {
        if let override = _userDataURLOverride { return override }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("wxkeep")
    }
    nonisolated(unsafe) static var _userDataURLOverride: URL?   // 仅测试注入（Swift 并发门）

    /// 隐式 config 的定位目录（doctor/manifest 用于在同一目录校验 manifest）。
    /// 候选顺序必须与 `load` 保持一致（含 userDataURL——update-data 的安装位），
    /// 否则 doctor 会去校验另一个目录的清单：装入用户目录的数据被篡改也检不出。
    static func locatedDirectory() -> URL? {
        var candidates = [FileManager.default.currentDirectoryPath + "/config.json"]
        candidates.append(Self.userDataURL.appendingPathComponent("config.json").path)
        let exePath = URL(fileURLWithPath: CommandLine.arguments[0],
                          relativeTo: nil).resolvingSymlinksInPath().path
        var dir = URL(fileURLWithPath: exePath).deletingLastPathComponent()
        for _ in 0..<8 {
            candidates.append(dir.appendingPathComponent("config.json").path)
            dir.deleteLastPathComponent()
        }
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            return nil
        }
        return URL(fileURLWithPath: path).deletingLastPathComponent()
    }

    init(versions: [VersionEntry]) { self.versions = versions }

    init(data: Data, origin: String) throws {
        let decoder = JSONDecoder()
        do { versions = try decoder.decode([VersionEntry].self, from: data) }
        catch { throw LoadError.malformed("\(error.localizedDescription) (\(origin))") }
        try validate()
    }

    /// Fail fast on bad hex / ambiguous modes so Patcher never sees garbage.
    private func validate() throws {
        for v in versions {
            for t in v.targets {
                for e in t.entries {
                    if e.addr == nil && e.recipe == nil {
                        throw LoadError.malformed(
                            "build \(v.version) target \(t.identifier): entry needs addr or recipe")
                    }
                    if e.addr != nil && e.recipe != nil {
                        throw LoadError.malformed(
                            "build \(v.version) target \(t.identifier): addr and recipe are mutually exclusive")
                    }
                    if let addr = e.addr, UInt64(addr, radix: 16) == nil {
                        throw LoadError.malformed(
                            "build \(v.version) target \(t.identifier): bad hex addr \"\(addr)\"")
                    }
                    if Data(hex: e.asm) == nil {
                        throw LoadError.malformed(
                            "build \(v.version) target \(t.identifier): bad hex asm \"\(e.asm)\"")
                    }
                    for variant in e.expected?.values ?? [] {
                        if Data(hex: variant) == nil {
                            throw LoadError.malformed(
                                "build \(v.version) target \(t.identifier): bad hex expected \"\(variant)\"")
                        }
                    }
                }
            }
        }
    }

    // MARK: - Queries

    func entry(build: String) -> VersionEntry? {
        versions.first { $0.version == build }
    }
}

// MARK: - Hex helpers

extension Data {
    /// Uppercase-hex string → bytes. Nil on odd length or non-hex characters.
    init?(hex: String) {
        let chars = Array(hex.unicodeScalars)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            guard let hi = chars[index].hexValue, let lo = chars[index + 1].hexValue else { return nil }
            bytes.append(UInt8(hi << 4 | lo))
            index += 2
        }
        self = Data(bytes)
    }

    var hexUppercase: String {
        map { String(format: "%02X", $0) }.joined()
    }
}

extension Unicode.Scalar {
    var hexValue: Int? {
        switch self {
        case "0"..."9": return Int(value - Unicode.Scalar("0").value)
        case "a"..."f": return Int(value - Unicode.Scalar("a").value + 10)
        case "A"..."F": return Int(value - Unicode.Scalar("A").value + 10)
        default: return nil
        }
    }
}
