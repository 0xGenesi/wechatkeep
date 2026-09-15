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

    /// Local-first resolution: explicit flag > ./config.json > walk up from the
    /// executable (max 8 levels). Remote default catalog arrives in M5.
    static func load(explicit: String?) throws -> Config {
        var candidates: [String] = []
        if let explicit { candidates.append(explicit) }
        candidates.append(FileManager.default.currentDirectoryPath + "/config.json")
        let exeDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        var dir = exeDir
        for _ in 0..<8 {
            candidates.append(dir.appendingPathComponent("config.json").path)
            dir.deleteLastPathComponent()
        }
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw LoadError.notFound(searched: candidates)
        }
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw LoadError.malformed("unreadable at \(path): \(error.localizedDescription)") }
        return try Config(data: data, origin: path)
    }

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
