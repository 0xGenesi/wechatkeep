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
            case .notFound: return "signatures.json not found (searched ./ and next to the executable)"
            case .malformed(let d): return "signatures.json malformed: \(d)"
            }
        }
    }

    static func load(explicit: String?) throws -> Signatures {
        var candidates: [String] = []
        if let explicit { candidates.append(explicit) }
        candidates.append(FileManager.default.currentDirectoryPath + "/signatures.json")
        let exeDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        var dir = exeDir
        for _ in 0..<8 {
            candidates.append(dir.appendingPathComponent("signatures.json").path)
            dir.deleteLastPathComponent()
        }
        guard let path = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw LoadError.notFound
        }
        do {
            return try JSONDecoder().decode(Signatures.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        } catch {
            throw LoadError.malformed("\(error.localizedDescription) (\(path))")
        }
    }
}
