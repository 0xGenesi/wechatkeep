import Foundation

/// Orchestrates one patch/restore run over an app bundle: catalog lookup,
/// variant-based target selection, per-binary grouping, backup, patching.
///
/// Resigning is NOT wired yet (M3). Until it is, `patch` hard-refuses real app
/// bundles unless `--ack-no-resign` is passed — a patched-but-unresigned bundle
/// is a guaranteed "Code Signature Invalid" kill on launch.
enum Engine {
    enum EngineError: Error, CustomStringConvertible {
        case unsupportedBuild(String, known: Int)
        case variantUnavailable(String)
        case restoreUnavailable(String)

        var description: String {
            switch self {
            case .unsupportedBuild(let build, let known):
                "build \(build) is not in the catalog (\(known) builds known). "
                + "Run `wxkeep locate` (M2) to auto-locate it, or wait for the catalog to update."
            case .variantUnavailable(let variant):
                "this build has no curated entries for variant `\(variant)`"
            case .restoreUnavailable(let detail):
                "cannot restore: \(detail). Reinstall WeChat from the official dmg, or use a backup file."
            }
        }
    }

    struct RunSummary {
        var lines: [String] = []
        var wroteAnything = false
        /// Bundle-relative paths of binaries whose bytes changed (for resign).
        var patchedBinaries: [String] = []
    }

    /// Auto-locate fallback: when the installed build is not in the catalog,
    /// run every signature recipe against the real binaries and synthesize a
    /// version entry on the fly. Derived addresses still pass the expected
    /// gate — a recipe picks WHERE, the gate decides WHETHER.
    static func autoLocatedEntry(app: URL, signatures: Signatures) -> Config.VersionEntry? {
        var targetsByBinary: [String: [Config.Target]] = [:]
        guard let build = try? WeChatApp.buildNumber(app: app) else { return nil }
        for (name, spec) in signatures.recipes.sorted(by: { $0.key < $1.key }) {
            let relative = spec.binary ?? "Contents/MacOS/WeChat"
            let binary = WeChatApp.binaryURL(app: app, relative: relative)
            guard FileManager.default.fileExists(atPath: binary.path) else { continue }
            let recipe: RecipeEngine.Recipe
            do {
                recipe = try RecipeEngine.Recipe(
                    anchor: spec.anchor, derive: spec.derive,
                    confirm: spec.confirm.map { $0.split(separator: ";").map(String.init) } ?? [])
            } catch { continue }
            guard let image = try? MachImage(file: binary, arch: spec.arch),
                  let va = try? RecipeEngine.resolve(recipe: recipe, image: image, arch: spec.arch)
            else { continue }
            let entry = Config.PatchEntry(
                arch: spec.arch, addr: String(va, radix: 16), recipe: nil,
                expected: Config.ExpectedVariants(spec.expected),
                asm: spec.asm, source: "recipe:\(name)")
            var group = targetsByBinary[relative, default: []]
            if let idx = group.firstIndex(where: { $0.identifier == "revoke" }) {
                group[idx].entries.append(entry)
            } else {
                group.append(Config.Target(identifier: "revoke", binary: spec.binary, entries: [entry]))
            }
            targetsByBinary[relative] = group
        }
        guard !targetsByBinary.isEmpty else { return nil }
        let targets = targetsByBinary.flatMap { $0.value }
        return Config.VersionEntry(version: build, targets: targets,
                                   note: "auto-located via signature recipes")
    }

    /// Selects targets for a variant: `revoke` for silent, `revoke-keeptip` for
    /// keeptip; every non-variant identifier (update, multiInstance, …) always applies.
    static func targets(for version: Config.VersionEntry, variant: String) throws -> [Config.Target] {
        let variantID = variant == "keeptip" ? "revoke-keeptip" : "revoke"
        var selected = [Config.Target]()
        for target in version.targets {
            if target.identifier == "revoke" || target.identifier == "revoke-keeptip" {
                if target.identifier == variantID { selected.append(target) }
            } else {
                selected.append(target)
            }
        }
        guard selected.contains(where: { $0.identifier == variantID }) else {
            throw EngineError.variantUnavailable(variant)
        }
        return selected
    }

    /// Patches every selected target of `build` inside `app` (catalog path).
    @discardableResult
    static func patch(
        app: URL, build: String, config: Config, variant: String,
        dryRun: Bool, allowUnverified: Bool, only: [String]?
    ) throws -> RunSummary {
        guard let versionEntry = config.entry(build: build) else {
            throw EngineError.unsupportedBuild(build, known: config.versions.count)
        }
        return try patch(app: app, versionEntry: versionEntry, variant: variant,
                         dryRun: dryRun, allowUnverified: allowUnverified, only: only)
    }

    /// Core patch path — works with a catalog entry OR a recipe-synthesized one.
    @discardableResult
    static func patch(
        app: URL, versionEntry: Config.VersionEntry, variant: String,
        dryRun: Bool, allowUnverified: Bool, only: [String]?
    ) throws -> RunSummary {
        var summary = RunSummary()
        var selected = try targets(for: versionEntry, variant: variant)
        if let only, !only.isEmpty {
            selected = selected.filter { only.contains($0.identifier) }
            guard !selected.isEmpty else {
                throw EngineError.variantUnavailable("no matching targets for --only \(only.joined(separator: ","))")
            }
        }

        let grouped = Dictionary(grouping: selected, by: { $0.binary ?? "Contents/MacOS/WeChat" })
        for (relative, targets) in grouped.sorted(by: { $0.key < $1.key }) {
            let binary = WeChatApp.binaryURL(app: app, relative: relative)
            summary.lines.append("binary: \(relative) (\(targets.map(\.identifier).joined(separator: ", ")))")
            let willWrite: (Config.PatchEntry, String) -> Bool = { entry, identifier in
                let inspections = (try? Patcher.inspect(binary: binary, entries: [entry], identifier: identifier)) ?? []
                return inspections.first?.state != .patched
            }
            // Decide whether a backup is needed before mutating anything.
            var needsBackup = false
            for target in targets {
                if target.entries.contains(where: { willWrite($0, target.identifier) }) {
                    needsBackup = true
                    break
                }
            }
            if needsBackup && !dryRun {
                let backup = try Backup.make(binary: binary)
                summary.lines.append("  backup: \(backup.lastPathComponent)")
            }
            for target in targets {
                let outcomes = try Patcher.patch(
                    binary: binary, entries: target.entries, identifier: target.identifier,
                    dryRun: dryRun, allowUnverified: allowUnverified)
                let written = outcomes.filter { $0 == .written }.count
                let skipped = outcomes.filter { $0 == .alreadyPatched }.count
                summary.wroteAnything = summary.wroteAnything || written > 0
                if written > 0 { summary.patchedBinaries.append(relative) }
                summary.lines.append("  \(target.identifier): \(written) written, \(skipped) already-patched")
            }
        }
        return summary
    }

    /// Inverts every catalog patch: writes `expected[0]` back, accepting both
    /// pristine and patched states (idempotent). Fails before writing anything
    /// if any target lacks `expected`.
    @discardableResult
    static func restore(app: URL, build: String, config: Config, dryRun: Bool) throws -> RunSummary {
        var summary = RunSummary()
        guard let versionEntry = config.entry(build: build) else {
            throw EngineError.unsupportedBuild(build, known: config.versions.count)
        }
        // Preflight: every target must be restorable.
        for target in versionEntry.targets {
            let unrestorable = target.entries.enumerated().filter { $0.element.expected == nil }
            if !unrestorable.isEmpty {
                throw EngineError.restoreUnavailable(
                    "target \(target.identifier) entries \(unrestorable.map(\.offset)) have no original bytes")
            }
        }
        let grouped = Dictionary(grouping: versionEntry.targets, by: { $0.binary ?? "Contents/MacOS/WeChat" })
        for (relative, targets) in grouped.sorted(by: { $0.key < $1.key }) {
            let binary = WeChatApp.binaryURL(app: app, relative: relative)
            summary.lines.append("binary: \(relative)")
            for target in targets {
                let inverted = target.entries.map { entry -> Config.PatchEntry in
                    var copy = entry
                    let asm = entry.asm
                    copy.asm = entry.expected!.values[0]
                    copy.expected = Config.ExpectedVariants([asm] + entry.expected!.values)
                    return copy
                }
                let outcomes = try Patcher.patch(
                    binary: binary, entries: inverted, identifier: target.identifier, dryRun: dryRun)
                let restored = outcomes.filter { $0 == .written }.count
                let skipped = outcomes.filter { $0 == .alreadyPatched }.count
                summary.wroteAnything = summary.wroteAnything || restored > 0
                if restored > 0 { summary.patchedBinaries.append(relative) }
                summary.lines.append("  \(target.identifier): \(restored) restored, \(skipped) already-pristine")
            }
        }
        return summary
    }
}
