import Foundation

/// Orchestrates one patch/restore run over an app bundle: catalog lookup,
/// variant-based target selection, per-binary grouping, backup, patching.
///
/// The CLI layer invokes Resigner afterwards for anything that wrote bytes.
enum Engine {
    enum EngineError: Error, CustomStringConvertible {
        case unsupportedBuild(String, known: Int)
        case variantUnavailable(String)
        case restoreUnavailable(String)
        case variantDeprecated(String)
        case foreignVariantPatched(target: String, sites: [String])

        var description: String {
            switch self {
            case .unsupportedBuild(let build, let known):
                "build \(build) is not in the catalog (\(known) builds known). "
                + "Run `wxkeep locate` (M2) to auto-locate it, or wait for the catalog to update."
            case .variantUnavailable(let variant):
                "this build has no curated entries for variant `\(variant)`"
            case .restoreUnavailable(let detail):
                "cannot restore: \(detail). Reinstall WeChat from the official dmg, or use a backup file."
            case .variantDeprecated(let variant):
                "variant `\(variant)` is deprecated: experiments proved it cannot preserve messages, "
                + "and its final revision crashes WeChat. Run `sudo wxkeep restore` to clean any "
                + "leftover bytes, then use `--variant keeptip`."
            case .foreignVariantPatched(let target, let sites):
                "deprecated target `\(target)` still has patched bytes at: "
                + "\(sites.joined(separator: ", ")). Run `sudo wxkeep restore` first, then re-run this command."
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
    /// (`revoke-keeptip2` is deprecated and can no longer be selected — it is kept
    /// in the catalog solely so `restore` can unwind machines that ran the experiments.)
    static func targets(for version: Config.VersionEntry, variant: String) throws -> [Config.Target] {
        let variantID = variant == "keeptip" ? "revoke-keeptip" : "revoke"
        var selected = [Config.Target]()
        for target in version.targets {
            if target.identifier == "revoke-keeptip2" {
                continue   // 废弃变体：永不自动应用（否则 else 分支会把它当 always-apply 目标）
            }
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

    /// Deprecated revoke-keeptip2 sites still holding its patched bytes,
    /// EXCLUDING sites also written by `coveredTargets` (shared writes —
    /// v1/keeptip2 both restore the prologue at 0x4bc5940 — are not leftovers).
    /// Empty result = clean.
    static func deprecatedLeftovers(
        app: URL, versionEntry: Config.VersionEntry, coveredTargets: [Config.Target]
    ) throws -> [String] {
        guard let legacy = versionEntry.targets.first(where: { $0.identifier == "revoke-keeptip2" }),
              !legacy.entries.isEmpty
        else { return [] }
        let covered = Set(coveredTargets.flatMap { target in
            target.entries.compactMap { en -> String? in
                guard let addr = en.addr?.lowercased() else { return nil }
                return "\(en.arch.rawValue):\(addr)"
            }
        })
        var leftover = [String]()
        let relative = legacy.binary ?? "Contents/MacOS/WeChat"
        let binary = WeChatApp.binaryURL(app: app, relative: relative)
        let inspections = (try? Patcher.inspect(
            binary: binary, entries: legacy.entries, identifier: legacy.identifier)) ?? []
        for i in inspections where i.state == .patched {
            let key = "\(i.arch.rawValue):\(String(i.va, radix: 16))"
            guard !covered.contains(key) else { continue }
            leftover.append("0x\(String(i.va, radix: 16))")
        }
        return leftover
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
        if variant == "keeptip2" {
            throw EngineError.variantDeprecated(variant)
        }
        var selected = try targets(for: versionEntry, variant: variant)

        // 遗留检测：废弃的 revoke-keeptip2 若还有补丁字节在盘上，拒绝应用并在
        // 报错里给出清理路径（而不是默默留下混合状态——今日实测的混淆根源）。
        // 例外：当前变体也覆盖的位点（v1/keeptip2 共享 0x4bc5940/0x32a0d9d——
        // 两变体在这些地址写相同字节，不算残留）。
        let leftover = try deprecatedLeftovers(app: app, versionEntry: versionEntry,
                                               coveredTargets: selected)
        if !leftover.isEmpty {
            throw EngineError.foreignVariantPatched(target: "revoke-keeptip2", sites: leftover)
        }

        // 变体切换：先还原另一变体的写入（幂等），再应用本变体。
        // 否则 silent 的 x64 补丁会与 keeptip 并存，静默语义覆盖 keeptip。
        let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"
        if let other = versionEntry.targets.first(where: { $0.identifier == otherID }),
           !other.entries.isEmpty, !dryRun {
            var undo = RunSummary()
            do { undo = try restoreTargets(app: app, targets: [other], dryRun: false) }
            catch let e as EngineError {
                if case .restoreUnavailable = e {
                    // 另一变体缺 expected（如无溯源条目）——跳过还原，不阻塞
                } else { throw e }
            }
            if undo.wroteAnything {
                summary.lines.append("  [switch] restored previous variant \(otherID) writes")
                summary.patchedBinaries += undo.patchedBinaries
            }
        }

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
                if written > 0, !summary.patchedBinaries.contains(relative) {
                    summary.patchedBinaries.append(relative)   // once per binary: multi-target groups re-sign once
                }
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
        guard let versionEntry = config.entry(build: build) else {
            throw EngineError.unsupportedBuild(build, known: config.versions.count)
        }
        return try restoreTargets(app: app, targets: versionEntry.targets, dryRun: dryRun)
    }

    /// Restore core for an explicit target list. Preflight: every target must
    /// be restorable (all entries carry expected bytes) BEFORE any write.
    @discardableResult
    static func restoreTargets(app: URL, targets: [Config.Target], dryRun: Bool) throws -> RunSummary {
        var summary = RunSummary()
        // Preflight: every target must be restorable.
        for target in targets {
            let unrestorable = target.entries.enumerated().filter { $0.element.expected == nil }
            if !unrestorable.isEmpty {
                throw EngineError.restoreUnavailable(
                    "target \(target.identifier) entries \(unrestorable.map(\.offset)) have no original bytes")
            }
        }
        let grouped = Dictionary(grouping: targets, by: { $0.binary ?? "Contents/MacOS/WeChat" })
        for (relative, group) in grouped.sorted(by: { $0.key < $1.key }) {
            let binary = WeChatApp.binaryURL(app: app, relative: relative)
            summary.lines.append("binary: \(relative)")
            for target in group {
                let inverted = target.entries.map { entry -> Config.PatchEntry in
                    var copy = entry
                    let asm = entry.asm
                    // asm ∈ expected 的条目是「归一化条目」（如 keeptip 在 isRevokemsg
                    // 入口写的恢复型条目）：其 expected[0] 是另一变体的补丁字节而非
                    // 原始字节。恢复目标必须是 asm 本身，否则 restore 会把 silent
                    // 补丁写回去（269602 x64 实证：revoke 先还原、keeptip 再覆盖）。
                    copy.asm = entry.expected!.values.contains(asm) ? asm : entry.expected!.values[0]
                    copy.expected = Config.ExpectedVariants([asm] + entry.expected!.values)
                    return copy
                }
                let outcomes = try Patcher.patch(
                    binary: binary, entries: inverted, identifier: target.identifier, dryRun: dryRun)
                let restored = outcomes.filter { $0 == .written }.count
                let skipped = outcomes.filter { $0 == .alreadyPatched }.count
                summary.wroteAnything = summary.wroteAnything || restored > 0
                if restored > 0, !summary.patchedBinaries.contains(relative) {
                    summary.patchedBinaries.append(relative)
                }
                summary.lines.append("  \(target.identifier): \(restored) restored, \(skipped) already-pristine")
            }
        }
        return summary
    }
}
