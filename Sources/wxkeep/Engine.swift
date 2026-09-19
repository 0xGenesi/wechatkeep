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

    /// 配方名 → catalog target identifier。现役配方全为 revoke*（signatures.json
    /// 的 SSOT），但 locate_update_x64 等工具产出的 update* 配方一旦并入
    /// signatures.json，硬编码 "revoke" 会把它们错标成变体域目标（silent 才应用、
    /// keeptip 漏打）——按名字前缀归类，未知前缀保守归 revoke（现状行为）。
    static func identifier(forRecipeName name: String) -> String {
        let lower = name.lowercased()
        if lower.hasPrefix("update") { return "update" }
        if lower.hasPrefix("multiinstance") { return "multiInstance" }
        return "revoke"
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
            // Recipe(anchor:derive:confirm:) 不抛错（抛错的是 dict 变体）——直接构造
            let recipe = RecipeEngine.Recipe(
                anchor: spec.anchor, derive: spec.derive,
                confirm: spec.confirm.map { $0.split(separator: ";").map(String.init) } ?? [])
            guard let image = try? MachImage(file: binary, arch: spec.arch),
                  let va = try? RecipeEngine.resolve(recipe: recipe, image: image, arch: spec.arch)
            else { continue }
            let entry = Config.PatchEntry(
                arch: spec.arch, addr: String(va, radix: 16), recipe: nil,
                expected: Config.ExpectedVariants(spec.expected),
                asm: spec.asm, source: "recipe:\(name)")
            let identifier = identifier(forRecipeName: name)
            var group = targetsByBinary[relative, default: []]
            if let idx = group.firstIndex(where: { $0.identifier == identifier }) {
                group[idx].entries.append(entry)
            } else {
                group.append(Config.Target(identifier: identifier, binary: spec.binary, entries: [entry]))
            }
            targetsByBinary[relative] = group
        }
        guard !targetsByBinary.isEmpty else { return nil }
        let targets = targetsByBinary.flatMap { $0.value }
        return Config.VersionEntry(version: build, targets: targets,
                                   note: "auto-located via signature recipes")
    }

    /// locate --append 的合并核心（纯函数，便于回归测试）。
    /// 定位产物必须按 identifier+binary 分组落位：同 identifier 不同 binary 的
    /// 条目互不相干——gen0 主程序配方与 wechat.dylib 配方并存时，单键合并会把
    /// 主程序条目塞进 dylib 的 Target（或反之），expected 门就去错误的文件上
    /// 校验，patch 必然 expectedMismatch。命中 identifier+binary 双键的已有
    /// Target 则按 arch 去重追加（精编条目优先，与 Config.merge 同语义）。
    static func mergeLocated(
        _ located: [(binary: String?, identifier: String, entry: Config.PatchEntry)],
        into versionEntry: inout Config.VersionEntry
    ) {
        var groups: [String: (binary: String?, identifier: String, entries: [Config.PatchEntry])] = [:]
        for item in located {
            groups["\(item.identifier)|\(item.binary ?? "Contents/MacOS/WeChat")",
                   default: (item.binary, item.identifier, [])]
                .entries.append(item.entry)
        }
        for (_, group) in groups.sorted(by: { $0.key < $1.key }) {
            if let idx = versionEntry.targets.firstIndex(where: {
                $0.identifier == group.identifier
                && ($0.binary ?? "Contents/MacOS/WeChat") == (group.binary ?? "Contents/MacOS/WeChat")
            }) {
                let archs = Set(versionEntry.targets[idx].entries.map(\.arch))
                versionEntry.targets[idx].entries += group.entries.filter { !archs.contains($0.arch) }
            } else {
                versionEntry.targets.append(Config.Target(
                    identifier: group.identifier, binary: group.binary, entries: group.entries))
            }
        }
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

        // --only 先行过滤：`--only update` 不得触碰任何 revoke 变体的字节——
        // 否则下面的「变体切换还原」会把另一个变体默默撤防（过滤前跑就会如此）。
        if let only, !only.isEmpty {
            selected = selected.filter { only.contains($0.identifier) }
            guard !selected.isEmpty else {
                throw EngineError.variantUnavailable("no matching targets for --only \(only.joined(separator: ","))")
            }
        }

        // 变体切换：先还原另一变体的写入（幂等），再应用本变体。
        // 否则 silent 的 x64 补丁会与 keeptip 并存，静默语义覆盖 keeptip。
        // 仅当本变体目标在本次作用域内（selected 含 variantID）才还原。
        let variantID = variant == "keeptip" ? "revoke-keeptip" : "revoke"
        let otherID = variant == "silent" ? "revoke-keeptip" : "revoke"
        if selected.contains(where: { $0.identifier == variantID }),
           let other = versionEntry.targets.first(where: { $0.identifier == otherID }),
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

        let grouped = Dictionary(grouping: selected, by: { $0.binary ?? "Contents/MacOS/WeChat" })
        do {
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
        } catch {
            // 半套态防线（与 runtime install 回滚同哲学）：本 run 已写入字节、
            // 却在后续 target 上失败抛错 → 不走正常重签，bundle 处于「字节已改
            // + 旧签名」的启动必崩态。尽力补一次重签：成功则微信可启动、doctor
            // 会把半套态如实报成 mixed；重签也失败则给人工恢复路径后再抛原错。
            if !dryRun && summary.wroteAnything, !summary.patchedBinaries.isEmpty {
                do {
                    try Resigner.resign(app: app, patchedBinaries: summary.patchedBinaries)
                    summary.lines.append("  [recovery] partial write re-signed — bundle launches; "
                                         + "run `wxkeep doctor` (expect mixed) and re-patch")
                } catch {
                    summary.lines.append("  [recovery] resign failed — run `sudo wxkeep restore` BEFORE launching WeChat")
                }
            }
            throw error
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

    /// Bytes `restore` writes back for an entry: `expected[0]` verbatim when
    /// concrete; when its wildcards start beyond the original asm span, only
    /// the asm-length prefix is needed — a patch never writes past
    /// `asm.count`, so the tail on disk already IS the original tail (the
    /// branch-flip form `expected 84C00F84???????? / asm 30C0` restores by
    /// writing `84C0` alone). Nil = not restorable from catalog data.
    static func restoreAsm(for entry: Config.PatchEntry) -> String? {
        guard let values = entry.expected?.values, let first = values.first else { return nil }
        if values.contains(entry.asm) { return entry.asm }   // normalized entry (asm ∈ expected)
        guard let pattern = ExpectedPattern(spec: first) else { return first }   // pre-validation data
        // 全具体时用物化字节而非原样透传 spec：带冗余 `:maskFFFF` 后缀的
        // 全具体条目若把后缀一起返回，下游 Data(hex:) 会解析失败。
        if let full = pattern.concretePrefix(pattern.byteCount) { return full.hexUppercase }
        guard let asm = Data(hex: entry.asm) else { return nil }
        return pattern.concretePrefix(asm.count)?.hexUppercase
    }

    /// Restore core for an explicit target list. Preflight: every target must
    /// be restorable (all entries carry materializable original bytes) BEFORE
    /// any write.
    @discardableResult
    static func restoreTargets(app: URL, targets: [Config.Target], dryRun: Bool) throws -> RunSummary {
        var summary = RunSummary()
        // Preflight: every target must be restorable.
        for target in targets {
            let unrestorable = target.entries.enumerated().filter {
                $0.element.expected == nil || restoreAsm(for: $0.element) == nil
            }
            if !unrestorable.isEmpty {
                throw EngineError.restoreUnavailable(
                    "target \(target.identifier) entries \(unrestorable.map(\.offset)) have no "
                    + "materializable original bytes (missing expected, or wildcards reach into the written span)")
            }
        }
        let grouped = Dictionary(grouping: targets, by: { $0.binary ?? "Contents/MacOS/WeChat" })
        for (relative, group) in grouped.sorted(by: { $0.key < $1.key }) {
            let binary = WeChatApp.binaryURL(app: app, relative: relative)
            summary.lines.append("binary: \(relative)")
            for target in group {
                let inverted = target.entries.map { entry -> Config.PatchEntry in
                    var copy = entry
                    // asm ∈ expected 的条目是「归一化条目」（如 keeptip 在 isRevokemsg
                    // 入口写的恢复型条目）：其 expected[0] 是另一变体的补丁字节而非
                    // 原始字节。恢复目标必须是 asm 本身，否则 restore 会把 silent
                    // 补丁写回去（269602 x64 实证：revoke 先还原、keeptip 再覆盖）。
                    // 通配条目只物化 asm 长度的前缀（见 restoreAsm 注释）。
                    copy.asm = restoreAsm(for: entry)!   // preflight 保证非空
                    copy.expected = Config.ExpectedVariants([entry.asm] + entry.expected!.values)
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
