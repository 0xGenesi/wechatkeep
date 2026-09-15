import ArgumentParser
import Foundation

@main
struct Wxkeep: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "wxkeep",
        abstract: "WeChatKeep — dual-architecture (arm64 + x86_64) anti-revoke patcher for WeChat 4.x on macOS.",
        version: "0.1.0-dev",
        subcommands: [Versions.self, Patch.self, Restore.self, Locate.self, Verify.self, Doctor.self]
    )

    struct Options: ParsableArguments {
        @Option(name: [.customShort("a"), .long], help: "Path of WeChat.app", transform: {
            let url = URL(fileURLWithPath: $0)
            guard FileManager.default.fileExists(atPath: url.appendingPathComponent("Contents/Info.plist").path)
            else { throw ValidationError("\($0) is not an app bundle") }
            return url
        })
        var app: URL = URL(fileURLWithPath: "/Applications/WeChat.app")

        @Option(name: [.customShort("c"), .long], help: "Path to config.json (default: ./config.json, else next to the executable)")
        var config: String?
    }
}

// MARK: - versions

extension Wxkeep {
    struct Versions: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show installed build and all catalog builds")

        @OptionGroup var options: Options

        mutating func run() throws {
            let config = try Config.load(explicit: options.config)
            let build = try WeChatApp.buildNumber(app: options.app)
            print("------ Installed ------")
            print("build \(build) at \(options.app.path)")
            print("------ Catalog (\(config.versions.count) builds) ------")
            let known = config.versions.contains { $0.version == build }
            print(known ? "(installed build is in the catalog)" : "(installed build is NOT in the catalog — run `wxkeep locate`)")
            for entry in config.versions {
                let marks = entry.targets.map(\.identifier).joined(separator: ",")
                let quarantine = entry.targets.flatMap(\.entries).contains { $0.expected == nil }
                    ? "  [unverified: lacks expected bytes]" : ""
                print("  \(entry.version)  \(marks)\(quarantine)")
            }
        }
    }
}

// MARK: - patch

extension Wxkeep {
    struct Patch: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Patch WeChat (anti-revoke + update block)")

        @OptionGroup var options: Options

        @Option(help: "silent (default): revoked messages stay, no tip. keeptip: keep the recall tip where supported.")
        var variant: Variant = .silent

        @Flag(help: "Read and verify everything, write nothing.")
        var dryRun: Bool = false

        @Flag(help: "Allow entries without `expected` provenance bytes (quarantined by default).")
        var allowUnverified: Bool = false

        @Option(name: [.customShort("o"), .long], help: "Comma-separated subset of targets (e.g. revoke,update)")
        var only: String?

        /// Resigning lands in M3. Until then writing into a real bundle without
        /// this acknowledgement is refused — an unresigned patched bundle is
        /// killed on launch with Code Signature Invalid.
        @Flag(help: "Acknowledge that resigning is NOT performed in this build; patch anyway.")
        var ackNoResign: Bool = false

        enum Variant: String, ExpressibleByArgument { case silent, keeptip }

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            // dry-run only reads bytes from disk — safe while WeChat runs.
            if !dryRun && WeChatApp.isRunning(app: options.app) { throw WeChatApp.AppError.running }
            if !options.app.hasDirectoryPath || options.app.path.hasPrefix("/Applications") {
                guard dryRun || ackNoResign else {
                    throw ValidationError(
                        "this build does not re-sign the app yet (M3). Patching without re-signing breaks the bundle\n"
                        + "signature and WeChat will be killed at launch. Pass --ack-no-resign to proceed anyway,\n"
                        + "or use --dry-run.")
                }
            }
            let config = try Config.load(explicit: options.config)
            let build = try WeChatApp.buildNumber(app: options.app)
            print("build \(build) — variant \(variant.rawValue)\(dryRun ? " — dry run" : "")")
            let onlyList = only?.split(separator: ",").map(String.init)
            let summary = try Engine.patch(
                app: options.app, build: build, config: config, variant: variant.rawValue,
                dryRun: dryRun, allowUnverified: allowUnverified, only: onlyList)
            summary.lines.forEach { print($0) }
            print(dryRun ? "dry run complete — nothing written" : "done")
        }
    }
}

// MARK: - restore

extension Wxkeep {
    struct Restore: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Write every patch point back to its original bytes")

        @OptionGroup var options: Options

        @Flag(help: "Verify only, write nothing.")
        var dryRun: Bool = false

        @Flag(help: "Acknowledge that re-signing is NOT performed in this build (M3).")
        var ackNoResign: Bool = false

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            if !dryRun && WeChatApp.isRunning(app: options.app) { throw WeChatApp.AppError.running }
            if options.app.path.hasPrefix("/Applications") {
                guard dryRun || ackNoResign else {
                    throw ValidationError("restore leaves the bundle ad-hoc-unresigned in this build (M3). Pass --ack-no-resign or --dry-run.")
                }
            }
            let config = try Config.load(explicit: options.config)
            let build = try WeChatApp.buildNumber(app: options.app)
            print("restore build \(build)\(dryRun ? " — dry run" : "")")
            let summary = try Engine.restore(app: options.app, build: build, config: config, dryRun: dryRun)
            summary.lines.forEach { print($0) }
            print(dryRun ? "dry run complete — nothing written" : "done")
        }
    }
}

// MARK: - M2/M3 placeholders (stable CLI surface)

extension Wxkeep {
    struct Locate: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Auto-locate patch points for the installed build via signature recipes")

        @OptionGroup var options: Options

        @Option(name: .shortAndLong, help: "Path to signatures.json (default: ./signatures.json or next to the executable)")
        var signatures: String?

        @Flag(help: "Append derived entries to config.json (backed up first)")
        var append: Bool = false

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            let build = try WeChatApp.buildNumber(app: options.app)
            let signatures = try Signatures.load(explicit: self.signatures)
            print("build \(build) — \(signatures.recipes.count) recipes")

            var derived: [Config.PatchEntry] = []
            var targets: [String: [Config.PatchEntry]] = [:]
            for (name, spec) in signatures.recipes.sorted(by: { $0.key < $1.key }) {
                let binary = WeChatApp.binaryURL(app: options.app, relative: spec.binary)
                guard FileManager.default.fileExists(atPath: binary.path) else {
                    print("  [\(name)] binary missing: \(spec.binary ?? "-") — skipped")
                    continue
                }
                let recipe = RecipeEngine.Recipe(
                    anchor: spec.anchor, derive: spec.derive,
                    confirm: spec.confirm.map { $0.split(separator: ";").map(String.init) } ?? [])
                do {
                    let image = try MachImage(file: binary, arch: spec.arch)
                    let va = try RecipeEngine.resolve(recipe: recipe, image: image, arch: spec.arch)
                    print("  [\(name)] ✓ site 0x\(String(va, radix: 16, uppercase: true)) expected \(spec.expected)")
                    let entry = Config.PatchEntry(
                        arch: spec.arch, addr: String(va, radix: 16), recipe: nil,
                        expected: Config.ExpectedVariants(spec.expected),
                        asm: spec.asm, source: "recipe:\(name)")
                    derived.append(entry)
                    targets["revoke", default: []].append(entry)
                } catch {
                    print("  [\(name)] — \(error)")
                }
            }
            guard !derived.isEmpty else {
                print("no recipe matched this build (new signature generation — needs human analysis)")
                return
            }
            if append {
                let configPath = options.config ?? "config.json"
                let url = URL(fileURLWithPath: configPath)
                guard FileManager.default.fileExists(atPath: configPath) else {
                    throw ValidationError("config not found at \(configPath) — pass --config")
                }
                let backup = url.appendingPathExtension("bak." + String(Int(Date().timeIntervalSince1970)))
                try? FileManager.default.copyItem(at: url, to: backup)
                var config = try Config.load(explicit: configPath)
                var versionEntry = config.entry(build: build)
                if versionEntry == nil {
                    versionEntry = Config.VersionEntry(version: build, targets: [], note: nil)
                    config.versions.insert(versionEntry!, at: 0)
                }
                for (identifier, entries) in targets {
                    if let idx = versionEntry!.targets.firstIndex(where: { $0.identifier == identifier }) {
                        // keep precise entries; add recipe-derived for arches not present
                        let archs = Set(versionEntry!.targets[idx].entries.map(\.arch))
                        versionEntry!.targets[idx].entries += entries.filter { !archs.contains($0.arch) }
                    } else {
                        versionEntry!.targets.append(Config.Target(
                            identifier: identifier,
                            binary: signatures.recipes.values.first?.binary,
                            entries: entries))
                    }
                }
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(config.versions).write(to: url)
                print("appended to \(configPath) (backup: \(backup.lastPathComponent))")
                print("next: sudo wxkeep patch --variant silent")
            }
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Behaviorally verify patched functions out-of-process (M2)")
        @OptionGroup var options: Options
        mutating func run() throws {
            throw ValidationError("verify arrives in M2 (behavioral test bench).")
        }
    }

    struct Doctor: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Read-only health check: build, SIP, signature, AMFI/taskgated risk (M3)")
        @OptionGroup var options: Options
        mutating func run() throws {
            throw ValidationError("doctor arrives in M3 (incl. the macOS 15 AMFI pre-check).")
        }
    }
}
