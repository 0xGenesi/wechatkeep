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
            abstract: "Auto-locate patch points for an uncatalogued build (M2)")
        @OptionGroup var options: Options
        mutating func run() throws {
            throw ValidationError("locate arrives in M2 (recipe engine). Use tools/ scripts meanwhile.")
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
