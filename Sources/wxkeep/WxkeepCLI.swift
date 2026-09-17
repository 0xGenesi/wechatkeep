import ArgumentParser
import Foundation

struct Wxkeep: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "wxkeep",
        abstract: "WeChatKeep — dual-architecture (arm64 + x86_64) anti-revoke patcher for WeChat 4.x on macOS.",
        version: "0.1.2",
        subcommands: [Versions.self, Patch.self, Restore.self, Locate.self, Verify.self, DoctorCommand.self, UpdateDataCmd.self, ManifestCmd.self, UpdateGuardCommand.self, PrivacyGuardCommand.self, CloneCommand.self]
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

        @Flag(help: "Skip re-signing after patching (debug only — the bundle will be killed on launch).")
        var noResign: Bool = false

        @Option(name: .shortAndLong, help: "Path to signatures.json for the auto-locate fallback")
        var signaturesPath: String?

        enum Variant: String, ExpressibleByArgument { case silent, keeptip }

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            // dry-run only reads bytes from disk — safe while WeChat runs.
            if !dryRun && WeChatApp.isRunning(app: options.app) { throw WeChatApp.AppError.running }
            let config = try Config.load(explicit: options.config)
            let build = try WeChatApp.buildNumber(app: options.app)
            print("build \(build) — variant \(variant.rawValue)\(dryRun ? " — dry run" : "")")
            let onlyList = only?.split(separator: ",").map(String.init)
            let summary: Engine.RunSummary
            if config.entry(build: build) != nil {
                summary = try Engine.patch(
                    app: options.app, build: build, config: config, variant: variant.rawValue,
                    dryRun: dryRun, allowUnverified: allowUnverified, only: onlyList)
            } else {
                // Auto-locate fallback: uncatalogued build → run signature recipes.
                print("build not in catalog — auto-locating via signature recipes…")
                let signatures = try Signatures.load(explicit: signaturesPath)
                guard let synthesized = Engine.autoLocatedEntry(app: options.app, signatures: signatures) else {
                    throw Engine.EngineError.unsupportedBuild(build, known: config.versions.count)
                }
                print("recipes resolved: \(synthesized.targets.map { t in t.identifier }.joined(separator: ", "))")
                summary = try Engine.patch(
                    app: options.app, versionEntry: synthesized, variant: variant.rawValue,
                    dryRun: dryRun, allowUnverified: allowUnverified, only: onlyList)
            }
            summary.lines.forEach { print($0) }
            if !dryRun && summary.wroteAnything && !noResign {
                print("------ Resign ------")
                try Resigner.resign(app: options.app, patchedBinaries: summary.patchedBinaries)
                // restore 语义 = 回到原始；不附带任何偏好写入
            }
            if !dryRun && summary.wroteAnything {
                let hostArch = ProcessInfo.processInfo.environment["PROCESSOR_ARCHITEW6432"] ?? nil
                _ = hostArch
                #if arch(arm64)
                let host = "arm64"
                #else
                let host = "x86_64"
                #endif
                print("本机架构 \(host)：可运行 `wxkeep verify` 行为级确认补丁效果")
            }
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

        @Flag(help: "Skip re-signing after restore (debug only).")
        var noResign: Bool = false

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            if !dryRun && WeChatApp.isRunning(app: options.app) { throw WeChatApp.AppError.running }
            let config = try Config.load(explicit: options.config)
            let build = try WeChatApp.buildNumber(app: options.app)
            print("restore build \(build)\(dryRun ? " — dry run" : "")")
            let summary = try Engine.restore(app: options.app, build: build, config: config, dryRun: dryRun)
            summary.lines.forEach { print($0) }
            if !dryRun && summary.wroteAnything && !noResign {
                print("------ Resign ------")
                try Resigner.resign(app: options.app, patchedBinaries: summary.patchedBinaries)
                // restore 语义 = 回到原始；不附带任何偏好写入
            }
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
                // 本地定位条目写入 config.local.json（与签名目录分离）：
                // locate 派生数据信任域=用户机器，不走 Ed25519 清单门；
                // 否则普通用户改完 config 会被 patch 拒绝且无私钥可重签。
                // 本地定位文件固定在用户级数据目录（永远可写，brew 用户亦然）
                let localURL = Config.userDataURL.appendingPathComponent("config.local.json")
                let backup = localURL.appendingPathExtension("bak." + String(Int(Date().timeIntervalSince1970)))
                if FileManager.default.fileExists(atPath: localURL.path) {
                    try? FileManager.default.copyItem(at: localURL, to: backup)
                }
                var localConfig: Config
                if FileManager.default.fileExists(atPath: localURL.path) {
                    localConfig = try Config(data: Data(contentsOf: localURL), origin: localURL.path)
                } else {
                    localConfig = Config(versions: [])   // 首次定位：本地文件尚不存在
                }
                let existingIdx = localConfig.versions.firstIndex { $0.version == build }
                var versionEntry = existingIdx.map { localConfig.versions[$0] }
                    ?? Config.VersionEntry(version: build, targets: [], note: nil)
                for (identifier, entries) in targets {
                    if let idx = versionEntry.targets.firstIndex(where: { $0.identifier == identifier }) {
                        // keep precise entries; add recipe-derived for arches not present
                        let archs = Set(versionEntry.targets[idx].entries.map(\.arch))
                        versionEntry.targets[idx].entries += entries.filter { !archs.contains($0.arch) }
                    } else {
                        versionEntry.targets.append(Config.Target(
                            identifier: identifier,
                            binary: signatures.recipes.values.first?.binary,
                            entries: entries))
                    }
                }
                if let idx = existingIdx {
                    localConfig.versions[idx] = versionEntry
                } else {
                    localConfig.versions.append(versionEntry)
                }
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(localConfig.versions).write(to: localURL)
                print("appended to \(localURL.path) (backup: \(backup.lastPathComponent))")
                print("next: wxkeep patch --variant silent")
            }
        }
    }

    struct UpdateGuardCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Block WeChat's updater at the preferences layer (no binary changes)")
        static var _commandName: String { "update-guard" }

        enum Action: String, ExpressibleByArgument { case status, off, on }

        @OptionGroup var options: Options

        @Option(help: "status / off (default: guard) / on (restore update checks)")
        var action: Action = .off

        mutating func run() throws {
            switch action {
            case .status:
                let statuses = UpdateGuard.read()
                print(UpdateGuard.render(statuses))
                print(allGuarded ? "更新防护：已开启" : "更新防护：未开启（存在升级弹窗/自动安装风险）")
            case .off:
                // cfprefd 把运行中沙盒 app 的域交给其 agent，外部写入会被丢弃
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError(
                        "WeChat 正在运行，偏好写入会被系统丢弃。请先退出微信（⌘Q）再执行，\n"
                        + "或使用 `wxkeep patch` —— 打补丁流程要求微信退出，会自动附带更新防护。")
                }
                let ok = UpdateGuard.disable()
                print(UpdateGuard.render(UpdateGuard.read()))
                print(ok ? "✓ 更新防护已开启：微信不再检查更新，不会再弹升级窗口"
                        : "✗ 写入未完全生效，请重试或检查权限")
            case .on:
                let ok = UpdateGuard.enable()
                print(ok ? "已恢复更新检查（微信将照常提示新版本）" : "恢复未完全生效，请重试")
            }
        }

        private var allGuarded: Bool { UpdateGuard.allGuarded }
    }

    struct CloneCommand: ParsableCommand {
        static var _commandName: String { "clone" }
        static let configuration = CommandConfiguration(
            abstract: "Clone-based multi-instance (independent data, no binary patching)",
            subcommands: [CloneCreate.self, CloneList.self, CloneRemove.self, CloneLaunch.self])

        @OptionGroup var options: Options

        struct CloneCreate: ParsableCommand {
            static var _commandName: String { "create" }
            static let configuration = CommandConfiguration(abstract: "Create a new WeChat clone")
            @OptionGroup var options: Options
            @Flag(help: "Overwrite an existing clone at the destination") var replace: Bool = false
            mutating func run() throws {
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError("源微信正在运行（复制一致性风险）。退出后重试。")
                }
                let dest = try Clone.create(source: options.app, replace: replace)
                let idx = Clone.list(in: options.app.deletingLastPathComponent())
                    .first { $0.url == dest }?.index ?? 0
                print("✓ 克隆已创建: \(dest.path)")
                print("  独立 bundle ID + 独立数据目录；可正常打开登录第二账号")
                print("  打开: wxkeep clone launch \(idx)")
            }
        }

        struct CloneList: ParsableCommand {
            static var _commandName: String { "list" }
            static let configuration = CommandConfiguration(abstract: "List wxkeep clones")
            @OptionGroup var options: Options
            mutating func run() throws {
                let clones = Clone.list(in: options.app.deletingLastPathComponent())
                if clones.isEmpty { print("无克隆（wxkeep clone 创建）"); return }
                for c in clones {
                    print("  #\(c.index)  \(c.url.lastPathComponent)  \(c.bundleID)")
                }
            }
        }

        struct CloneRemove: ParsableCommand {
            static var _commandName: String { "remove" }
            static let configuration = CommandConfiguration(abstract: "Remove a wxkeep clone")
            @OptionGroup var options: Options
            @Argument(help: "Clone .app 路径或名称（如 'WeChat wxkeep 1.app'）")
            var target: String
            mutating func run() throws {
                let url = Self.resolve(target, in: options.app.deletingLastPathComponent())
                try Clone.remove(url)
                print("✓ 已删除 \(url.lastPathComponent)")
            }
            static func resolve(_ t: String, in dir: URL) -> URL {
                if t.hasSuffix(".app"), FileManager.default.fileExists(atPath: t) {
                    return URL(fileURLWithPath: t)
                }
                let direct = dir.appendingPathComponent(t.hasSuffix(".app") ? t : t + ".app")
                if FileManager.default.fileExists(atPath: direct.path) { return direct }
                if let n = Int(t), let hit = Clone.list(in: dir).first(where: { $0.index == n }) {
                    return hit.url
                }
                return direct
            }
        }

        struct CloneLaunch: ParsableCommand {
            static var _commandName: String { "launch" }
            static let configuration = CommandConfiguration(abstract: "Launch a clone")
            @OptionGroup var options: Options
            @Argument(help: "Clone .app 路径、名称或序号")
            var target: String
            mutating func run() throws {
                let url = Wxkeep.CloneCommand.CloneRemove.resolve(target, in: options.app.deletingLastPathComponent())
                try Clone.launch(url)
                print("已启动 \(url.lastPathComponent)")
            }
        }
    }

    struct PrivacyGuardCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Minimize WeChat telemetry/diagnostic reporting (preferences layer)")
        static var _commandName: String { "privacy-guard" }

        enum Action: String, ExpressibleByArgument { case status, off }

        @OptionGroup var options: Options
        @Option(help: "status / off (default: harden)")
        var action: Action = .off

        mutating func run() throws {
            switch action {
            case .status:
                print(PrivacyGuard.render(PrivacyGuard.read()))
                print(PrivacyGuard.allGuarded ? "隐私加固：已开启" : "隐私加固：未开启")
            case .off:
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError("WeChat 正在运行（偏好写入会被 cfprefd 丢弃）。退出后重试，或随 patch/update-guard 一同执行。")
                }
                let ok = PrivacyGuard.disable()
                print(PrivacyGuard.render(PrivacyGuard.read()))
                print(ok ? "✓ 遥测/诊断上报已最小化" : "✗ 未完全生效，请重试")
            }
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Prove the patch's behavior by calling the patched function out-of-process")

        @OptionGroup var options: Options

        @Option(name: .shortAndLong, help: "Path to signatures.json (verify specs live there)")
        var signatures: String?

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            let config = try Config.load(explicit: options.config)
            let signatures = try Signatures.load(explicit: self.signatures)
            let build = try WeChatApp.buildNumber(app: options.app)

            // Find the x86_64 revoke site: catalog first, recipes otherwise.
            guard let spec = signatures.recipes["revoke_x64"]?.verify else {
                throw ValidationError("no verify spec for revoke_x64 in signatures.json")
            }
            var entries: [Config.PatchEntry]
            var target = config.entry(build: build)?.targets.first { $0.identifier == "revoke" }
            if target == nil {
                guard let synthesized = Engine.autoLocatedEntry(app: options.app, signatures: signatures),
                      let t = synthesized.targets.first(where: { $0.identifier == "revoke" })
                else { throw ValidationError("no revoke site for build \(build)") }
                target = t
            }
            guard let x64Entry = target?.entries.first(where: { $0.arch == .x86_64 }),
                  let addrHex = x64Entry.addr, let va = UInt64(addrHex, radix: 16)
            else { throw ValidationError("no x86_64 revoke entry for build \(build)") }
            entries = [x64Entry]

            let binary = WeChatApp.binaryURL(app: options.app, relative: target?.binary)
            let states = try Patcher.inspect(binary: binary, entries: entries, identifier: "revoke")
            let state = states.first?.state ?? .unknown
            print("site 0x\(String(va, radix: 16, uppercase: true)) — on-disk state: \(state)")

            let results = try Verifier.run(binary: binary, targetVA: va, spec: spec)
            for r in results {
                print("  isRevokemsg(\"\(r.text)\") = \(r.returned ? 1 : 0)")
            }
            if let failure = Verifier.verdict(results: results, spec: spec, state: state) {
                throw ValidationError(String(describing: failure))
            }
            print(state == .pristine
                  ? "✓ behavior matches the PRISTINE expectation (function classifies correctly)"
                  : "✓ behavior matches the PATCHED expectation (classification neutralized)")
        }
    }

    struct UpdateDataCmd: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "update-data",
            abstract: "Fetch the latest signed patch catalog (day-0 support for new builds, no CLI upgrade needed)")

        mutating func run() throws {
            try UpdateData.run()
        }
    }

    struct ManifestCmd: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "manifest",
            abstract: "Verify the signed data manifest (supply-chain check for config/signatures)")

        @Option(name: .shortAndLong, help: "Directory to verify (default: config search path)")
        var dir: String?

        mutating func run() throws {
            let target: URL
            if let dir {
                target = URL(fileURLWithPath: dir)
            } else if let found = Config.locatedDirectory() {
                target = found
            } else {
                target = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            }
            switch Manifest.verify(directory: target) {
            case .verified:
                print("manifest: ✓ verified (\(target.path))")
            case .legacy:
                print("manifest: — no signed manifest in \(target.path) (pre-v0.1.3 data or dev copy)")
            case .invalid(let reason):
                print("manifest: ✗ INVALID — \(reason)")
                throw ExitCode(1)
            }
        }
    }

    struct DoctorCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Read-only health check: build, SIP, AMFI/taskgated kill prediction, patch state")
        static var _commandName: String { "doctor" }

        @OptionGroup var options: Options

        @Flag(help: "Machine-readable output (single-verdict contract)")
        var json: Bool = false

        mutating func run() throws {
            try WeChatApp.validate(options.app)
            let config = try Config.load(explicit: options.config)
            let report = Doctor.run(app: options.app, config: config)
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(report)
                print(String(data: data, encoding: .utf8)!)
            } else {
                print(Doctor.render(report))
            }
        }
    }
}
