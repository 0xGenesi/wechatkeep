import ArgumentParser
import Foundation

struct Wxkeep: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "wxkeep",
        abstract: "WeChatKeep — dual-architecture (arm64 + x86_64) anti-revoke patcher for WeChat 4.x on macOS.",
        version: "0.2.0",
        subcommands: [Versions.self, Patch.self, Restore.self, Locate.self, Verify.self, DoctorCommand.self, UpdateDataCmd.self, ManifestCmd.self, UpdateGuardCommand.self, PrivacyGuardCommand.self, CloneCommand.self, RuntimeCommand.self]
    )

    struct Options: ParsableArguments {
        @Option(name: [.customShort("a"), .long], help: "Path of WeChat.app", transform: {
            let url = URL(fileURLWithPath: $0)
            guard FileManager.default.fileExists(atPath: url.appendingPathComponent("Contents/Info.plist").path)
            else { throw ValidationError("\($0) is not an app bundle") }
            return url
        })
        var app: URL = URL(fileURLWithPath: "/Applications/WeChat.app")

        @Option(name: [.customShort("c"), .long], help: "Path to config.json (default search: ./, user data dir, next to the executable)")
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
            let version = WeChatApp.marketingVersion(app: options.app) ?? "?"
            print("------ Installed ------")
            print("build \(build) (v\(version)) at \(options.app.path)")
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
            let version = WeChatApp.marketingVersion(app: options.app).map { " (v\($0))" } ?? ""
            print("build \(build)\(version) — variant \(variant.rawValue)\(dryRun ? " — dry run" : "")")
            let onlyList = only?.split(separator: ",").map(String.init)
            let summary: Engine.RunSummary
            do {
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
            } catch {
                Wxkeep.printPermissionHintIfTCC(error)
                throw error
            }
            summary.lines.forEach { print($0) }
            if !dryRun && summary.wroteAnything && !noResign {
                print("------ Resign ------")
                do {
                    try Resigner.resign(app: options.app, patchedBinaries: summary.patchedBinaries)
                } catch {
                    Wxkeep.printPermissionHintIfTCC(error)
                    throw error
                }
                // restore 语义 = 回到原始；不附带任何偏好写入
            }
            if !dryRun && summary.wroteAnything {
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

    /// macOS 14+ 的「App 管理」TCC 权限：root 也绕不过（社区高频卡点，
    /// sunnyyoung #1025 / zengtianli user-blockers）。写 /Applications 下的
    /// App 报权限错误时，把指引打在人话层面再抛原错误。
    /// patch / restore / runtime install|remove 等写盘命令统一接入。
    static func printPermissionHintIfTCC(_ error: Error) {
        let ns = error as NSError
        let denied = (ns.domain == NSCocoaErrorDomain
                      && (ns.code == CocoaError.Code.fileWriteNoPermission.rawValue
                          || ns.code == CocoaError.Code.fileReadNoPermission.rawValue))
            || (ns.domain == NSPOSIXErrorDomain && (ns.code == Int(EPERM) || ns.code == Int(EACCES)))
        guard denied else { return }
        print("⚠️ 写入被系统拒绝（Permission denied）。macOS 14+ 即使 sudo 也会被「App 管理」"
            + "隐私权限拦截：系统设置 → 隐私与安全性 → App 管理 → 打开你所用的终端 App"
            + "（Terminal/iTerm/Warp 等），然后重试。")
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
            let summary: Engine.RunSummary
            do {
                summary = try Engine.restore(app: options.app, build: build, config: config, dryRun: dryRun)
            } catch {
                Wxkeep.printPermissionHintIfTCC(error)
                throw error
            }
            summary.lines.forEach { print($0) }
            if !dryRun && summary.wroteAnything && !noResign {
                print("------ Resign ------")
                do {
                    try Resigner.resign(app: options.app, patchedBinaries: summary.patchedBinaries)
                } catch {
                    Wxkeep.printPermissionHintIfTCC(error)
                    throw error
                }
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
            // 定位产物带 binary 归属：合并时按 binary 分组落进各自的 Target
            // （Engine.mergeLocated），不再池化进单组——gen0 主程序配方与
            // wechat.dylib 配方并存时，池化会把 binary 字段写错文件。
            var located: [(binary: String?, entry: Config.PatchEntry)] = []
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
                    located.append((spec.binary, entry))
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
                // 信任域分流：缺省写用户级数据目录（用户派生数据，免签名）；
                // 显式 --config 时写该文件（CI/开发者管理签名与提交的路径）。
                let localURL: URL
                if let explicit = options.config {
                    localURL = URL(fileURLWithPath: explicit)
                } else {
                    localURL = Config.userDataURL.appendingPathComponent("config.local.json")
                }
                let backup = localURL.appendingPathExtension("bak." + String(Int(Date().timeIntervalSince1970)))
                if FileManager.default.fileExists(atPath: localURL.path) {
                    try? FileManager.default.copyItem(at: localURL, to: backup)
                    // 保留策略：config.local.json.bak.* 只留最新 3 个
                    let dir = localURL.deletingLastPathComponent()
                    if let entries = try? FileManager.default.contentsOfDirectory(atPath: dir.path) {
                        let baks = entries.filter { $0.hasPrefix(localURL.lastPathComponent + ".bak.") }
                            .sorted(by: >)
                        for stale in baks.dropFirst(3) {
                            try? FileManager.default.removeItem(atPath: dir.appendingPathComponent(stale).path)
                        }
                    }
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
                Engine.mergeLocated(located, into: &versionEntry)
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
                if UpdateGuard.rewrittenByApp {
                    print("更新防护：✗ 已被微信改回（4.1.13+ 启动时重写更新开关的已知行为）。"
                        + "偏好层挡不住自动更新——可靠的防护是 `wxkeep patch` 附带的字节级目标（可用构建）；"
                        + "若微信已升级，请重跑 `wxkeep doctor`。")
                } else {
                    print(allGuarded ? "更新防护：已开启（偏好层；4.1.13+ 前两键可能被微信改回，见 keys 说明）"
                          : "更新防护：未开启（存在升级弹窗/自动安装风险）")
                }
            case .off:
                // cfprefd 把运行中沙盒 app 的域交给其 agent，外部写入会被丢弃
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError(
                        "WeChat 正在运行，偏好写入会被系统丢弃。请先退出微信（⌘Q）再执行，\n"
                        + "或使用 `wxkeep patch` —— 打补丁流程要求微信退出，会自动附带更新防护。")
                }
                let ok = UpdateGuard.disable()
                print(UpdateGuard.render(UpdateGuard.read()))
                if ok {
                    print("✓ 三个偏好键已写入（SUSendProfileInfo 实测可长期存活）")
                    print("  注意：微信 4.1.13+ 会在启动时把 SUEnableAutomaticChecks / SUAutomaticallyUpdate"
                        + " 改回「开」——本层是 best-effort。真正可靠的更新防护随 `wxkeep patch` 附带；"
                        + "若微信之后自动升级，重跑 `wxkeep doctor`。")
                } else {
                    print("✗ 写入未完全生效，请重试或检查权限")
                }
            case .on:
                let ok = UpdateGuard.enable()   // enable 内部清除改回检测标记
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

    struct RuntimeCommand: ParsableCommand {
        static var _commandName: String { "runtime" }
        static let configuration = CommandConfiguration(
            abstract: "Runtime component (optional): inject a support dylib into WeChat",
            subcommands: [RuntimeStatus.self, RuntimeHooks.self, RuntimeInstall.self, RuntimeRemove.self])

        static func mainExecURL(_ app: URL) -> URL {
            WeChatApp.binaryURL(app: app, relative: "Contents/MacOS/WeChat")
        }
        static func frameworkDylibURL(_ app: URL) -> URL {
            WeChatApp.binaryURL(app: app, relative: "Contents/Frameworks/wxkeep_runtime.dylib")
        }
        static let lcPath = "@executable_path/../Frameworks/wxkeep_runtime.dylib"

        struct RuntimeHooks: ParsableCommand {
            static var _commandName: String { "hooks" }
            static let configuration = CommandConfiguration(
                abstract: "Refresh the hooks address table in runtime.json (effective on next WeChat launch)")
            @OptionGroup var options: Options
            mutating func run() throws {
                do {
                    let rows = try RuntimeConfig.mergeKnownHooks(into: RuntimeConfig.url())
                    var builds: [String] = []
                    for r in rows where !builds.contains(r.build) { builds.append(r.build) }
                    print("✓ hooks: \(rows.count) 行（构建 \(builds.joined(separator: "/"))）")
                    print("  \(RuntimeConfig.url().path)")
                    print("  微信下次启动生效——已装运行时组件时无需重装 dylib")
                } catch {
                    print("⚠️ runtime.json hooks 写入失败: \(error.localizedDescription)")
                    throw error
                }
            }
        }

        struct RuntimeStatus: ParsableCommand {
            static var _commandName: String { "status" }
            @OptionGroup var options: Options
            mutating func run() throws {
                try WeChatApp.validate(options.app)
                let main = RuntimeCommand.mainExecURL(options.app)
                let data = try Data(contentsOf: main)
                let injected = MachOInjector.isInjectedAnySlice(data: data, path: lcPath)
                let dylib = RuntimeCommand.frameworkDylibURL(options.app)
                let dylibExists = FileManager.default.fileExists(atPath: dylib.path)
                let marker = RuntimeConfig.groupContainerURL().appendingPathComponent("runtime.marker")
                let markerText = FileManager.default.fileExists(atPath: marker.path)
                    ? (try? String(contentsOf: marker, encoding: .utf8)) : nil
                let markerExists = markerText != nil
                print("LC_LOAD_DYLIB 注入: \(injected ? "是" : "否")")
                print("runtime dylib:     \(dylibExists ? "存在" : "缺失") (\(dylib.path))")
                print("加载标记:          \(markerExists ? "已加载（上次启动）" : "无记录")")
                // runtime.json 在微信 App Group 容器（dylib 沙盒内读同一路径），
                // plist 格式——与 RuntimeConfig.mergeKnownHooks 同源同格式。
                let cfg = (try? PropertyListSerialization.propertyList(
                    from: Data(contentsOf: RuntimeConfig.url()),
                    options: [], format: nil)) as? [String: Any]
                if let hooks = cfg?["hooks"] as? [[String: Any]] {
                    let builds = Set(hooks.compactMap { $0["build"] as? String })
                        .sorted().joined(separator: "/")
                    print("hooks 地址表:      \(hooks.count) 行（\(builds)）")
                    let currentBuild = (try? WeChatApp.buildNumber(app: options.app)) ?? "?"
                    let rowsForBuild = hooks.filter { ($0["build"] as? String) == currentBuild }
                    let matchNote = rowsForBuild.isEmpty
                        ? "无地址行——hook 不会武装（新构建需 derive_runtime_hooks 产出数据）"
                        : "\(rowsForBuild.count) 行匹配（\(rowsForBuild.compactMap { $0["arch"] as? String }.joined(separator: "+"))）"
                    print("当前构建 \(currentBuild):    \(matchNote)")
                } else {
                    print("hooks 地址表:      无（dylib 用内置表，仅 270099 x64）")
                }
                if let tip = cfg?["tip_text"] as? String, !tip.isEmpty {
                    print("自定义文案:        \(tip)")
                } else {
                    print("自定义文案:        未配置（无 tip_text 则 hook 只武装不改写）")
                }
                // hook 实际武装状态来自 marker 的 mr2= 字段（dylib 每次启动
                // 回写）——「已启用」只代表注入在位；构建无匹配地址行/序言
                // 不符时 dylib 加载但 hook 不武装，必须显式区分。
                let armed = markerText?.contains("mr2=hook-armed") ?? false
                let hookState = !markerExists
                    ? "未知（无启动记录）"
                    : (armed ? "已武装（对已匹配构建生效）"
                             : "未武装（当前构建无匹配地址行或序言不符）")
                print("hook 武装:         \(hookState)")
                let state = injected && dylibExists ? (markerExists ? "已启用" : "已注入（启动微信后生效）") : "未启用"
                print("整体:              \(state)")
            }
        }

        /// runtime dylib 搜索序（返回候选列表，第一个存在者胜出）：
        /// 1. 显式 --dylib（绝对或相对 cwd）
        /// 2. 环境变量 WXKEEP_RUNTIME_DYLIB
        /// 3. brew 布局：<Cellar>/wxkeep/<v>/lib/libwxkeep_runtime.dylib
        ///    （/usr/local/bin/wxkeep 是符号链接，resolve 后 ../lib 命中）
        /// 4. 可执行文件同目录（随手放置）
        /// 5. 开发构建：cwd/.build/release/
        static func dylibSearchOrder(
            explicit: String?, env: String?, exePath: String, cwd: String
        ) -> [String] {
            var c: [String] = []
            if let explicit, !explicit.isEmpty { c.append(explicit) }
            if let env, !env.isEmpty { c.append(env) }
            let bin = URL(fileURLWithPath: exePath).resolvingSymlinksInPath()
                .deletingLastPathComponent()
            c.append(bin.deletingLastPathComponent()
                .appendingPathComponent("lib/libwxkeep_runtime.dylib").path)
            c.append(bin.appendingPathComponent("libwxkeep_runtime.dylib").path)
            c.append(URL(fileURLWithPath: ".build/release/libwxkeep_runtime.dylib",
                         relativeTo: URL(fileURLWithPath: cwd)).path)
            return c
        }

        static func resolveDylibPath(explicit: String?) -> String? {
            dylibSearchOrder(
                explicit: explicit,
                env: ProcessInfo.processInfo.environment["WXKEEP_RUNTIME_DYLIB"],
                exePath: CommandLine.arguments[0],
                cwd: FileManager.default.currentDirectoryPath
            ).first { FileManager.default.fileExists(atPath: $0) }
        }

        struct RuntimeInstall: ParsableCommand {
            static var _commandName: String { "install" }
            static let configuration = CommandConfiguration(abstract: "Install the runtime dylib into WeChat (requires WeChat quit)")
            @OptionGroup var options: Options
            @Option(help: "Path of the built libwxkeep_runtime.dylib (default: search brew lib/ → exe dir → .build/release)")
            var dylib: String?
            mutating func run() throws {
                try WeChatApp.validate(options.app)
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError("WeChat 正在运行。退出后重试。")
                }
                let fm = FileManager.default
                guard let dylib = resolveDylibPath(explicit: dylib) else {
                    throw ValidationError(
                        "runtime dylib 未找到。搜索序：--dylib 显式路径 → $WXKEEP_RUNTIME_DYLIB → "
                        + "brew lib/ → 可执行文件同目录 → .build/release/。"
                        + "brew 用户升级到 ≥0.2.0 后自带；源码用户先 swift build -c release")
                }
                let main = RuntimeCommand.mainExecURL(options.app)
                let backup = try Backup.make(binary: main)
                print("backup: \(backup.lastPathComponent)")

                var data = try Data(contentsOf: main)
                do {
                    try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: lcPath)
                    try data.write(to: main)
                } catch {
                    Wxkeep.printPermissionHintIfTCC(error)
                    throw error
                }
                // 写盘后重读验证（2026-09-18 事故防线：LC 必须真的在场，
                // 否则 dylib 装了也永远不加载——静默失效比失败更危险）
                let verifyData = try Data(contentsOf: main)
                guard MachOInjector.isInjectedAnySlice(data: verifyData, path: lcPath) else {
                    try? Data(contentsOf: backup).write(to: main)
                    throw ValidationError("LC_LOAD_DYLIB 写入未生效（已回滚备份）——请汇报此问题")
                }

                let dest = RuntimeCommand.frameworkDylibURL(options.app)
                do {
                    try fm.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
                    if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
                    try fm.copyItem(at: URL(fileURLWithPath: dylib), to: dest)
                    // 子组件先签：主程序 codesign 的验证会检查 bundle 内 dylib 的签名状态
                    _ = Shell.run("/usr/bin/codesign", ["--force", "--sign", "-", dest.path])
                    try Resigner.resign(app: options.app,
                                        patchedBinaries: ["Contents/MacOS/WeChat",
                                                          "Contents/Frameworks/wxkeep_runtime.dylib"])
                } catch {
                    // LC 已注入但 dylib 拷贝/重签失败 = 下次启动 dyld 找不到库必崩的
                    // 混合态——回滚主程序并尽力清掉已拷入的 dylib，保持原子性。
                    Wxkeep.printPermissionHintIfTCC(error)
                    try? Data(contentsOf: backup).write(to: main)
                    try? fm.removeItem(at: dest)
                    throw error
                }
                print("✓ runtime 已注入（微信下次启动时加载）")
                // hooks 地址表随装写入 runtime.json（新构建 day-0 数据通道，
                // 详见 RuntimeConfig 注释）；tip_text/rewrite_self 不在管理面，
                // 用户手写的值原样保留。
                do {
                    let rows = try RuntimeConfig.mergeKnownHooks(into: RuntimeConfig.url())
                    var builds: [String] = []
                    for r in rows where !builds.contains(r.build) { builds.append(r.build) }
                    print("  hooks: \(rows.count) 行（runtime.json，构建 \(builds.joined(separator: "/"))）")
                    print("  文案: 编辑 \(RuntimeConfig.url().path) 的 tip_text（支持 {from} 占位符）")
                } catch {
                    print("  ⚠️ runtime.json hooks 写入失败: \(error.localizedDescription)")
                    print("     dylib 将回落内置地址表（当前构建仍可用）")
                }
                print("  验证: 启动微信后运行 wxkeep runtime status")
                print("  移除: wxkeep runtime remove")
            }
        }

            struct RuntimeRemove: ParsableCommand {
            static var _commandName: String { "remove" }
            static let configuration = CommandConfiguration(abstract: "Remove the runtime dylib and its load command")
            @OptionGroup var options: Options
            mutating func run() throws {
                try WeChatApp.validate(options.app)
                if WeChatApp.isRunning(app: options.app) {
                    throw ValidationError("WeChat 正在运行。退出后重试。")
                }
                let main = RuntimeCommand.mainExecURL(options.app)
                let backup = try Backup.make(binary: main)
                var data = try Data(contentsOf: main)
                var lcWasPresent = true
                do {
                    do {
                        try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: lcPath)
                    } catch MachOInjector.InjectorError.loadCommandNotFound {
                        // LC 本就不在场（历史半装态的孤儿 dylib）：删除 dylib 无
                        // 启动风险（无引用者），主程序一字节不动，仍走清理路径。
                        lcWasPresent = false
                    }
                    if lcWasPresent {
                        // 内存态先验证：LC 真的没了才落盘
                        guard !MachOInjector.isInjectedAnySlice(data: data, path: lcPath) else {
                            throw ValidationError("LC_LOAD_DYLIB 移除未生效（遍历校验失败）——已中止，dylib 保留")
                        }
                        try data.write(to: main)
                    }
                } catch {
                    Wxkeep.printPermissionHintIfTCC(error)
                    throw error
                }
                if lcWasPresent {
                    // 落盘后重读验证（2026-09-18 事故防线：LC 未清零时删除 dylib
                    // 文件 = 下次启动必崩。失败即回滚备份，dylib 文件原样保留）
                    let verifyData = try Data(contentsOf: main)
                    guard !MachOInjector.isInjectedAnySlice(data: verifyData, path: lcPath) else {
                        try? Data(contentsOf: backup).write(to: main)
                        throw ValidationError("LC_LOAD_DYLIB 移除写盘未生效（已回滚备份）——请汇报此问题")
                    }
                }
                let dylib = RuntimeCommand.frameworkDylibURL(options.app)
                try? FileManager.default.removeItem(at: dylib)
                if lcWasPresent {
                    try Resigner.resign(app: options.app, patchedBinaries: ["Contents/MacOS/WeChat"])
                }
                print(lcWasPresent
                      ? "✓ runtime 已移除（备份: \(backup.lastPathComponent)）"
                      : "✓ LC 未注入，孤儿 dylib 已清理（主程序未改动）")
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
