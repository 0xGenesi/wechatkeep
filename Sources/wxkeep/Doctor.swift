import Foundation
import CryptoKit

/// Read-only health check: build, SIP, the exclusive AMFI/taskgated kill
/// prediction, signature/entitlements, patch state — with ONE verdict
/// computed in exactly one place (the JSON contract future GUIs decode).
struct Doctor {
    // MARK: - Report model (the --json contract)

    struct Report: Codable {
        let overall: String
        let nativeArch: String
        let build: String
        /// Marketing version (CFBundleShortVersionString, e.g. "4.1.15"); "" unknown.
        var appVersion: String = ""
        let appPath: String
        let configKnown: Bool
        let configTargets: [String]
        let sip: String
        let amfiRisk: AmfiRisk?
        let running: Bool
        let writable: Bool
        let signature: String
        let entitlementsOk: Bool
        let entitlementKeyCount: Int
        let restrictedEntitlements: Bool
        let patchStates: [String: String]   // identifier → patched/pristine/mixed/unknown（仅本机架构切片）
        let manifest: String?              // verified/legacy/invalid:<reason>（数据供应链）
        /// nil = 无残留；否则为未确认写入事务的摘要（kind + 起始时间）。
        var journal: String? = nil
        let verdicts: [String]
        let nextCommand: String?
        // runtime 组件（可选功能）。nil = 无启动记录（marker 缺失）——
        // 注入在位但微信尚未启动过时无法判定武装与否。
        var runtimeInjected: Bool? = nil
        var runtimeHookArmed: Bool? = nil

        enum CodingKeys: String, CodingKey {
            case overall, build
            case nativeArch = "native_arch"
            case appVersion = "app_version"
            case appPath = "app_path"
            case configKnown = "config_known"
            case configTargets = "config_targets"
            case sip
            case amfiRisk = "amfi_risk"
            case running, writable, signature
            case entitlementsOk = "entitlements_ok"
            case entitlementKeyCount = "entitlement_key_count"
            case restrictedEntitlements = "restricted_entitlements"
            case patchStates = "patch_states"
            case manifest
            case journal
            case verdicts
            case nextCommand = "next_command"
            case runtimeInjected = "runtime_injected"
            case runtimeHookArmed = "runtime_hook_armed"
        }
    }

    struct AmfiRisk: Codable {
        /// kill_predicted / mitigated / not_applicable
        let level: String
        let reason: String
        let fixCommand: String?

        enum CodingKeys: String, CodingKey {
            case level, reason
            case fixCommand = "fix_command"
        }
    }

    enum Overall {
        static let protected = "protected"
        static let partial = "partial"
        static let unprotected = "unprotected"
        static let unsupportedBuild = "unsupported_build"
        static let mixed = "mixed"
    }

    // MARK: - Pure AMFI assessment (unit-testable)

    /// 执行架构（universal 二进制原生运行 → 即实际使用的切片架构）。
    static func nativeArch() -> String {
        var sys = utsname()
        uname(&sys)
        return withUnsafeBytes(of: &sys.machine) { buf in
            let data = Data(buf.prefix(while: { $0 != 0 }))
            return String(decoding: data, as: UTF8.self)
        }
    }

    /// ad-hoc 重签 + restricted entitlements（application-identifier /
    /// team-identifier / application-groups）在 macOS 15+ 的风险评估。
    ///
    /// 2026-09 证据复盘（全网检索 + 社区双实现对照）：主流工具
    /// （zengtianli/WeChatTweak、fzlzjerry/wechat-antirecall）在**保留全部
    /// restricted entitlements** + 注入两个 cs.* 键的前提下，于原生 SIP 开启的
    /// macOS 15+ 用户机上正常运行；sunnyyoung #1038 的真实杀机根因是把
    /// entitlements **剥光**（codesign --remove-sign + 裸 --deep）。本项目早期
    /// 的「必杀 + AMFI boot-arg 处方」把 verifier worker 的 RWX 杀机经验误外推
    /// 到了微信重签场景。现降级为 watch：不再处方关 SIP/boot-arg，改为
    /// 崩溃日志取证指引（Termination Reason, Namespace CODESIGNING）。
    ///
    /// 本机先例（2026-09-15 16:28/16:29，repo 诞生前的手工实验期）：
    /// WeChat-*.ips ×2 记录 `CODESIGNING / Taskgated Invalid Signature` SIGKILL，
    /// codeSigningFlags=0x1000000（CS_ADHOC）——ad-hoc 态在 AMFI 活跃的引导下
    /// 确曾被杀。但当时重签配置无记录（早于 Resigner 管线，疑似 entitlements
    /// 被剥的裸 codesign），**不能**作为当前管线的受控证据。受控实证协议见
    /// tools/amfi_sip_probe.sh（原生 SIP 下 patch→launch→harvest→restore 一键化）。
    static func assessAmfiRisk(
        adhocSigned: Bool,
        restrictedEntitlements: Bool,
        osMajor: Int,
        bootArgs: String?
    ) -> AmfiRisk? {
        guard adhocSigned, restrictedEntitlements, osMajor >= 15 else { return nil }
        let bypass = bootArgs?.contains("amfi_get_out_of_my_way") == true
        if bypass {
            return AmfiRisk(
                level: "mitigated",
                reason: "ad-hoc signature with restricted entitlements on macOS \(osMajor); AMFI bypass boot-arg present",
                fixCommand: nil)
        }
        return AmfiRisk(
            level: "watch",
            reason: "ad-hoc re-sign carries restricted entitlements on macOS \(osMajor). "
                + "Mainstream tools ship the same configuration on stock SIP-on machines, "
                + "so this is watch-level, not a kill prediction. If WeChat is killed at launch, "
                + "check the crash report's Termination Reason (Namespace CODESIGNING) before changing system security settings.",
            fixCommand: "ls -t ~/Library/Logs/DiagnosticReports/ | grep -i wechat | head -3")
    }

    // MARK: - Collection

    static func run(app: URL, config: Config) -> Report {
        let fm = FileManager.default
        let build = (try? WeChatApp.buildNumber(app: app)) ?? "unknown"
        let versionEntry = config.entry(build: build)
        let configKnown = versionEntry != nil

        // SIP
        let csr = Shell.run("/usr/bin/csrutil", ["status"]).stdout
        let sip: String = {
            if csr.contains("disabled") { return "disabled" }
            if csr.contains("enabled") { return "enabled" }
            return "unknown"
        }()

        // Signature + entitlements of the main executable.
        let main = WeChatApp.binaryURL(app: app, relative: "Contents/MacOS/WeChat")
        let dvv = Shell.run("/usr/bin/codesign", ["-dvv", main.path])
        let signature: String = {
            if dvv.stdout.contains("Signature=adhoc") || dvv.stderr.contains("Signature=adhoc") { return "adhoc" }
            if dvv.stdout.contains("Authority=") || dvv.stderr.contains("Authority=") { return "original" }
            return "unreadable"
        }()
        let profile = Resigner.inspectEntitlements(main)
        let restricted = ["com.apple.application-identifier",
                          "com.apple.developer.team-identifier",
                          "com.apple.security.application-groups"]
            .contains { profile?[$0] != nil }
        let entitlementsOk = !(profile?.isEmpty ?? true)

        let amfiRisk = assessAmfiRisk(
            adhocSigned: signature == "adhoc",
            restrictedEntitlements: restricted,
            osMajor: ProcessInfo.processInfo.operatingSystemVersion.majorVersion,
            bootArgs: {
                let nvram = Shell.run("/usr/sbin/nvram", ["boot-args"])
                return nvram.status == 0 ? nvram.stdout : nil
            }())

        // Patch states per target identifier — only the NATIVE-arch slice counts:
        // a fat binary on Intel never executes the arm64 slice, so its state is
        // irrelevant to protection (and vice versa). Cross-arch aggregation used
        // to poison the verdict ("mixed"/"unprotected" with full x64 protection).
        let nativeArch = Doctor.nativeArch()
        var patchStates: [String: String] = [:]
        var inspectFailures: [String] = []
        if let versionEntry {
            for target in versionEntry.targets {
                let binary = WeChatApp.binaryURL(app: app, relative: target.binary)
                do {
                    let states = try Patcher.inspect(
                        binary: binary, entries: target.entries,
                        identifier: target.identifier)
                        .filter { $0.arch.rawValue == nativeArch }
                        .map(\.state)
                    guard !states.isEmpty else { continue }   // 目标不含本机架构切片 → 不参与判定
                    patchStates[target.identifier] = aggregate(states)
                } catch {
                    // inspect 失败（读不了/权限/异常）≠「无本机切片」——静默
                    // 丢弃会让判定面带着盲区报 protected。unknown 进门，让
                    // mixed 路径如实降级并指认目标。
                    patchStates[target.identifier] = "unknown"
                    inspectFailures.append("⚠️ inspect failed for \(target.identifier) (\(target.binary ?? "?")): \(error.localizedDescription)")
                }
            }
        }

        let running = WeChatApp.isRunning(app: app)
        let writable = fm.isWritableFile(atPath: main.path)

        // ---- runtime 组件状态（可选功能，只读探测） ----
        let runtimeDylibURL = WeChatApp.binaryURL(app: app, relative: "Contents/Frameworks/wxkeep_runtime.dylib")
        let runtimeDylibExists = fm.fileExists(atPath: runtimeDylibURL.path)
        // LC 探测不依赖 dylib 在场：dylib 被删而 LC 残留 = 下次启动 dyld 必
        // 崩的混合态（remove 半途/手工删除），必须可见而非报 null。
        var runtimeInjected = false
        if let mainData = try? Data(contentsOf: main, options: .alwaysMapped) {
            runtimeInjected = MachOInjector.isInjectedAnySlice(
                data: mainData, path: Wxkeep.RuntimeCommand.lcPath)
        }
        let runtimeMarkerText = RuntimeConfig.readMarkerText()
        let runtimeHookArmed: Bool? = runtimeMarkerText == nil
            ? nil
            : (runtimeMarkerText?.contains("mr2=hook-armed") == true)

        // ---- single verdict point ----

        var verdicts: [String] = inspectFailures
        if runtimeInjected && !runtimeDylibExists {
            verdicts.append("❌ LC_LOAD_DYLIB 在场但 runtime dylib 缺失 — 下次启动 dyld 必崩。修复：`wxkeep runtime install` 重装，或 `wxkeep runtime remove` 清掉 LC")
        }
        // 供应链与切片完整性观察
        var manifestStatus: String? = nil
        if let cfgDir = Config.locatedDirectory() {
            switch Manifest.verify(directory: cfgDir) {
            case .verified: manifestStatus = "verified"
            case .legacy: manifestStatus = "legacy"
            case .invalid(let r): manifestStatus = "invalid:\(r)"
            }
        }
        var overall: String
        if let entry = versionEntry, configKnown {
            // 废弃变体残留（共享位点不算）：有则告警并给清理路径。
            let leftovers = (try? Engine.deprecatedLeftovers(
                app: app, versionEntry: entry,
                coveredTargets: entry.targets.filter { $0.identifier != "revoke-keeptip2" })) ?? []
            if !leftovers.isEmpty {
                // sudo 前缀按可写性条件化（与下方 nextCommand 同款）——非 sudo
                // 环境硬编码 sudo 会误导（writable 时不需要）。
                verdicts.append("⚠️ deprecated revoke-keeptip2 bytes present (\(leftovers.joined(separator: ", "))) — run `\(writable ? "" : "sudo ")wxkeep restore` to clean, then re-patch")
                patchStates["revoke-keeptip2"] = "leftover(\(leftovers.count))"
            } else if patchStates["revoke-keeptip2"] != nil {
                patchStates["revoke-keeptip2"] = "clean"
            }
            // 废弃目标不参与 overall 判定（deprecated → 只影响上面的告警行）。
            let gating = patchStates.filter { $0.key != "revoke-keeptip2" }
            if gating.values.contains("unknown") {
                overall = Overall.mixed
                verdicts.append("some native-arch patch points hold unknown bytes — restore or reinstall, then re-patch")
            } else {
                let revoke = gating["revoke"] == "patched" || gating["revoke-keeptip"] == "patched"
                let revokeSideMixed = [gating["revoke"], gating["revoke-keeptip"]]
                    .contains("mixed")
                if revoke && revokeSideMixed {
                    overall = Overall.mixed
                    verdicts.append("anti-revoke patch points are partially applied on \(nativeArch) — re-run patch")
                } else if revoke {
                    overall = Overall.protected
                } else if gating.values.contains("patched") {
                    overall = Overall.partial
                } else {
                    overall = Overall.unprotected
                }
            }
        } else {
            overall = Overall.unsupportedBuild
            verdicts.append("build \(build) is not in the catalog — run `wxkeep locate` to auto-locate via recipes")
        }
        if signature == "adhoc" { verdicts.append("bundle is re-signed (ad-hoc) — expected after patching") }
        if let amfiRisk, amfiRisk.level == "watch" {
            verdicts.append("AMFI watch: ad-hoc + restricted entitlements on macOS 15+ — mainstream evidence says this runs; only act if a crash report shows Namespace CODESIGNING")
        }
        if running { verdicts.append("WeChat is running — quit it before patching") }
        if !writable, ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 14 {
            verdicts.append("macOS 14+ 提示：sudo 也会被「App 管理」隐私权限拦截——若 patch 报 Permission denied，到 系统设置 → 隐私与安全性 → App 管理 给终端 App 授权后重试")
        }
        if UpdateGuard.rewrittenByApp {
            verdicts.append("update-guard: 微信已把更新开关改回（4.1.13+ 启动时重写的已知行为）——偏好层防护挡不住自动更新；若微信已升级请重打补丁")
        }
        if let ms = manifestStatus, ms.hasPrefix("invalid:") {
            verdicts.append("⚠️ catalog manifest INVALID — \(String(ms.dropFirst(8))). Refusing to trust bundled data; fetch a fresh copy.")
        }
        if runtimeInjected && runtimeHookArmed == false {
            verdicts.append("runtime hook 未武装——当前构建无匹配地址行/序言不符/函数身份门不符（77 续：同序言不同函数已实证可能）：`wxkeep runtime hooks` 刷新后重启微信，`wxkeep runtime status` 看诊断位")
        }

        // next command
        var nextCommand: String? = nil
        if overall == Overall.unsupportedBuild {
            nextCommand = "wxkeep locate"
        } else if overall != Overall.protected {
            let sudo = writable ? "" : "sudo "
            let hasKeeptip = versionEntry?.targets.contains { $0.identifier == "revoke-keeptip" } ?? false
            let variant = hasKeeptip ? "keeptip" : "silent"
            nextCommand = "\(sudo)wxkeep patch --variant \(variant)"
        }
        // （不再处方 AMFI boot-arg：watch 级判定无前置动作，见 assessAmfiRisk 注释）

        // ---- 中断事务（WAL journal 残留）：判读行 + nextCommand 覆盖 ----
        // journal 残留时恢复指引优先于「继续打补丁」——半套态上叠加新动作
        // 与错误路径的处置哲学（先归一）相悖。
        let journalPending = PatchJournal.pending()
        var journalSummary: String? = nil
        if journalPending.exists {
            let gating = patchStates.filter { $0.key != "revoke-keeptip2" }
            let guidance = interruptedTxGuidance(
                journalExists: true, record: journalPending.record,
                gatingStates: gating, sudoRequired: !writable, appPath: app.path,
                runtimeInjected: runtimeInjected, runtimeDylibExists: runtimeDylibExists)
            verdicts.append(contentsOf: guidance.verdictLines)
            journalSummary = guidance.journalSummary
            nextCommand = guidance.nextCommand ?? nextCommand
        }

        return Report(
            overall: overall,
            nativeArch: nativeArch,
            build: build,
            appVersion: WeChatApp.marketingVersion(app: app) ?? "",
            appPath: app.path,
            configKnown: configKnown,
            configTargets: versionEntry?.targets.map(\.identifier) ?? [],
            sip: sip,
            amfiRisk: amfiRisk,
            running: running,
            writable: writable,
            signature: signature,
            entitlementsOk: entitlementsOk,
            entitlementKeyCount: profile?.count ?? 0,
            restrictedEntitlements: restricted,
            patchStates: patchStates,
            manifest: manifestStatus,
            journal: journalSummary,
            verdicts: verdicts,
            nextCommand: nextCommand,
            // LC 探测不再被 dylib 在场性掩盖（混合态 = LC 在而 dylib 缺，
            // 已有专门 verdict 行；hook 武装语义依赖 dylib 曾加载，保持门）。
            runtimeInjected: runtimeInjected,
            runtimeHookArmed: runtimeDylibExists ? runtimeHookArmed : nil)
    }

    /// 归一化恢复型条目（asm ∈ expected，如 keeptip 在 isRevokemsg 入口的
    /// 序言恢复条目）打与不打字节同形（.ambiguous）——由同 target 的可判定
    /// 条目代判：全二义则无法判定，可判定条目意见不一维持 mixed/unknown。
    /// internal：DoctorTests 直接回归真实实现（不再维护镜像副本）。
    static func aggregate(_ states: [Patcher.Inspection.State]) -> String {
        guard !states.isEmpty else { return "unknown" }
        let resolvable = states.filter { $0 != .ambiguous }
        guard let anchor = resolvable.first else { return "unknown" }
        guard resolvable.allSatisfy({ $0 == anchor }) else {
            return resolvable.contains(.unknown) ? "unknown" : "mixed"
        }
        switch anchor {
        case .patched: return "patched"
        case .pristine: return "pristine"
        case .ambiguous, .unknown: return "unknown"
        }
    }

    /// update-guard 一行标签。判定顺序即语义：rewrittenByApp（写过 0、
    /// 现在读 1）蕴含 guardOn=false——先判 on/off 会让「失守」分支永不
    /// 显示（被笼统的 off 遮蔽），失守信息只能从 verdict 行看到。
    static func updateGuardTag(guardOn: Bool, rewrittenByApp: Bool) -> String {
        if rewrittenByApp {
            return "失守（微信已把更新开关改回——见判定行）"
        }
        if !guardOn {
            return "off（有升级弹窗风险，跑 wxkeep update-guard）"
        }
        return "on（不检查更新；4.1.13+ 前两键可能被微信改回）"
    }

    // MARK: - 中断事务判读（WAL 残留 × 字节态合读，纯函数）

    /// journal 残留 = 上次写入事务（patch/restore）未确认完成——进程可能
    /// 在多点写入中途被杀（catch 型恢复重签覆盖不到 SIGKILL/断电）。但
    /// journal 在场 ≠ 字节必坏：进程也可能在「写完+签完、收口前」死掉。
    /// 与 gating 字节态合读给精确指引（restore 幂等，永远是安全动作）：
    ///
    /// - patch + 字节态完好 → 疑似写完未收口：verify 确认即可（re-patch
    ///   也能收口，但 verify 更轻）；
    /// - patch + 字节态残缺 → 确认中断：restore 先归一，再按需重打——
    ///   直接重打虽也写全点位，但「半套态上直接重打」与既有错误路径的
    ///   处置哲学（先 restore 归一）保持一致；
    /// - restore → 重跑 restore 即可（幂等，收口 journal）。
    /// gating 语义与 overall 判定共用：废弃目标不参与。
    static func interruptedTxGuidance(
        journalExists: Bool,
        record: PatchJournal.Record?,
        gatingStates: [String: String],
        sudoRequired: Bool,
        appPath: String,
        runtimeInjected: Bool = false,
        runtimeDylibExists: Bool = false
    ) -> (verdictLines: [String], journalSummary: String?, nextCommand: String?) {
        guard journalExists else { return ([], nil, nil) }
        let sudo = sudoRequired ? "sudo " : ""
        guard let record else {
            return (["⚠️ patch journal present but UNREADABLE — a write transaction may have been "
                     + "interrupted (or the journal was tampered with). Run `\(sudo)wxkeep restore` "
                     + "(idempotent) to normalize, then re-patch if desired"],
                    "unreadable", "\(sudo)wxkeep restore")
        }
        // app 不匹配（clone/多 bundle 机器）：不越权指路，只提示去正确 app 检查
        guard record.app == appPath else {
            return (["journal from a DIFFERENT app bundle (\(record.app), \(record.kind.rawValue) "
                     + "started \(record.startedAt)) — inspect it with `wxkeep doctor --app \(record.app)`"],
                    "\(record.kind.rawValue)@\(record.app)", nil)
        }
        let started = record.startedAt
        let revokePatched = gatingStates["revoke"] == "patched"
            || gatingStates["revoke-keeptip"] == "patched"
        let byteDamage = gatingStates.values.contains { $0 == "mixed" || $0 == "unknown" }
        let anyPatched = gatingStates.values.contains { $0 == "patched" }
        switch record.kind {
        case .patch where revokePatched && !byteDamage:
            return (["journal from an unfinished patch run (started \(started)) — bytes look fully "
                     + "applied; it likely died before cleanup. Confirm with `wxkeep verify`; "
                     + "re-running patch (idempotent) clears the journal"],
                    "patch@\(started)", "wxkeep verify")
        case .patch where !byteDamage && !anyPatched:
            return (["journal from an unfinished patch run (started \(started)) — bytes look "
                     + "pristine: the run likely failed BEFORE writing (permissions / TCC / wrong "
                     + "build) or died before the first byte. Fix the cause and re-run patch, "
                     + "or `\(sudo)wxkeep restore` to clear"],
                    "patch@\(started)", "\(sudo)wxkeep patch")
        case .patch:
            return (["⚠️ INTERRUPTED PATCH detected (started \(started)) — the process likely died "
                     + "mid-write; bytes may be half-applied with a stale signature. "
                     + "Run `\(sudo)wxkeep restore` (idempotent) first, then re-patch"],
                    "patch@\(started)", "\(sudo)wxkeep restore")
        case .restore where !byteDamage && !anyPatched:
            return (["journal from an unfinished restore run (started \(started)) — bytes look "
                     + "pristine; re-run `\(sudo)wxkeep restore` once to clear it"],
                    "restore@\(started)", "\(sudo)wxkeep restore")
        case .restore:
            return (["⚠️ INTERRUPTED RESTORE detected (started \(started)) — re-run "
                     + "`\(sudo)wxkeep restore` to complete it (idempotent)"],
                    "restore@\(started)", "\(sudo)wxkeep restore")
        case .runtimeInstall:
            // runtime 事务的半套态：LC 注入/入口跳板/dylib 拷贝/重签四个
            // 步骤都可能只走了一半——LC 在而 dylib 缺 = dyld 必崩混合态。
            // 收口动作 = 重跑 install（幂等重建全部组件）或 remove 清干净。
            let mixedLC = runtimeInjected && !runtimeDylibExists
            return ([mixedLC
                     ? "⚠️ INTERRUPTED RUNTIME INSTALL detected (started \(started)) and the bundle is in the "
                       + "launch-crash mixed state (LC present, dylib missing). Run `\(sudo)wxkeep runtime remove` to clean"
                     : "journal from an unfinished runtime install (started \(started)) — components look "
                       + "consistent; re-running `\(sudo)wxkeep runtime install` (idempotent) or "
                       + "`\(sudo)wxkeep runtime remove` clears it"],
                    "runtimeInstall@\(started)",
                    mixedLC ? "\(sudo)wxkeep runtime remove" : "\(sudo)wxkeep runtime install")
        case .runtimeRemove:
            return (["⚠️ INTERRUPTED RUNTIME REMOVE detected (started \(started)) — re-run "
                     + "`\(sudo)wxkeep runtime remove` to complete it (idempotent)"],
                    "runtimeRemove@\(started)", "\(sudo)wxkeep runtime remove")
        }
    }


    // MARK: - Rendering

    static func render(_ report: Report) -> String {
        var lines: [String] = []
        lines.append("------ Doctor ------")
        let versionTag = report.appVersion.isEmpty ? "" : " (v\(report.appVersion))"
        lines.append("WeChat build: \(report.build)\(versionTag)  (\(report.appPath))")
        lines.append("native arch: \(report.nativeArch)")
        lines.append("catalog:     \(report.configKnown ? "matched (\(report.configTargets.joined(separator: ", ")))" : "UNKNOWN BUILD")")
        lines.append("SIP:         \(report.sip)")
        if let amfi = report.amfiRisk {
            lines.append("AMFI risk:   \(amfi.level) — \(amfi.reason)")
            if let fix = amfi.fixCommand { lines.append("             fix: \(fix)") }
        } else {
            lines.append("AMFI risk:   not applicable")
        }
        lines.append("running:     \(report.running ? "yes — quit before patching" : "no")")
        lines.append("writable:    \(report.writable ? "yes" : "no — patch with sudo")")
        lines.append("signature:   \(report.signature)")
        let guardStatuses = UpdateGuard.read()
        let guardTag = Doctor.updateGuardTag(
            guardOn: guardStatuses.allSatisfy(\.guarded),
            rewrittenByApp: UpdateGuard.rewrittenByApp)
        lines.append("update-guard: \(guardTag)")
        let privacy = PrivacyGuard.read()
        lines.append("privacy-guard: \(privacy.allSatisfy(\.guarded) ? "on（遥测最小化）" : "off（跑 wxkeep privacy-guard）")")
        if let injected = report.runtimeInjected {
            // armed=nil（dylib 缺失=有专门 ❌ verdict；或装好但从未启动微信）
            // 不再整行隐藏——刚 install 完的用户在 doctor 里应能看到注入在位
            // 与「启动后才有武装态」的指引（runtime status 同语义）。
            let hook: String
            if let armed = report.runtimeHookArmed {
                hook = armed ? "已武装" : "未武装（wxkeep runtime hooks 刷新后重启微信）"
            } else {
                hook = "未知（启动微信后回写 marker；`wxkeep runtime status` 看细节）"
            }
            lines.append("runtime:      注入=\(injected ? "是" : "否") hook=\(hook)")
        }
        lines.append("entitlements: \(report.entitlementKeyCount) keys, restricted=\(report.restrictedEntitlements ? "yes" : "no")")
        for (identifier, state) in report.patchStates.sorted(by: { $0.key < $1.key }) {
            lines.append("patch[\(identifier)]: \(state)")
        }
        lines.append("------ Verdict ------")
        if let m = report.manifest { lines.append("manifest: \(m)") }
        lines.append("journal:     \(report.journal == nil ? "clean (no pending write transaction)" : "PENDING — \(report.journal!)")")
        lines.append("overall: \(report.overall)")
        report.verdicts.forEach { lines.append(" • \($0)") }
        if let next = report.nextCommand { lines.append("➡️  next: \(next)") }
        return lines.joined(separator: "\n")
    }
}
