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
        let verdicts: [String]
        let nextCommand: String?

        enum CodingKeys: String, CodingKey {
            case overall, build
            case nativeArch = "native_arch"
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
            case verdicts
            case nextCommand = "next_command"
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
        if let versionEntry {
            for target in versionEntry.targets {
                let binary = WeChatApp.binaryURL(app: app, relative: target.binary)
                let states = ((try? Patcher.inspect(
                    binary: binary, entries: target.entries,
                    identifier: target.identifier)) ?? [])
                    .filter { $0.arch.rawValue == nativeArch }
                    .map(\.state)
                guard !states.isEmpty else { continue }   // 目标不含本机架构切片 → 不参与判定
                patchStates[target.identifier] = aggregate(states)
            }
        }

        let running = WeChatApp.isRunning(app: app)
        let writable = fm.isWritableFile(atPath: main.path)

        // ---- single verdict point ----

        var verdicts: [String] = []
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
                verdicts.append("⚠️ deprecated revoke-keeptip2 bytes present (\(leftovers.joined(separator: ", "))) — run `sudo wxkeep restore` to clean, then re-patch")
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
        if let ms = manifestStatus, ms.hasPrefix("invalid:") {
            verdicts.append("⚠️ catalog manifest INVALID — \(String(ms.dropFirst(8))). Refusing to trust bundled data; fetch a fresh copy.")
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

        return Report(
            overall: overall,
            nativeArch: nativeArch,
            build: build,
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
            verdicts: verdicts,
            nextCommand: nextCommand)
    }

    private static func aggregate(_ states: [Patcher.Inspection.State]) -> String {
        guard !states.isEmpty else { return "unknown" }
        if states.allSatisfy({ $0 == .patched }) { return "patched" }
        if states.allSatisfy({ $0 == .pristine }) { return "pristine" }
        return states.contains(.unknown) ? "unknown" : "mixed"
    }

    // MARK: - Rendering

    // MARK: - 切片哈希观察



    static func render(_ report: Report) -> String {
        var lines: [String] = []
        lines.append("------ Doctor ------")
        lines.append("WeChat build: \(report.build)  (\(report.appPath))")
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
        lines.append("update-guard: \(guardStatuses.allSatisfy(\.guarded) ? "on（不检查更新）" : "off（有升级弹窗风险，跑 wxkeep update-guard）")")
        let privacy = PrivacyGuard.read()
        lines.append("privacy-guard: \(privacy.allSatisfy(\.guarded) ? "on（遥测最小化）" : "off（跑 wxkeep privacy-guard）")")
        lines.append("entitlements: \(report.entitlementKeyCount) keys, restricted=\(report.restrictedEntitlements ? "yes" : "no")")
        for (identifier, state) in report.patchStates.sorted(by: { $0.key < $1.key }) {
            lines.append("patch[\(identifier)]: \(state)")
        }
        lines.append("------ Verdict ------")
        if let m = report.manifest { lines.append("manifest: \(m)") }
        lines.append("overall: \(report.overall)")
        report.verdicts.forEach { lines.append(" • \($0)") }
        if let next = report.nextCommand { lines.append("➡️  next: \(next)") }
        return lines.joined(separator: "\n")
    }
}
