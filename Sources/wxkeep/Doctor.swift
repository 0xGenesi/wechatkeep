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
        /// `codesign --verify --strict` 实测（110 轮）：false = 字节已改+陈旧签名
        /// 的启动必崩态（-dvv 的结构读取检不出来）。nil = 未检（异常兜底）。
        var signatureValid: Bool? = nil
        let entitlementsOk: Bool
        let entitlementKeyCount: Int
        let restrictedEntitlements: Bool
        let patchStates: [String: String]   // identifier → patched/pristine/mixed/unknown（仅本机架构切片）
        let manifest: String?              // verified/legacy/invalid:<reason>（数据供应链）
        /// nil = 无残留；否则为未确认写入事务的摘要（kind + 起始时间）。
        var journal: String? = nil
        /// per-site 审计账目对账（125 轮）：fresh / stale / unreadable /
        /// foreign-app；nil = 无账目（restore 后收口或从未 patch）。
        var auditState: String? = nil
        /// 近 7 天目标 app 的 .ips 崩溃报告扫描（125 轮外部判据面）。
        /// nil = 无匹配报告（健康常态）。
        var recentCrashReports: CrashSummary? = nil
        /// spctl Gatekeeper 评估（125 轮，informational——ad-hoc 被拒是预期
        /// 态，本机放行判据是 AMFI，两行互补）。nil = 未评。
        var gatekeeperAssessment: String? = nil
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
            case signatureValid = "signature_valid"
            case entitlementsOk = "entitlements_ok"
            case entitlementKeyCount = "entitlement_key_count"
            case restrictedEntitlements = "restricted_entitlements"
            case patchStates = "patch_states"
            case manifest
            case journal
            case auditState = "audit_state"
            case recentCrashReports = "recent_crash_reports"
            case gatekeeperAssessment = "gatekeeper_assessment"
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

    /// .ips 崩溃报告扫描摘要（125 轮 V5 深度轮，外部判据面）。
    struct CrashSummary: Codable, Equatable {
        let count: Int
        /// 最近一份文件名（nil 理论不可达——count>0 才有摘要；防御式可空）。
        let mostRecent: String?
        /// 其中 Termination Namespace=CODESIGNING 的份数（签名击杀证据）。
        let codesigning: Int

        enum CodingKeys: String, CodingKey {
            case count
            case mostRecent = "most_recent"
            case codesigning
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

    /// 执行切片选择（124 轮 Rosetta 盲区收口，纯函数）。语义三支：
    /// ① 有本机切片 → 只看本机（跨架构聚合的 mixed/unprotected 假红是
    ///    既有修复，语义不变）；
    /// ② 无本机切片但有他切片 → 回退到他切片（3.x x64-only 构建在
    ///    Apple Silicon 上经 Rosetta 运行的实况；此前静默跳过 = 判定面空，
    ///    protected/unprotected 双向失真）；
    /// ③ 空 → 不参与判定（既有语义）。
    /// 强制「以 Rosetta 打开」的双切片构建不在此面（需运行进程取证，
    /// 静态不可判）——诚实边界，不猜。
    static func executingSliceStates(_ all: [Patcher.Inspection],
                                     nativeArch: String)
        -> (states: [Patcher.Inspection.State], viaRosetta: Bool) {
        let native = all.filter { $0.arch.rawValue == nativeArch }.map(\.state)
        if !native.isEmpty { return (native, false) }
        if all.isEmpty { return ([], false) }
        return (all.map(\.state), true)
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

    static func run(app: URL, config: Config, explicitConfigPath: String? = nil,
                    deep: Bool = false) -> Report {
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
        // 探查失败=nil（doctor 诊断面不炸；签名门另有 codesign --verify 兜底）
        let profile = try? Resigner.inspectEntitlements(main)
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
        // 执行切片回退目标（124 轮 Rosetta 盲区收口）：二进制无本机切片、
        // 判定按实际执行的他架构切片走的 target 清单（verdicts 如实标注）。
        var rosettaTargets: [String] = []
        if let versionEntry {
            for target in versionEntry.targets {
                let binary = WeChatApp.binaryURL(app: app, relative: target.binary)
                do {
                    let all = try Patcher.inspect(
                        binary: binary, entries: target.entries,
                        identifier: target.identifier)
                    // 执行切片解析（124 轮收口）：见 executingSliceStates 注释
                    //（语义三支；回退 = 3.x x64-only 构建 AS 上经 Rosetta 的实况）。
                    let sel = Doctor.executingSliceStates(all, nativeArch: nativeArch)
                    if sel.viaRosetta {
                        let otherArchs = Set(all.map { $0.arch.rawValue }).sorted()
                        rosettaTargets.append(
                            "\(target.identifier) 跑 \(otherArchs.joined(separator: "+")) 切片")
                    }
                    guard !sel.states.isEmpty else { continue }
                    patchStates[target.identifier] = aggregate(sel.states)
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

        // 签名有效性实测（110 轮修）：-dvv 只读内嵌签名结构——补丁字节改后
        // 不重签，它照样报 Signature=adhoc（甚至 original），「字节已改+陈旧
        // 签名」的启动必崩态此前在 doctor 全盲（双评审 P1 的检测缺口半边）。
        // --verify --strict 实算 cdhash 比对（Resigner 成功门同源；不带
        // --deep——340MB 全量太慢，主签名足以暴露字节级漂移）。
        let signatureValid: Bool? = {
            // 125 轮 --deep 可选：快速态（默认）验主签名足以暴露字节级漂移；
            // --deep 升级全量校验（嵌套代码漂移可见，340MB 慢——成本取舍
            // 如实交用户）。
            var args = ["--verify", "--strict"]
            if deep { args.append("--deep") }
            let verify = Shell.run("/usr/bin/codesign", args + [app.path])
            return verify.status == 0
        }()

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

        // ---- 外部判据面（125 轮 V5 深度轮）----
        // .ips：系统崩溃记录 =「最近真的崩过吗」的客观观测（watch 级，与
        // launch_soak 的浸泡判据同源；CODESIGNING 击杀与 AMFI risk 行合读）。
        let crashReports: CrashSummary? = {
            let dir = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Logs/DiagnosticReports")
            let appName = app.deletingPathExtension().lastPathComponent
            return scanCrashReports(directory: dir, appName: appName)
        }()
        // spctl Gatekeeper 评估（informational，不翻 overall）
        let spctlRun = Shell.run("/usr/sbin/spctl", ["-a", "-t", "execute", app.path])
        let gatekeeper = gatekeeperLine(status: spctlRun.status,
                                        output: spctlRun.stdout + spctlRun.stderr,
                                        adhocSigned: signature == "adhoc")

        // ---- single verdict point ----

        var verdicts: [String] = inspectFailures
        if let cr = crashReports {
            verdicts.append("ℹ︎ 最近 7 天崩溃报告 \(cr.count) 份（CODESIGNING 击杀 "
                            + "\(cr.codesigning)）"
                            + (cr.codesigning > 0
                               ? "——签名击杀证据与 AMFI risk 行合读；取证: "
                                 + "ls -t ~/Library/Logs/DiagnosticReports | grep -i wechat"
                               : "——非签名类崩溃与补丁无必然关联，Termination Reason 见报告本体"))
        }
        if !rosettaTargets.isEmpty {
            verdicts.append("Rosetta 执行态：二进制无 \(nativeArch) 切片，\(rosettaTargets.joined(separator: "；")) —— 判定按实际执行的切片（若在「显示简介」里强制过 Rosetta 的双切片构建，此判定不覆盖，请复原设置）")
        }
        if runtimeInjected && !runtimeDylibExists {
            verdicts.append("❌ LC_LOAD_DYLIB 在场但 runtime dylib 缺失 — 下次启动 dyld 必崩。修复：`wxkeep runtime install` 重装，或 `wxkeep runtime remove` 清掉 LC")
        }
        // 供应链与切片完整性观察。目录选择（108 轮修）：显式 --config 时验
        // 实际装载文件所在目录——隐式 locatedDirectory 可能指向另一份候选
        // （brew exe 旁恒有 config.json），「manifest: verified」就会描述一份
        // 未被使用的数据。
        var manifestStatus: String? = nil
        let manifestDir: URL? = explicitConfigPath.map {
            URL(fileURLWithPath: PathUtil.expandTilde($0)).deletingLastPathComponent()
        } ?? Config.locatedDirectory()
        if let cfgDir = manifestDir {
            switch Manifest.verify(directory: cfgDir) {
            case .verified: manifestStatus = "verified"
            case .legacy: manifestStatus = "legacy"
            case .invalid(let r): manifestStatus = "invalid:\(r)"
            }
        }
        var overall: String
        var hasKeeptip2Leftover = false
        if let entry = versionEntry, configKnown {
            // 废弃变体残留（共享位点不算）：有则告警并给清理路径。
            let leftovers = (try? Engine.deprecatedLeftovers(
                app: app, versionEntry: entry,
                coveredTargets: entry.targets.filter { $0.identifier != "revoke-keeptip2" })) ?? []
            if !leftovers.isEmpty {
                hasKeeptip2Leftover = true
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
            // 111 轮 UX：先 update-data（新构建 day-0 数据通道，常一步解决）
            verdicts.append("构建 \(build) 不在补丁目录——先 `wxkeep update-data` 拉最新补丁数据；仍不支持再 `wxkeep locate` 自动定位")
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
            nextCommand = "wxkeep update-data"
        } else if hasKeeptip2Leftover {
            // 残留在场时 patch 会抛 foreignVariantPatched（残留检查在 --only 过滤
            // 之前）——nextCommand 指到 restore 才机器可执行（124 轮体检 P3）。
            nextCommand = "\(writable ? "" : "sudo ")wxkeep restore"
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
                runtimeInjected: runtimeInjected, runtimeDylibExists: runtimeDylibExists,
                currentBuild: build == "unknown" ? nil : build)
            verdicts.append(contentsOf: guidance.verdictLines)
            journalSummary = guidance.journalSummary
            nextCommand = guidance.nextCommand ?? nextCommand
        }

        // ---- per-site 审计账目 vs 盘上字节（125 轮 V5 深度轮）----
        // journal 回答「事务是否收口」；audit 回答「最终写了哪些位点」。stale =
        // 账目与盘不符（外改/手工写入/收口前死掉的中途态证据）——watch 级：
        // 字节态判定的权威在 patchStates，audit 失配不单独翻 overall（如 AMFI
        // 的保守哲学），但 verdict 行如实可见。
        var auditState: String? = nil
        let auditPending = PatchAudit.pending()
        if auditPending.exists, let auditRecord = auditPending.record {
            if auditRecord.app != app.path {
                auditState = "foreign-app"
                verdicts.append("ℹ︎ patch audit from a DIFFERENT app bundle (\(auditRecord.app)) — "
                                + "inspect it with `wxkeep doctor --app \(auditRecord.app)`")
            } else {
                let check = auditSiteStates(record: auditRecord, app: app)
                auditState = check.fresh ? "fresh" : "stale"
                if !check.fresh {
                    let head = check.mismatches.prefix(3).map { "\($0.site.identifier)@\($0.site.va)" }
                        .joined(separator: ", ")
                    // 处方分层（126 轮 C6）：--allow-unverified 打过的机器 restore
                    // 会按设计拒绝无溯源条目（拒绝盲写是 restore 的安全合同）——
                    // 处方如实分流，不给注定失败的 restore 死路。
                    var fix = ". Fix: `\(writable ? "" : "sudo ")wxkeep restore` (idempotent), then re-patch"
                    let hasQuarantined = versionEntry?.targets.contains {
                        $0.entries.contains { $0.expected == nil }
                    } == true
                    if hasQuarantined {
                        fix += "；本构建含无溯源（quarantined）条目——若曾以 --allow-unverified 写入，"
                            + "restore 将按设计拒绝：改用官方 dmg 重装或备份文件恢复"
                    }
                    verdicts.append("⚠️ patch audit STALE — ledger cites bytes no longer on disk "
                                    + "(external modification or interrupted run): \(head)"
                                    + (check.mismatches.count > 3 ? " …" : "")
                                    + fix)
                }
            }
        } else if auditPending.exists {
            auditState = "unreadable"
            verdicts.append("⚠️ patch audit present but UNREADABLE — cannot account for written bytes. "
                            + "Run `\(writable ? "" : "sudo ")wxkeep restore` to normalize")
        }

        // 签名实测门（110 轮）：改字节未重签（中断事务/手工改写/陈旧工具）在此
        // 现形——放在所有 nextCommand 逻辑之后，必崩态指引拥有最终话语权。
        // restore 幂等 = 通用归一路径（restore 后再 patch 会强制重签）。
        if signatureValid == false {
            overall = Overall.mixed
            verdicts.append("❌ bundle signature INVALID (codesign --verify --strict) — bytes changed after the last re-sign; WeChat would be killed at launch. Fix: `\(writable ? "" : "sudo ")wxkeep restore` (idempotent), then re-patch")
            nextCommand = "\(writable ? "" : "sudo ")wxkeep restore"
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
            signatureValid: signatureValid,
            entitlementsOk: entitlementsOk,
            entitlementKeyCount: profile?.count ?? 0,
            restrictedEntitlements: restricted,
            patchStates: patchStates,
            manifest: manifestStatus,
            journal: journalSummary,
            auditState: auditState,
            recentCrashReports: crashReports,
            gatekeeperAssessment: gatekeeper,
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

    /// 审计账目逐位点对账（125 轮）：fresh = 账目 after 字节全部在盘。
    /// binary 缺失/inspect 失败按失配计（保守——对账面不能假绿）；probe 走
    /// Patcher.inspect 只读路径（asm 前缀比对，expected nil = 无原像门）。
    /// internal：PatchAuditTests 直接回归真实实现。
    static func auditSiteStates(record: PatchAudit.Record, app: URL)
        -> (fresh: Bool, checked: Int, mismatches: [(site: PatchAudit.Site, state: String)]) {
        var mismatches: [(site: PatchAudit.Site, state: String)] = []
        for site in record.sites {
            guard let arch = Config.Arch(rawValue: site.arch) else {
                mismatches.append((site, "bad-arch"))
                continue
            }
            let binary = WeChatApp.binaryURL(app: app, relative: site.binary)
            let probe = Config.PatchEntry(
                arch: arch, addr: site.va, recipe: nil, expected: nil,
                asm: site.after, source: nil)
            let inspections = (try? Patcher.inspect(
                binary: binary, entries: [probe], identifier: "audit-probe")) ?? []
            if inspections.first?.state == .patched { continue }
            mismatches.append((site, inspections.first.map { "\($0.state)" } ?? "inspect-failed"))
        }
        return (mismatches.isEmpty, record.sites.count, mismatches)
    }

    /// 近 N 天目标 app 的 .ips 崩溃报告扫描（125 轮 V5 深度轮，外部判据：
    /// 系统自己的崩溃记录）。纯函数（目录/当前时刻注入可测）；目录不可读
    /// 或零匹配 → nil。
    ///
    /// 实测格式（本机 macOS 27 真件，2026-11-03，双评审 P0 修正）：
    /// - 首行头 JSON：`app_name`/`name`/`timestamp`——时间戳是
    ///   `"2026-11-02 23:17:11.00 +0800"` 形（空格分隔、无 T、时区无冒号），
    ///   ISO8601DateFormatter 解不了，须归一后解析；
    /// - 正文 = 首行之后的**整段 JSON**（可多行）：`procName`/`procPath`/
    ///   `termination.namespace` 都在正文里，不在头行。
    /// 坏件/超限件（>8MB）逐个跳过，扫描面不炸。watch 级：计数如实上报，
    /// 不单独翻 overall（AMFI 同哲学）——签名必崩态的权威判定在
    /// signatureValid，本面补「最近真的崩过吗」的观测。
    static func scanCrashReports(directory: URL, appName: String,
                                 days: Int = 7, now: Date = Date()) -> CrashSummary? {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            return nil
        }
        let cutoff = now.addingTimeInterval(-Double(days) * 86400)
        var count = 0, codesigning = 0
        var mostRecent: (date: Date, name: String)?
        for name in names where name.hasSuffix(".ips") {
            let url = directory.appendingPathComponent(name)
            // 头行流式读（≤4KB 即可判名与时间，坏件/大件不必整读）
            guard let handle = try? FileHandle(forReadingFrom: url),
                  let headData = try? handle.read(upToCount: 4096) else { continue }
            try? handle.close()
            guard let nl = headData.firstIndex(of: 0x0A),
                  let header = try? JSONSerialization.jsonObject(
                      with: headData[..<nl]) as? [String: Any] else { continue }
            // 头行门：app_name/name 都不沾边即可整体跳过（helper 进程与主
            // 进程共享 app_name；不沾边的第三方件不进正文读取）。
            let hdrName = ((header["app_name"] as? String) ?? (header["name"] as? String) ?? "")
            let headerHit = hdrName.range(of: appName, options: .caseInsensitive) != nil
            guard headerHit,
                  let ts = header["timestamp"] as? String,
                  let date = parseIpsTimestamp(ts),
                  date >= cutoff else { continue }
            // 正文整段 JSON（可多行；>8MB 跳过——诊断扫描不吞内存）
            guard let bodyText = try? String(contentsOf: url, encoding: .utf8),
                  bodyText.utf8.count <= 8 << 20,
                  let bodyStart = bodyText.firstIndex(of: "\n"),
                  let body = try? JSONSerialization.jsonObject(
                      with: Data(bodyText[bodyText.index(after: bodyStart)...].utf8))
                      as? [String: Any] else { continue }
            // 身份归因（launch_soak 同口径）：procName 等名或 procPath 落在
            // 该 app bundle 内（副本/真机实例按 procPath 分）。
            let procName = (body["procName"] as? String) ?? hdrName
            let procPath = body["procPath"] as? String
            let matches = procName.caseInsensitiveCompare(appName) == .orderedSame
                || (procPath?.contains("/\(appName).app/") ?? false)
            guard matches else { continue }
            count += 1
            if mostRecent == nil || date > mostRecent!.date { mostRecent = (date, name) }
            if let term = body["termination"] as? [String: Any],
               (term["namespace"] as? String)?.uppercased() == "CODESIGNING" {
                codesigning += 1
            }
        }
        guard count > 0 else { return nil }
        return CrashSummary(count: count, mostRecent: mostRecent?.name, codesigning: codesigning)
    }

    /// .ips 头行时间戳归一解析：`2026-11-02 23:17:11.00 +0800` → ISO8601。
    /// 小数位宽度可变、时区无冒号——手工归一后走 ISO8601（+分数秒回退）。
    static func parseIpsTimestamp(_ raw: String) -> Date? {
        // "yyyy-MM-dd HH:mm:ss[.fff…] ±zzzz" → "yyyy-MM-ddTHH:mm:ss.fff±zz:zz"
        var s = raw.trimmingCharacters(in: .whitespaces)
        if let sp = s.firstIndex(of: " ") {
            s.replaceSubrange(sp...sp, with: "T")
        }
        if let tz = s.range(of: #"([+-]\d{4})$"#, options: .regularExpression) {
            let v = String(s[tz])
            s.replaceSubrange(tz, with: "\(v.prefix(3)):\(v.suffix(2))")
        }
        let frac = ISO8601DateFormatter()
        frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = frac.date(from: s) { return d }
        let plain = ISO8601DateFormatter()
        return plain.date(from: s)
    }

    /// spctl -a -t execute 判读（125 轮，informational）。ad-hoc 签名被
    /// Gatekeeper 评估拒收是预期态——「预期态」注解只在确为 ad-hoc 时给出
    ///（双评审 P2 修：签名真损坏的 rejected 不许被安慰成预期态，与紧邻的
    /// signatureValid ❌ 行自相矛盾）。本地放行的实际判据是 AMFI（见
    /// assessAmfiRisk 行），两行互补；这里只如实转述系统判官的裁决。
    static func gatekeeperLine(status: Int32, output: String, adhocSigned: Bool) -> String {
        if status == 0 { return "accepted" }
        if output.contains("rejected") || output.contains("no usable signature") {
            return adhocSigned
                ? "rejected（ad-hoc 预期态；本机放行判据见 AMFI risk 行）"
                : "rejected（非预期——与 signature 行合读，可能为签名损坏）"
        }
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        return "unknown (\(trimmed.isEmpty ? "exit \(status)" : trimmed))"
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
        runtimeDylibExists: Bool = false,
        currentBuild: String? = nil   // 123 轮体检 P3：事务后微信自更新的判读面
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
        // 事务属于旧构建而微信已自更新（123 轮体检 P3-8）：重跑 patch 会对新
        // 构建报 unsupportedBuild——先 update-data；restore 收口不受影响。
        let buildDrift: [String] = {
            guard let cur = currentBuild, !cur.isEmpty, !record.build.isEmpty,
                  record.build != cur else { return [] }
            return ["ℹ︎ journal 属于构建 \(record.build) 而当前微信已是 \(cur)（事务后自更新）——"
                    + "对新构建重打前先 `wxkeep update-data`；restore 收口不受影响"]
        }()
        let revokePatched = gatingStates["revoke"] == "patched"
            || gatingStates["revoke-keeptip"] == "patched"
        let byteDamage = gatingStates.values.contains { $0 == "mixed" || $0 == "unknown" }
        let anyPatched = gatingStates.values.contains { $0 == "patched" }
        switch record.kind {
        case .patch where revokePatched && !byteDamage && record.resigned == true:
            // 111 轮修（处方收敛）：next_command 原为 `wxkeep verify`——verify
            // 不触碰 journal，照做后 doctor 每次仍给同一处方，PENDING 永不
            // 收敛（稀释真事故提示）。verify 降为人读确认步骤，机器可执行
            // 指令改幂等 patch（重跑即清 journal）。
            return (buildDrift + ["journal from an unfinished patch run (started \(started)) — bytes look fully "
                     + "applied and re-signing was confirmed; it likely died before cleanup. "
                     + "Re-running patch (idempotent) clears the journal; "
                     + "`wxkeep verify` afterwards confirms behavior"],
                    "patch@\(started)", "\(sudo)wxkeep patch")
        case .patch where revokePatched && !byteDamage:
            // 110 轮修（洗白链）：字节完好但重签从未确认（v1 旧记录 nil 同判）——
            // 「重跑 patch 即收口」的旧处方会把陈旧签名洗白成 protected（全部
            // alreadyPatched → 跳过重签）。新 CLI 的幂等重跑已强制重签，但最稳
            // 指引仍是先 restore 归一（同时治签名）再重打。
            return (["⚠️ journal from an unfinished patch run (started \(started)) — bytes look "
                     + "fully applied, but RE-SIGNING was never confirmed: the signature may not "
                     + "cover the patched bytes (launch kill). Run `\(sudo)wxkeep restore` "
                     + "(idempotent) first, then re-patch (re-run now force-resigns)"],
                    "patch@\(started)", "\(sudo)wxkeep restore")
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
                       + "consistent; `\(sudo)wxkeep runtime remove` then re-install completes it "
                       + "(re-running install alone is rejected by the already-injected check), "
                       + "or `remove` alone clears it"],
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
        // 123 轮体检 P3：macOS 14+ sudo 也会被「App 管理」拦（下方提示同义）——
        // 渲染行按 OS 条件化，不给出注定失败的建议。
        if report.writable {
            lines.append("writable:    yes")
        } else if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 14 {
            lines.append("writable:    no — sudo + 终端需有「App 管理」权限（见下方提示）")
        } else {
            lines.append("writable:    no — patch with sudo")
        }
        lines.append("signature:   \(report.signature)"
                     + (report.signatureValid == false ? " — ❌ VERIFY FAILED（字节与签名不符，启动必崩）" : ""))
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
        if let audit = report.auditState {
            // stale 时 verdict 区已有修复指引，这里给状态行。
            lines.append("audit:       \(audit)")
        }
        if let gk = report.gatekeeperAssessment {
            lines.append("gatekeeper:  \(gk)")
        }
        if let cr = report.recentCrashReports {
            lines.append("crash(7d):   \(cr.count) 份（CODESIGNING \(cr.codesigning)）"
                         + (cr.mostRecent.map { "，最近: \($0)" } ?? ""))
        }
        lines.append("overall: \(report.overall)")
        report.verdicts.forEach { lines.append(" • \($0)") }
        if let next = report.nextCommand { lines.append("➡️  next: \(next)") }
        return lines.joined(separator: "\n")
    }
}
