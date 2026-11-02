import Foundation
import Testing
@testable import WxkeepRuntime   // marker 内容缝（C 符号）
@testable import wxkeep

struct DoctorTests {
    // MARK: AMFI 纯函数（2026-09 证据复盘后：watch 级，不再处方 boot-arg）

    @Test func amfiWatchOnMac15AdhocRestricted() {
        let risk = Doctor.assessAmfiRisk(
            adhocSigned: true, restrictedEntitlements: true,
            osMajor: 15, bootArgs: nil)
        #expect(risk?.level == "watch")
        // 处方已从「关 SIP + AMFI boot-arg」降级为崩溃日志取证
        #expect(risk?.fixCommand?.contains("amfi_get_out_of_my_way") != true)
        #expect(risk?.fixCommand?.contains("DiagnosticReports") == true)
    }

    @Test func amfiMitigatedWithBootArg() {
        let risk = Doctor.assessAmfiRisk(
            adhocSigned: true, restrictedEntitlements: true,
            osMajor: 15, bootArgs: "boot-args\tamfi_get_out_of_my_way=0x1")
        #expect(risk?.level == "mitigated")
        #expect(risk?.fixCommand == nil)
    }

    @Test func amfiNotApplicableWhenNoRestrictedKeysOrOriginalSig() {
        #expect(Doctor.assessAmfiRisk(adhocSigned: true, restrictedEntitlements: false,
                                      osMajor: 15, bootArgs: nil) == nil)
        #expect(Doctor.assessAmfiRisk(adhocSigned: false, restrictedEntitlements: true,
                                      osMajor: 15, bootArgs: nil) == nil)
        // macOS 14 taskgated 行不同：不预测
        #expect(Doctor.assessAmfiRisk(adhocSigned: true, restrictedEntitlements: true,
                                      osMajor: 14, bootArgs: nil) == nil)
    }

    // MARK: 判定聚合（直接回归真实实现——.ambiguous 语义见 aggregate 注释）

    @Test func aggregateStates() {
        let allPatched = [Patcher.Inspection.State](repeating: .patched, count: 3)
        let allPristine = [Patcher.Inspection.State](repeating: .pristine, count: 2)
        let mixedBag: [Patcher.Inspection.State] = [.pristine, .patched]
        let withUnknown: [Patcher.Inspection.State] = [.patched, .unknown]
        let empty: [Patcher.Inspection.State] = []
        #expect(Doctor.aggregate(allPatched) == "patched")
        #expect(Doctor.aggregate(allPristine) == "pristine")
        #expect(Doctor.aggregate(mixedBag) == "mixed")
        #expect(Doctor.aggregate(withUnknown) == "unknown")
        #expect(Doctor.aggregate(empty) == "unknown")
    }

    /// 归一化恢复型条目（asm ∈ expected）的 .ambiguous 态由同 target 的
    /// 可判定条目代判——pristine 二进制上 doctor 曾因此误报 keeptip=mixed
    /// （ROADMAP ㊲ 附带发现 6）。
    @Test func aggregateResolvesAmbiguousFromSiblings() {
        // keeptip x64 实形：普通条目 + 归一化条目（270100 的 537e52d + 4e8d5d0）
        #expect(Doctor.aggregate([.pristine, .ambiguous]) == "pristine")   // 修复前：mixed
        #expect(Doctor.aggregate([.patched, .ambiguous]) == "patched")
        // arm64 实形（270100 的 4bc4fa4 + 4bc5744）
        #expect(Doctor.aggregate([.ambiguous, .pristine]) == "pristine")
        #expect(Doctor.aggregate([.ambiguous, .patched]) == "patched")
        // 全二义 → 无法判定；二义不掩盖可判定条目的分歧/未知
        #expect(Doctor.aggregate([.ambiguous, .ambiguous]) == "unknown")
        #expect(Doctor.aggregate([.patched, .pristine, .ambiguous]) == "mixed")
        #expect(Doctor.aggregate([.unknown, .ambiguous]) == "unknown")
    }

    // MARK: JSON 契约（未来 GUI 的命脉——键集快照）

    @Test func jsonContractHasStableShape() throws {
        let report = Doctor.Report(
            overall: "protected", nativeArch: "x86_64", build: "999999", appPath: "/x.app",
            configKnown: true, configTargets: ["revoke"],
            sip: "disabled", amfiRisk: nil, running: false, writable: true,
            signature: "adhoc", entitlementsOk: true, entitlementKeyCount: 17,
            restrictedEntitlements: true, patchStates: ["revoke": "patched"],
            manifest: nil,
            verdicts: [], nextCommand: nil)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let object = try JSONSerialization.jsonObject(
            with: encoder.encode(report)) as? [String: Any] ?? [:]
        // required keys are always present; optional-valued keys (amfi_risk,
        // next_command) are omitted when nil — absent == null for decoders
        let requiredKeys: Set<String> = [
            "overall", "native_arch", "build", "app_path", "config_known", "config_targets", "sip",
            "running", "writable", "signature", "entitlements_ok",
            "entitlement_key_count", "restricted_entitlements", "patch_states",
            "verdicts",
        ]
        #expect(requiredKeys.isSubset(of: Set(object.keys)))
        #expect(!Set(object.keys).isSuperset(of: ["amfi_risk"]))  // nil omitted
        // 非_nil_时两键必须在——见下一个用例
        // snake_case 约定（GUI 直接解码，驼峰即破坏性变更）
        #expect(object["app_path"] is String)
        #expect(object["patch_states"] is [String: Any])
    }

    @Test func optionalKeysPresentWhenNonNil() throws {
        let report = Doctor.Report(
            overall: "unprotected", nativeArch: "x86_64", build: "1", appPath: "/x",
            configKnown: false, configTargets: [],
            sip: "enabled",
            amfiRisk: Doctor.AmfiRisk(level: "kill_predicted", reason: "r", fixCommand: "sudo ..."),
            running: false, writable: false, signature: "adhoc",
            entitlementsOk: true, entitlementKeyCount: 2,
            restrictedEntitlements: true, patchStates: [:],
            manifest: nil,
            verdicts: ["v"], nextCommand: "wxkeep locate")
        let object = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(report)) as? [String: Any] ?? [:]
        #expect(object["amfi_risk"] is [String: Any])
        #expect(object["next_command"] is String)
    }

    @Test func amfiRiskEncodesSnakeCaseFixCommand() throws {
        let risk = Doctor.AmfiRisk(level: "kill_predicted", reason: "r",
                                   fixCommand: "sudo nvram ...")
        let data = try JSONEncoder().encode(risk)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        #expect(object["fix_command"] is String)
        #expect(object["level"] as? String == "kill_predicted")
    }

    /// rewrittenByApp（写过 0、现在读 1）蕴含 guardOn=false——失守判定必须
    /// 优先于 off，否则「失守」标签被笼统的 off 遮蔽、永不显示（旧实现的
    /// 分支顺序使然）。
    @Test func updateGuardTagOrder() {
        #expect(Doctor.updateGuardTag(guardOn: false, rewrittenByApp: true).hasPrefix("失守"))
        #expect(Doctor.updateGuardTag(guardOn: false, rewrittenByApp: false).hasPrefix("off"))
        #expect(Doctor.updateGuardTag(guardOn: true, rewrittenByApp: false).hasPrefix("on"))
    }
}

extension DoctorTests {
    /// 组件移除后 marker 残留（remove 不清 marker 的存量机器，2026-09-23
    /// 本机实测踩中）：`runtime status` 必须把过期 marker 降格为历史快照，
    /// 不能把「已武装（对已匹配构建生效）」当现状陈述——用户会以为 hook
    /// 仍在生效。install/remove 现已清理 marker，本测试守护存量机器的展示面。
    @Test func runtimeStatusStaleMarkerIsHistorical() {
        // 组件在位：marker 照常陈述现状
        #expect(Wxkeep.RuntimeCommand.runtimeMarkerLine(active: true, markerExists: true)
                == "已加载（上次启动）")
        #expect(Wxkeep.RuntimeCommand.runtimeHookStateText(active: true, markerExists: true, armed: true)
                == "已武装（对已匹配构建生效）")
        #expect(Wxkeep.RuntimeCommand.runtimeHookStateText(active: true, markerExists: true, armed: false)
                == "未武装（当前构建无匹配地址行或序言不符）")
        // 组件移除 + marker 残留：降格为历史快照，明示不再生效
        #expect(Wxkeep.RuntimeCommand.runtimeMarkerLine(active: false, markerExists: true)
                .contains("历史快照——组件已移除"))
        #expect(Wxkeep.RuntimeCommand.runtimeHookStateText(active: false, markerExists: true, armed: true)
                == "曾武装（历史快照——组件已移除，重启微信后不再生效）")
        #expect(Wxkeep.RuntimeCommand.runtimeHookStateText(active: false, markerExists: true, armed: false)
                == "未武装（历史快照——组件已移除）")
        // 无 marker：未知/无记录（与 active 无关）
        #expect(Wxkeep.RuntimeCommand.runtimeMarkerLine(active: true, markerExists: false) == "无记录")
        #expect(Wxkeep.RuntimeCommand.runtimeMarkerLine(active: false, markerExists: false) == "无记录")
        #expect(Wxkeep.RuntimeCommand.runtimeHookStateText(active: true, markerExists: false, armed: false)
                == "未知（无启动记录）")
    }

    /// marker status 位域判读（77 续修复：kStInstallFail=3 与 uuid(1)+
    /// prologue(2) 同形——status=11 曾被误读为序言门，实为 callback+
    /// install-fail，77 轮靠 istep/errno 才纠偏）。新编码独立 bit +
    /// marker enc=2 标记；旧编码 marker 只展示原值不解位。
    @Test func runtimeStatusFlagsDecodeIndependentBits() {
        let f = Wxkeep.RuntimeCommand.runtimeStatusFlags
        #expect(f(0) == ["idle"])
        #expect(f(4) == ["install-fail"])
        // 77 轮实案的新编码形态：callback + install-fail = 16|4
        #expect(f(20) == ["install-fail", "callback"])
        #expect(f(23) == ["uuid-mismatch", "prologue-mismatch", "install-fail", "callback"])
        #expect(f(8) == ["armed"])
        #expect(f(64) == ["func-id-mismatch"])
        #expect(f(36) == ["install-fail", "scan-missed"])
    }

    @Test func markerStatusDecodeGatedByEncodingMarker() {
        // 新编码（enc=2）：位域 + istep/ierr 齐读
        let fresh = "loaded ts=1 mr2=marker-only status=20 enc=2 istep=2 ierr=13 fires=0 hits=0 zero=0"
        let d1 = Wxkeep.RuntimeCommand.markerStatusDecode(fresh)
        #expect(d1?.status == 20)
        #expect(d1?.flags == ["install-fail", "callback"])
        #expect(d1?.installStep == 2)
        #expect(d1?.installErrno == 13)
        // 旧编码（无 enc=2，77 轮前的 dylib 写出）：status 原值可读，位域不判读
        let old = "loaded ts=1 mr2=marker-only status=11 fires=0 hits=0 zero=0"
        let d2 = Wxkeep.RuntimeCommand.markerStatusDecode(old)
        #expect(d2?.status == 11)
        #expect(d2?.flags == nil, "11 在旧编码 = callback+install-fail，新判读会误读——不判读")
        // 无 status 字段
        #expect(Wxkeep.RuntimeCommand.markerStatusDecode("loaded ts=1") == nil)
    }

    /// marker 键名双侧 round-trip 锁（123 轮体检 P2-3）：格式串在
    /// runtime.m、解析键名在 CLI——两侧手写，改一侧另一侧静默显 "?" / 0。
    /// 用生产构造函数的实出内容对照 CLI 消费的键全集。
    @Test func markerFormatKeysRoundTrip() {
        guard let c = wxkeep_runtime_test_marker_content() else {
            Issue.record("marker 内容缝不可用"); return
        }
        let line = String(cString: c)
        // CLI `runtime status`/doctor 消费的每一个键（markerInt/markerDigits/
        // markerStatusDecode/直读 range 四类全集；124 轮 +cldrop/clgap 池键）
        let keys = ["status", "enc", "istep", "ierr",
                    "fires", "hits", "zero", "selfskip",
                    "clone", "clmiss", "clrow", "cllastlen", "clpair", "clsvc",
                    "clkey", "clhit", "clmissq", "clget", "clinner",
                    "clpub", "clpubm", "clins", "clsvc2", "cldrop", "clgap",
                    "cfg", "cfgh", "ts"]
        for k in keys {
            #expect(line.contains(" \(k)=") || line.hasPrefix("\(k)=") || line.contains(" \(k)=\(k == "enc" ? "2" : "")"),
                    "marker 格式串缺键 \(k)——CLI 侧将静默显 ?/0")
        }
        // doctor 判读面照生产内容可解
        let d = Wxkeep.RuntimeCommand.markerStatusDecode(line)
        #expect(d != nil)
        #expect(d?.flags != nil, "enc=2 在场 = 新编码应解位域")
    }

    /// 执行切片选择三支（124 轮 Rosetta 盲区收口）：本机在场只看本机 /
    /// 仅他切片回退他切片（3.x x64-only 经 Rosetta 实况）/ 空不参与。
    /// 关键回归：x64-only 目标在 arm64 主机此前被静默跳过 = 判定面空。
    @Test func executingSliceSelectionThreeBranches() {
        func ins(_ arch: String, _ state: Patcher.Inspection.State)
            -> Patcher.Inspection {
            Patcher.Inspection(arch: .init(rawValue: arch)!, va: 0x1000,
                                      state: state, current: "AA")
        }
        // ① 本机在场：只看本机（arm64 切片 pristine 不被 x64 patched 拉成 mixed）
        let a = Doctor.executingSliceStates(
            [ins("arm64", .pristine), ins("x86_64", .patched)], nativeArch: "arm64")
        #expect(a.states == [Patcher.Inspection.State.pristine])
        #expect(a.viaRosetta == false)
        // ② 仅他切片（arm64 主机 × x64-only 3.x 构建）：回退 + 标注 Rosetta
        let b = Doctor.executingSliceStates(
            [ins("x86_64", .patched), ins("x86_64", .patched)], nativeArch: "arm64")
        #expect(b.states == [.patched, .patched] as [Patcher.Inspection.State])
        #expect(b.viaRosetta == true)
        // ③ 空：不参与（既有语义）
        let c = Doctor.executingSliceStates([], nativeArch: "arm64")
        #expect(c.states.isEmpty)
        #expect(c.viaRosetta == false)
        // 反向（x64 主机 × arm64-only 构建——Intel Mac 装 universal 剥片件，罕见同门）
        let e = Doctor.executingSliceStates(
            [ins("arm64", .patched)], nativeArch: "x86_64")
        #expect(e.states == [Patcher.Inspection.State.patched])
        #expect(e.viaRosetta == true)
    }
}

// MARK: - 125 轮 V5 深度轮：外部判据面（.ips 扫描 / Gatekeeper 判读）

extension DoctorTests {
    /// 真实格式 .ips 夹具（本机 macOS 27 真件实测布局，双评审 P0 修正）：
    /// 首行头 JSON 只带 app_name/name/timestamp（**无** procName/procPath，
    /// 时间戳 "yyyy-MM-dd HH:mm:ss.SS +0800" 非 ISO）；procName/procPath/
    /// termination 在首行之后的整段正文 JSON 里（可多行）。
    private func writeIps(dir: URL, name: String, procName: String,
                          timestamp: String, namespace: String?,
                          withPath: Bool = true) throws {
        let header = #"{"app_name":"\#(procName)","name":"\#(procName)","timestamp":"\#(timestamp)"}"#
        // withPath=false：procName 匹配面必须独立可测（M25 曾被 `|| procPath`
        // 子句救活=夹具全带 path 的盲区，125 续变异批次实证存活）。
        let pathField = withPath
            ? #","procPath":"/Applications/\#(procName).app/Contents/MacOS/\#(procName)""#
            : ""
        let body = #"{"procName":"\#(procName)"\#(pathField),"termination":\#(namespace.map { #"{"namespace":"\#($0)"}"# } ?? "null")}"#
        try (header + "\n" + body).write(to: dir.appendingPathComponent(name),
                                         atomically: true, encoding: .utf8)
    }

    /// .ips 头行时间戳实格式生成器（"yyyy-MM-dd HH:mm:ss.SS +0800"）。
    private func ipsTimestamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "Asia/Shanghai")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SS ZZZ"
        return f.string(from: date)
    }

    @Test func crashScanCountsMatchesAndCodesigningKills() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-ips-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let now = Date(timeIntervalSince1970: 1_760_000_000)
        func ts(_ ago: TimeInterval) -> String { ipsTimestamp(now.addingTimeInterval(-ago)) }

        // 两份匹配（一份 CODESIGNING 击杀、一份普通崩溃）、一份他进程、
        // 一份过期——只有前两份进摘要。
        try writeIps(dir: dir, name: "wechat-old.ips", procName: "WeChat",
                     timestamp: ts(8 * 86400), namespace: "CODESIGNING")
        // 无 procPath 形：身份只能来自 procName（M25 杀例面）
        try writeIps(dir: dir, name: "wechat-crash.ips", procName: "WeChat",
                     timestamp: ts(3600), namespace: nil, withPath: false)
        try writeIps(dir: dir, name: "wechat-cs-kill.ips", procName: "WeChat",
                     timestamp: ts(60), namespace: "CODESIGNING")
        try writeIps(dir: dir, name: "safari.ips", procName: "Safari",
                     timestamp: ts(60), namespace: "CODESIGNING")

        let summary = Doctor.scanCrashReports(directory: dir, appName: "WeChat", now: now)
        #expect(summary?.count == 2, "他进程与过期件不计（got \(summary?.count ?? -1)）")
        #expect(summary?.codesigning == 1)
        #expect(summary?.mostRecent == "wechat-cs-kill.ips", "mostRecent 按时间戳非文件名序")

        // 身份匹配负例（M25 杀例面）：全非匹配目录 → nil（健康常态）
        let clean = dir.deletingLastPathComponent()
            .appendingPathComponent("wxkeep-ips-clean-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: clean, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: clean) }
        try writeIps(dir: clean, name: "only-safari.ips", procName: "Safari",
                     timestamp: ts(60), namespace: nil)
        #expect(Doctor.scanCrashReports(directory: clean, appName: "WeChat", now: now) == nil)
    }

    @Test func gatekeeperLineInterpretsSpctlVerdicts() {
        #expect(Doctor.gatekeeperLine(status: 0, output: "app accepted", adhocSigned: true) == "accepted")
        #expect(Doctor.gatekeeperLine(status: 1, output: "app rejected (the code is valid but does not seem to be an app)", adhocSigned: true)
                .contains("rejected（ad-hoc 预期态"), "ad-hoc 拒收如实转述 + 预期态解读")
        #expect(Doctor.gatekeeperLine(status: 1, output: "app rejected (the code is valid but does not seem to be an app)", adhocSigned: false)
                .contains("非预期"), "非 ad-hoc 的拒收不许安慰成预期态（与 signatureValid ❌ 行合读）")
        #expect(Doctor.gatekeeperLine(status: 3, output: "  ", adhocSigned: true).hasPrefix("unknown"),
                "异常输出不猜——unknown 带原始输出")
    }

    @Test func ipsTimestampNormalizerParsesRealFormat() {
        // 真件格式（"2026-11-02 23:17:11.00 +0800"）必须可解析——双评审
        // P0 修正的回归锁：归一器坏了整个 .ips 判据面变安慰剂。
        #expect(Doctor.parseIpsTimestamp("2026-11-02 23:17:11.00 +0800") != nil,
                "真机头行时间戳格式可解析")
        #expect(Doctor.parseIpsTimestamp("2026-11-02T23:17:11.000Z") != nil,
                "标准 ISO 形也兼容")
        #expect(Doctor.parseIpsTimestamp("garbage") == nil)
    }

    @Test func jsonContractCarriesExternalEvidenceKeys() throws {
        // 125 轮增量字段（audit_state / recent_crash_reports / gatekeeper_assessment）
        // 的 JSON 形状锁——GUI/脚本消费者契约。
        let report = Doctor.Report(
            overall: "protected", nativeArch: "arm64", build: "270351",
            appPath: "/Applications/WeChat.app", configKnown: true,
            configTargets: ["revoke"], sip: "enabled", amfiRisk: nil,
            running: false, writable: true, signature: "adhoc",
            entitlementsOk: true, entitlementKeyCount: 2, restrictedEntitlements: true,
            patchStates: ["revoke": "patched"], manifest: nil,
            auditState: "fresh",
            recentCrashReports: Doctor.CrashSummary(
                count: 2, mostRecent: "wechat-cs-kill.ips", codesigning: 1),
            gatekeeperAssessment: "rejected（ad-hoc 预期态；本机放行判据见 AMFI risk 行）",
            verdicts: [], nextCommand: nil)
        let data = try JSONEncoder().encode(report)
        let text = String(decoding: data, as: UTF8.self)
        for key in ["\"audit_state\":\"fresh\"", "\"recent_crash_reports\"",
                    "\"most_recent\":\"wechat-cs-kill.ips\"", "\"codesigning\":1",
                    "\"gatekeeper_assessment\""] {
            #expect(text.contains(key), "JSON 契约键 \(key) 在场")
        }
    }
}
