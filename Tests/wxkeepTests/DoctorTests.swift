import Foundation
import Testing
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
}
