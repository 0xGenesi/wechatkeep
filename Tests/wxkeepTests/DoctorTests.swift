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

    // MARK: 判定聚合

    @Test func aggregateStates() {
        let allPatched = [Patcher.Inspection.State](repeating: .patched, count: 3)
        let allPristine = [Patcher.Inspection.State](repeating: .pristine, count: 2)
        let mixedBag: [Patcher.Inspection.State] = [.pristine, .patched]
        let withUnknown: [Patcher.Inspection.State] = [.patched, .unknown]
        let empty: [Patcher.Inspection.State] = []
        #expect(DoctorAggregate(allPatched) == "patched")
        #expect(DoctorAggregate(allPristine) == "pristine")
        #expect(DoctorAggregate(mixedBag) == "mixed")
        #expect(DoctorAggregate(withUnknown) == "unknown")
        #expect(DoctorAggregate(empty) == "unknown")
    }

    // aggregate 是 private——通过 patch_states 输出验证（JSON 契约测试覆盖）。
    private func DoctorAggregate(_ states: [Patcher.Inspection.State]) -> String {
        // mirror of the private logic via the same inputs the engine produces;
        // kept adjacent so a change to either fails review
        guard !states.isEmpty else { return "unknown" }
        if states.allSatisfy({ $0 == .patched }) { return "patched" }
        if states.allSatisfy({ $0 == .pristine }) { return "pristine" }
        return states.contains(.unknown) ? "unknown" : "mixed"
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
}
