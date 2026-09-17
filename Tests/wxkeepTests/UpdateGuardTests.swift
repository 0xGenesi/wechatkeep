import Foundation
import Testing
@testable import wxkeep

/// UpdateGuard 的写入路径依赖 cfprefd 域所有权（微信运行时写入被丢弃，
/// 由 CLI 层的运行中检测保护），这里测试读取结构与渲染。
struct UpdateGuardTests {
    @Test func readCoversAllThreeKeys() {
        let statuses = UpdateGuard.read()
        #expect(statuses.count == 3)
        #expect(statuses.map(\.key) == ["SUEnableAutomaticChecks", "SUAutomaticallyUpdate", "SUSendProfileInfo"])
        // 未设置的键读作 <unset> 而非崩溃
        _ = statuses.map(\.value)
    }

    @Test func renderMarksGuardedState() {
        let statuses = [
            UpdateGuard.Status(key: "SUEnableAutomaticChecks", value: "0", guarded: true, meaning: "a"),
            UpdateGuard.Status(key: "SUAutomaticallyUpdate", value: "1", guarded: false, meaning: "b"),
        ]
        let text = UpdateGuard.render(statuses)
        #expect(text.contains("[✓] SUEnableAutomaticChecks = 0"))
        #expect(text.contains("[✗] SUAutomaticallyUpdate = 1"))
    }

    // MARK: 改回检测（4.1.13+ 微信启动时重写更新开关——2026-09 本机实证）

    private func status(_ key: String, _ value: String) -> UpdateGuard.Status {
        UpdateGuard.Status(key: key, value: value, guarded: value == "0", meaning: "")
    }

    @Test func rewrittenDetectedOnlyWithMarkerAndEnabledToggle() {
        let keysOn = [status("SUEnableAutomaticChecks", "0"),
                      status("SUAutomaticallyUpdate", "0"),
                      status("SUSendProfileInfo", "0")]
        let togglesBack = [status("SUEnableAutomaticChecks", "1"),   // ← 被微信改回
                           status("SUAutomaticallyUpdate", "0"),
                           status("SUSendProfileInfo", "0")]
        let telemetryOnly = [status("SUEnableAutomaticChecks", "0"),
                             status("SUAutomaticallyUpdate", "0"),
                             status("SUSendProfileInfo", "1")]   // 非开关键不参与判定

        #expect(!UpdateGuard.rewritten(keysOn, markerExists: true), "全键有效 → 未失守")
        #expect(UpdateGuard.rewritten(togglesBack, markerExists: true), "写过且开关被改回 → 失守")
        #expect(!UpdateGuard.rewritten(togglesBack, markerExists: false), "从未写过（无标记）→ 不判定")
        #expect(!UpdateGuard.rewritten(telemetryOnly, markerExists: true), "遥测键被改回不算失守")
    }
}
