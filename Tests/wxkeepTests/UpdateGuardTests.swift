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
}
