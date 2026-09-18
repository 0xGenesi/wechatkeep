import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Blocks WeChat's updater at the preferences layer — zero binary changes.
///
/// The Sparkle channel is prefs-driven and the accidental-upgrade risk is
/// exactly these three switches:
///   SUEnableAutomaticChecks → no update checks at all, no prompts
///   SUAutomaticallyUpdate   → never download/install without asking
///   SUSendProfileInfo       → telemetry off as a bonus
/// Writes route to the app's sandboxed container domain via cfprefd.
///
/// 诚实边界（2026-09 实证复盘）：微信 4.1.13+ 的更新管理器会在**启动时把
/// SUEnableAutomaticChecks / SUAutomaticallyUpdate 改回 1**（zengtianli 定位
/// 脚本结论 + 本机观测：两键被改回、SULastCheckTime 持续刷新）。三键中只有
/// SUSendProfileInfo 存活。改写者在 4.1.15 已定位为回归的 XAppUpdateManager
/// + Sparkle 2.6.4 fork（docs/findings-269602-updater.md 2026-09-18 节）——
/// 269602 有 mmui 周期工人的字节级目标、270099 x64 有 XAppUpdateManager
/// 四方法条目（待真机行为验证）。因此本层只是 best-effort：
/// - 旧构建 / 未重写的构建：三键有效
/// - 4.1.13+：遥测键有效，更新开关会被改回（rewrittenByApp 可检出）
/// 二进制级目标随 `wxkeep patch` 附带；升级发生后重跑 `wxkeep doctor` 重新评估。
enum UpdateGuard {
    static let domain = "com.tencent.xinWeChat"
    static let keys: [(key: String, guardedValue: String, meaning: String)] = [
        ("SUEnableAutomaticChecks", "0", "不检查更新（无弹窗；4.1.13+ 会被微信改回）"),
        ("SUAutomaticallyUpdate", "0", "绝不自动安装（4.1.13+ 会被微信改回）"),
        ("SUSendProfileInfo", "0", "关闭更新遥测上报（实测存活）"),
    ]

    struct Status {
        let key: String
        let value: String
        let guarded: Bool
        let meaning: String
    }

    static func read() -> [Status] {
        keys.map { spec in
            let result = Shell.run("/usr/bin/defaults", ["read", domain, spec.key])
            let value = result.status == 0
                ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                : "<unset>"
            return Status(key: spec.key, value: value,
                          guarded: value == spec.guardedValue, meaning: spec.meaning)
        }
    }

    static var allGuarded: Bool { read().allSatisfy(\.guarded) }

    /// 上次成功写防护的标记（用户级数据目录，内容=时间戳）。
    static var markerURL: URL { Config.userDataURL.appendingPathComponent("update-guard.marker") }

    /// 「写过 0、现在读到 1」→ 微信已把更新开关改回（4.1.13+ 已知行为），
    /// 偏好层防护失守。从未写过（无标记）则不判定。纯函数便于测试。
    static func rewritten(_ statuses: [Status], markerExists: Bool) -> Bool {
        guard markerExists else { return false }
        let toggles: Set<String> = ["SUEnableAutomaticChecks", "SUAutomaticallyUpdate"]
        return statuses.contains { toggles.contains($0.key) && !$0.guarded }
    }

    static var rewrittenByApp: Bool {
        rewritten(read(), markerExists: FileManager.default.fileExists(atPath: markerURL.path))
    }

    /// Applies all three guarded values. Idempotent.
    @discardableResult
    static func disable() -> Bool {
        let ok = apply(guarded: true)
        if ok {
            try? FileManager.default.createDirectory(
                at: markerURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? Data("\(Date().timeIntervalSince1970)".utf8).write(to: markerURL)
        }
        return ok
    }

    /// Restores update checks (user asked for it explicitly).
    @discardableResult
    static func enable() -> Bool {
        // 用户明确要求恢复更新——改回检测标记一并清除（不再把后续的 1 判为「微信改回」）
        try? FileManager.default.removeItem(at: markerURL)
        return apply(guarded: false)
    }

    /// Root context (sudo patch) writes to ROOT's prefs — cfprefd drops or
    /// misroutes them for the user-owned sandboxed domain. Delegate to the
    /// console user via launchctl asuser so the write lands in THEIR plist.
    private static func defaultsArgs(_ args: [String]) -> [String] {
        if geteuid() != 0 { return ["/usr/bin/defaults"] + args }
        let consoleUser = Shell.run("/usr/bin/stat", ["-f", "%Su", "/dev/console"]).stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !consoleUser.isEmpty, consoleUser != "root",
              let uidNum = Int(Shell.run("/usr/bin/id", ["-u", consoleUser]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return ["/usr/bin/defaults"] + args
        }
        return ["/bin/launchctl", "asuser", String(uidNum),
                "/usr/bin/sudo", "-u", consoleUser, "/usr/bin/defaults"] + args
    }

    private static func apply(guarded: Bool) -> Bool {
        for spec in keys {
            let value = guarded ? "false" : "true"   // defaults CLI 需要 true/false 字面量
            let args = defaultsArgs(["write", domain, spec.key, "-bool", value])
            _ = Shell.run(args[0], Array(args[1...]))
        }
        _ = Shell.run("/usr/bin/killall", ["-hup", "cfprefsd"])
        return allGuarded
    }

    static func render(_ statuses: [Status]) -> String {
        statuses.map { status in
            let mark = status.guarded ? "✓" : "✗"
            return "  [\(mark)] \(status.key) = \(status.value)  (\(status.meaning))"
        }.joined(separator: "\n")
    }
}
