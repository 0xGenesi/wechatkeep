import Foundation

/// Blocks WeChat's updater at the preferences layer — zero binary changes.
///
/// On 269602+ the binary-level updater block is unavailable (the updater is
/// pure C++, no ObjC metadata to locate; see docs/findings-269602-updater.md),
/// but the Sparkle channel remains prefs-driven and the accidental-upgrade
/// risk is exactly these three switches:
///   SUEnableAutomaticChecks → no update checks at all, no prompts
///   SUAutomaticallyUpdate   → never download/install without asking
///   SUSendProfileInfo       → telemetry off as a bonus
/// Writes route to the app's sandboxed container domain via cfprefd.
enum UpdateGuard {
    static let domain = "com.tencent.xinWeChat"
    static let keys: [(key: String, guardedValue: String, meaning: String)] = [
        ("SUEnableAutomaticChecks", "0", "不检查更新（无弹窗）"),
        ("SUAutomaticallyUpdate", "0", "绝不自动安装"),
        ("SUSendProfileInfo", "0", "关闭更新遥测上报"),
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

    /// Applies all three guarded values. Idempotent.
    @discardableResult
    static func disable() -> Bool {
        for spec in keys {
            _ = Shell.run("/usr/bin/defaults", ["write", domain, spec.key, "-bool", spec.guardedValue])
        }
        // cfprefd caches aggressively for sandboxed domains — flush and re-read.
        _ = Shell.run("/usr/bin/killall", ["-hup", "cfprefsd"])
        return allGuarded
    }

    /// Restores update checks (user asked for it explicitly).
    @discardableResult
    static func enable() -> Bool {
        for spec in keys where spec.key != "SUSendProfileInfo" {
            _ = Shell.run("/usr/bin/defaults", ["write", domain, spec.key, "-bool", "1"])
        }
        _ = Shell.run("/usr/bin/killall", ["-hup", "cfprefsd"])
        return read().filter { $0.key != "SUSendProfileInfo" }.allSatisfy { $0.value == "1" }
    }

    static func render(_ statuses: [Status]) -> String {
        statuses.map { status in
            let mark = status.guarded ? "✓" : "✗"
            return "  [\(mark)] \(status.key) = \(status.value)  (\(status.meaning))"
        }.joined(separator: "\n")
    }
}
