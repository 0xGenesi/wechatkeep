import Foundation
#if canImport(Darwin)
import Darwin
#endif

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
    static func disable() -> Bool { apply(guarded: true) }

    /// Restores update checks (user asked for it explicitly).
    @discardableResult
    static func enable() -> Bool { apply(guarded: false) }

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
            let value = guarded ? spec.guardedValue : "1"
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
