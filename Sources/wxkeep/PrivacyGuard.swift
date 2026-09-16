import Foundation

/// Privacy hardening — minimize WeChat's telemetry/diagnostic reporting at
/// the preferences layer. Zero binary changes; the same cfprefd-domain
/// constraint as UpdateGuard applies (WeChat must be quit for writes to
/// stick — the CLI guards this).
enum PrivacyGuard {
    static let domain = "com.tencent.xinWeChat"

    /// Keys to disable. Values verified against on-device prefs + community
    /// knowledge; "1" means reporting ON (bad) → we write "0".
    /// Keys that don't exist in a given install are simply set — harmless.
    static let keys: [(key: String, meaning: String)] = [
        ("SUSendProfileInfo", "Sparkle 更新遥测上报"),
        ("TencentDevTools", "开发者诊断通道"),
        ("EnableCrashReport", "崩溃报告上传"),
        ("EnableDiagnosticLog", "诊断日志上传"),
        ("JMZFLogicReportSwitch", "逻辑埋点上报"),
        ("JMZFPerformanceReportSwitch", "性能埋点上报"),
        ("KMReservedKey1", "诊断组件预留开关"),
    ]

    struct Status {
        let key: String
        let value: String
        let guarded: Bool
        let meaning: String
    }

    static func read() -> [Status] {
        keys.map { spec in
            let r = Shell.run("/usr/bin/defaults", ["read", domain, spec.key])
            let value = r.status == 0
                ? r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                : "<unset>"
            return Status(key: spec.key, value: value,
                          guarded: value == "0", meaning: spec.meaning)
        }
    }

    static var allGuarded: Bool { read().allSatisfy(\.guarded) }

    @discardableResult
    static func disable() -> Bool {
        for spec in keys {
            _ = Shell.run("/usr/bin/defaults", ["write", domain, spec.key, "-bool", "0"])
        }
        _ = Shell.run("/usr/bin/killall", ["-hup", "cfprefsd"])
        return allGuarded
    }

    static func render(_ statuses: [Status]) -> String {
        statuses.map { s in
            let mark = s.guarded ? "✓" : "✗"
            return "  [\(mark)] \(s.key) = \(s.value)  (\(s.meaning))"
        }.joined(separator: "\n")
    }
}
