import Foundation
#if canImport(Darwin)
import Darwin
#endif

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
            let guarded = (value == "0") || (value == "<unset>")
            return Status(key: spec.key, value: value, guarded: guarded, meaning: spec.meaning)
        }
    }

    static var allGuarded: Bool { read().allSatisfy(\.guarded) }

    @discardableResult
    static func disable() -> Bool {
        // sudo 场景：root 对用户沙盒域的写会被 cfprefd 丢弃 → 委托给 console user
        // 非root：直接写（用户域，cfprefd 接受）。root：委托 console user。
        // geteuid 需要 Darwin 导入（文件头已有）。
        let asUser = geteuid() == 0
        let console = asUser
            ? Shell.run("/usr/bin/stat", ["-f", "%Su", "/dev/console"]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            : ""
        for spec in keys {
            // unset 的键微信内部默认按关处理——强写反而制造无意义状态，跳过
            let exists = Shell.run("/usr/bin/defaults", ["read", domain, spec.key]).status == 0
            guard exists else { continue }
            var args = ["/usr/bin/defaults", "write", domain, spec.key, "-bool", "0"]
            if asUser {
                let uid = Shell.run("/usr/bin/id", ["-u", console]).stdout
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                args = ["/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-u", console] + args
            }
            _ = Shell.run(args[0], Array(args[1...]))
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
