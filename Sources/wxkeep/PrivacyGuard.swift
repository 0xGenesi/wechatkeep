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

    /// root 语境的委托链解析（111 轮修）：console 用户名/uid 不可解析
    ///（stat 失败 / ssh 无 GUI 会话 / 登录窗口态）时委托链必然失败——
    /// 返回 nil，调用方如实报「无法操作」而不是把「读不到」伪装成已关。
    static func consoleDelegation() -> (console: String, uid: String)? {
        guard geteuid() == 0 else { return nil }   // 非 root 无需委托
        let console = Shell.run("/usr/bin/stat", ["-f", "%Su", "/dev/console"])
            .stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !console.isEmpty, console != "root" else { return nil }
        let uid = Shell.run("/usr/bin/id", ["-u", console]).stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !uid.isEmpty, uid.allSatisfy(\.isNumber) else { return nil }
        return (console, uid)
    }

    static func read() -> [Status] {
        keys.map { spec in
            // root 语境委托控制台用户读（disable 同款；否则 sudo status 读
            // root 域误报「未开启」）。委托链不可用 = 该键状态不可知（≠已关）。
            let r: Shell.Result
            if let dlg = consoleDelegation() {
                r = Shell.run("/bin/launchctl", ["asuser", dlg.uid, "/usr/bin/sudo", "-u", dlg.console,
                                                 "/usr/bin/defaults", "read", domain, spec.key])
            } else if geteuid() == 0 {
                return Status(key: spec.key, value: "<unreadable>", guarded: false, meaning: spec.meaning)
            } else {
                r = Shell.run("/usr/bin/defaults", ["read", domain, spec.key])
            }
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
        // 委托链不可用（111 轮修）：如实失败——此前探针失败 → 全部跳写 →
        // 同链读回「<unset>」被当 guarded →「✓ 已最小化」的空转误报。
        let asUser = geteuid() == 0
        let dlg = consoleDelegation()
        if asUser && dlg == nil { return false }   // root 且无法定位控制台用户（ssh/登录窗口态）
        let console = dlg?.console ?? "", uid = dlg?.uid ?? ""
        /// 与写侧同域的 defaults 参数（108 轮修：exists 探针原先裸读 root 域
        /// ——sudo 下恒不存在 → 全部跳写 → allGuarded 委托读用户域恒 false
        /// →「✗ 请重试」死循环。探针与写必须查同一个域）。
        func delegated(_ args: [String]) -> [String] {
            guard asUser, let dlg else { return args }
            return ["/bin/launchctl", "asuser", dlg.uid, "/usr/bin/sudo", "-u", dlg.console] + args
        }
        for spec in keys {
            // unset 的键微信内部默认按关处理——强写反而制造无意义状态，跳过
            let probe = delegated(["/usr/bin/defaults", "read", domain, spec.key])
            let exists = Shell.run(probe[0], Array(probe[1...])).status == 0
            guard exists else { continue }
            let args = delegated(["/usr/bin/defaults", "write", domain, spec.key, "-bool", "0"])
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
