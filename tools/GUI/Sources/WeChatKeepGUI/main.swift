// WeChatKeepGUI — wxkeep 的菜单栏面板（零依赖，AppKit）。
//
// 职责刻意收窄：只做【只读状态展示 + 命令代备】。patch/restore 需 root，
// GUI 不做提权（那是特权助手要解决的独立课题），改为把 doctor 给出的
// next_command 一键复制 / 一键在终端执行——诚实且无攻击面。
//
// CLI 定位顺序：环境变量 WXKEEP_GUI_CLI → 可执行文件同目录 → /usr/local/bin/wxkeep。

import AppKit

struct DoctorReport {
    let build: String
    let overall: String
    let running: Bool
    let nextCommand: String
    let verdicts: [String]
    let patchStates: [(String, String)]

    init?(json: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let build = obj["build"] as? String,
              let overall = obj["overall"] as? String else { return nil }
        self.build = build
        self.overall = overall
        self.running = (obj["running"] as? Bool) ?? false
        self.nextCommand = (obj["next_command"] as? String) ?? ""
        self.verdicts = (obj["verdicts"] as? [String]) ?? []
        var states: [(String, String)] = []
        if let ps = obj["patch_states"] as? [String: String] {
            states = ps.map { ($0.key, $0.value) }.sorted { $0.0 < $1.0 }
        }
        self.patchStates = states
    }
}

let overallText: [String: String] = [
    "protected": "✅ 已防护",
    "partial": "🟡 部分防护",
    "unprotected": "⛔️ 未防护",
]

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    var cliPath: String {
        if let p = ProcessInfo.processInfo.environment["WXKEEP_GUI_CLI"] { return p }
        let beside = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
            .appendingPathComponent("wxkeep").path
        if FileManager.default.isExecutableFile(atPath: beside) { return beside }
        return "/usr/local/bin/wxkeep"
    }
    var lastReport: DoctorReport?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem.button?.title = "🛡"
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        refresh(nil)
    }

    @objc func refresh(_ sender: Any?) {
        let report = runDoctor()
        lastReport = report
        rebuildMenu(report)
    }

    func runDoctor() -> DoctorReport? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cliPath)
        p.arguments = ["doctor", "--json"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return DoctorReport(json: data)
    }

    func rebuildMenu(_ report: DoctorReport?) {
        let menu = statusItem.menu!
        menu.removeAllItems()

        guard let r = report else {
            menu.addItem(withTitle: "无法读取 wxkeep（doctor --json 失败）", action: nil, keyEquivalent: "")
            menu.addItem(withTitle: "CLI 路径：\(cliPath)", action: nil, keyEquivalent: "")
            menu.addItem(.separator())
            menu.addItem(withTitle: "重试", action: #selector(refresh(_:)), keyEquivalent: "r").target = self
            menu.addItem(quitItem())
            return
        }

        let state = overallText[r.overall] ?? r.overall
        let head = menu.addItem(withTitle: "构建 \(r.build) — \(state)\(r.running ? "（微信运行中）" : "")",
                                action: nil, keyEquivalent: "")
        head.isEnabled = false
        for (target, value) in r.patchStates {
            let mark = value == "patched" ? "●" : (value == "pristine" ? "○" : "◐")
            menu.addItem(withTitle: "    \(mark) \(target)：\(value)", action: nil, keyEquivalent: "").isEnabled = false
        }
        for v in r.verdicts.prefix(3) {
            let item = menu.addItem(withTitle: "    · \(v)", action: nil, keyEquivalent: "")
            item.isEnabled = false
        }
        menu.addItem(.separator())
        if !r.nextCommand.isEmpty {
            menu.addItem(withTitle: "📋 复厂建议命令：\(r.nextCommand)", action: nil, keyEquivalent: "").isEnabled = false
            let copy = menu.addItem(withTitle: "复制命令", action: #selector(copyNext(_:)), keyEquivalent: "c")
            copy.target = self
            if !r.running {
                let run = menu.addItem(withTitle: "在终端执行…", action: #selector(runInTerminal(_:)), keyEquivalent: "t")
                run.target = self
            }
            menu.addItem(.separator())
        }
        menu.addItem(withTitle: "刷新", action: #selector(refresh(_:)), keyEquivalent: "r").target = self
        menu.addItem(quitItem())
        statusItem.button?.title = r.overall == "protected" ? "🛡" : (r.overall == "partial" ? "🧯" : "⚠️")
    }

    func quitItem() -> NSMenuItem {
        let q = NSMenuItem(title: "退出 WeChatKeep", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        q.target = NSApp
        return q
    }

    @objc func copyNext(_ sender: Any?) {
        guard let cmd = lastReport?.nextCommand else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(cmd, forType: .string)
    }

    @objc func runInTerminal(_ sender: Any?) {
        guard let cmd = lastReport?.nextCommand else { return }
        let script = "tell application \"Terminal\"\nactivate\ndo script \"\(cmd.replacingOccurrences(of: "\"", with: "\\\""))\"\nend tell"
        if let appleScript = try? NSAppleScript(source: script) {
            var err: NSDictionary?
            appleScript.executeAndReturnError(&err)
        }
    }

    // 菜单展开前自动刷新一次（状态永不过期）
    func menuWillOpen(_ menu: NSMenu) { refresh(nil) }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
