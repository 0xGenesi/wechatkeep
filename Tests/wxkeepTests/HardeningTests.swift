import Foundation
import Testing
@testable import wxkeep

/// 71 轮深审的三处加固回归：
/// 1. SafeWrite——主可执行整体覆写的原子性 + 权限保留（.atomic 替换文件
///    默认 0644，可执行位丢失 = 微信无法启动）
/// 2. pgrepPattern——ERE 元字符转义（非法 regex → pgrep 退出 2 → 被当成
///    「没在运行」→ 微信运行中继续 patch）
/// 3. isRunning 端到端——带括号的真实路径在修复前判 false
struct HardeningTests {
    // MARK: - SafeWrite

    @Test func overwritePreservesPermissionsAndUpdatesContent() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-safewrite-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("exec")

        try Data([0xAA]).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)

        try SafeWrite.overwrite(Data([0xBB, 0xCC]), to: url)

        let perms = (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions]) as! NSNumber
        #expect(perms.intValue == 0o755, ".atomic 替换后可执行位必须保留")
        #expect(try Data(contentsOf: url) == Data([0xBB, 0xCC]), "内容必须更新")
    }

    @Test func overwriteCreatesMissingFile() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-safewrite-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("new-file")
        try SafeWrite.overwrite(Data([0x01]), to: url)
        #expect(try Data(contentsOf: url) == Data([0x01]))
    }

    // MARK: - pgrep pattern escaping

    @Test func pgrepPatternEscapesEREMetacharacters() {
        // `.` 也是元字符（无转义时 WeChatXapp 会假阳性命中）——.app → \.app
        #expect(WeChatApp.pgrepPattern(for: URL(fileURLWithPath: "/Applications/WeChat.app"))
                == "/Applications/WeChat\\.app/Contents/MacOS")
        // 全部 ERE 元字符逐个转义
        #expect(WeChatApp.pgrepPattern(for: URL(fileURLWithPath: "/a\\b[]{}()*+?^$|().app"))
                == "/a\\\\b\\[\\]\\{\\}\\(\\)\\*\\+\\?\\^\\$\\|\\(\\)\\.app/Contents/MacOS")
        // 克隆命名（带空格）：空格不是元字符，不转义
        #expect(WeChatApp.pgrepPattern(for: URL(fileURLWithPath: "/Applications/WeChat wxkeep 1.app"))
                == "/Applications/WeChat wxkeep 1\\.app/Contents/MacOS")
    }

    /// 端到端：带括号的路径（合法目录名）在修复前 pgrep 收到非法 ERE 以
    /// 退出码 2/1 失败 → isRunning 恒 false（微信运行中被误判为未运行，
    /// patch 照跑）；修复后应正确判 true。载体 = sh 双命令形态——单命令
    /// 会被 sh exec 优化掉（注释不进最终 cmdline），双命令保 sh 存活为
    /// 解释器、完整 argv 留在进程表。
    @Test func isRunningDetectsPathWithParentheses() throws {
        let fake = URL(fileURLWithPath: "/tmp/wxkeep-isrunning (1).testapp")
        let carrier = Process()
        carrier.executableURL = URL(fileURLWithPath: "/bin/sh")
        carrier.arguments = ["-c",
                             "sleep 6; exit 0 # " + fake.path + "/Contents/MacOS/WeChat"]
        try carrier.run()
        defer {
            if carrier.isRunning { carrier.terminate() }
            carrier.waitUntilExit()
        }
        // 进程注册有延迟：轮询至多 ~2s
        var detected = false
        for _ in 0..<20 {
            if WeChatApp.isRunning(app: fake) { detected = true; break }
            usleep(100_000)
        }
        #expect(detected, "带括号路径的运行进程必须被 isRunning 识别")
        carrier.terminate()
        _ = carrier.waitUntilExit()
        // 收尾判净：pattern 不再命中（孤儿 sleep 子进程的 cmdline 是
        // "sleep 6"，不含路径，不参与匹配）
        var gone = false
        for _ in 0..<20 {
            if !WeChatApp.isRunning(app: fake) { gone = true; break }
            usleep(100_000)
        }
        #expect(gone, "终止后应不再匹配")
    }
}
