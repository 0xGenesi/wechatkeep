import Foundation

/// App-bundle helpers: version, running check, binary resolution, writability.
enum WeChatApp {
    enum AppError: Error, CustomStringConvertible {
        case invalidApp(String)
        case running

        var description: String {
            switch self {
            case .invalidApp(let path):
                "\(path) is not a WeChat.app bundle — pass --app /Applications/WeChat.app"
            case .running:
                "WeChat is still running. Quit it completely first (⌘Q, then wait ~10 s: "
                + "helper processes linger), then re-run. Check: pgrep -fl WeChat.app/Contents/MacOS"
            }
        }
    }

    static func validate(_ url: URL) throws {
        let plist = url.appendingPathComponent("Contents/Info.plist")
        guard FileManager.default.fileExists(atPath: plist.path) else {
            throw AppError.invalidApp(url.path)
        }
    }

    /// CFBundleVersion — the build number that keys the catalog (e.g. "269602").
    static func buildNumber(app: URL) throws -> String {
        guard let bundle = Bundle(url: app),
              let version = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
              !version.isEmpty
        else { throw AppError.invalidApp(app.path) }
        return version
    }

    /// CFBundleShortVersionString — the marketing version (e.g. "4.1.15").
    /// Build numbers are the catalog key, but users think in marketing
    /// versions; showing both removes the #1 community confusion.
    static func marketingVersion(app: URL) -> String? {
        guard let bundle = Bundle(url: app),
              let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
              !version.isEmpty
        else { return nil }
        return version
    }

    /// pgrep -f 的 pattern 是 ERE 正则：路径里的元字符（括号/加号/点等——
    /// 「WeChat (1).app」「WeChat+2.app」这类目录名完全合法）会让正则非法
    /// 或错配；pgrep 对非法 regex 以退出码 2 失败，会被下方当成「没在运行」
    /// ——微信运行中继续 patch 是真事故。转义全部 ERE 元字符（纯函数，
    /// isRunningTests 端到端回归）。
    static func pgrepPattern(for app: URL) -> String {
        let raw = "\(app.path)/Contents/MacOS"
        let metachars = "\\.[]{}()*+?^$|()"
        var out = ""
        for ch in raw {
            if metachars.contains(ch) { out.append("\\") }
            out.append(ch)
        }
        return out
    }

    static func isRunning(app: URL) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-f", pgrepPattern(for: app)]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        // 143 轮 A-7：pgrep 启动失败（fork/资源耗尽）原按「未运行」放行
        // ——fail-open 会把「运行中进程的可执行定点写」放进窗口。改
        // fail-closed（按运行中拒）：代价是极罕见态下的一次重试，方向
        // 与其余守卫一致（红向安全）。
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus == 0 }
        catch { return true }
    }

    static func binaryURL(app: URL, relative: String?) -> URL {
        let path = relative ?? "Contents/MacOS/WeChat"
        return URL(fileURLWithPath: app.path).appendingPathComponent(path)
    }

    static func isWritable(_ url: URL) -> Bool {
        FileManager.default.isWritableFile(atPath: url.path)
    }
}

// MARK: - Shell helper (used by pgrep above and codesign in M3)

enum Shell {
    struct Result {
        let status: Int32
        let stdout: String
        let stderr: String
        /// 子进程死于信号时为真（terminationReason == .uncaughtSignal）。
        /// 此时 Darwin Foundation 的 status 是**裸信号号**（SIGKILL→9，实测），
        /// 不是 shell 约定的 128+n——退出码语义必须结合本字段判读。
        let signalled: Bool
        /// 141 轮 P1-1：deadline 到点被杀的子进程为真（status=SIGKILL 裸值
        /// 9 + signalled——调用方以此区分「挂死被杀」与「真崩溃」）。
        let timedOut: Bool

        init(status: Int32, stdout: String, stderr: String,
             signalled: Bool, timedOut: Bool = false) {
            self.status = status
            self.stdout = stdout
            self.stderr = stderr
            self.signalled = signalled
            self.timedOut = timedOut
        }
    }

    /// 141 轮 P1-1（挂死收口，作用域从严）：verify/parse-oracle worker 与
    /// lipo -thin 这类「秒级应完成」的子进程加 deadline——映射函数/畸形
    /// 镜像卡死时父进程不再无限等（挂死=未建模状态的另一形态，须有出口
    /// 而非 CLI 整条命令冻死）。codesign（340MB deep 校验分钟级合法）与
    /// 其它调用点**不加**——一刀切超时会误杀慢而正常的重签（反向证伪过的
    /// 收紧面）。
    @discardableResult
    static func run(_ executable: String, _ arguments: [String],
                    deadline: TimeInterval? = nil) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        // stdout/stderr 都走 TEMP FILE：子进程派生的 helper 若继承管道 fd 且
        // 永不退出，readDataToEndOfFile 永远等不到 EOF（stderr 侧曾在 CI 实测
        // 挂死——stdout 是同一类隐患，只是还没被踩到）。文件无此生命周期。
        let tmp = FileManager.default.temporaryDirectory
        let outURL = tmp.appendingPathComponent("wxkeep-sh-\(UUID().uuidString).out")
        let errURL = tmp.appendingPathComponent("wxkeep-sh-\(UUID().uuidString).err")
        FileManager.default.createFile(atPath: outURL.path, contents: nil)
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let outHandle = try? FileHandle(forWritingTo: outURL)
        let errHandle = try? FileHandle(forWritingTo: errURL)
        process.standardOutput = outHandle ?? nil
        process.standardError = errHandle ?? nil
        defer {
            try? outHandle?.close()
            try? errHandle?.close()
            try? FileManager.default.removeItem(at: outURL)
            try? FileManager.default.removeItem(at: errURL)
        }
        do {
            try process.run()
        } catch {
            return Result(status: 127, stdout: "", stderr: error.localizedDescription, signalled: false)
        }
        // 141 轮 P1-1：deadline 语义 = 到点 SIGKILL + timedOut=true（status
        // 是裸 9——与真 SIGKILL 的区分面只有本字段）。
        var timedOut = false
        if let deadline {
            let wall = Date().addingTimeInterval(deadline)
            while process.isRunning && Date() < wall {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                timedOut = true
                process.interrupt()
                // interrupt/terminate（SIGINT/SIGTERM）对挂死在不可中断态的
                // 进程可能无效——1s 宽限后 SIGKILL 直杀（kill(2) 绕过
                // Foundation 的有限信号面；SIGKILL 后 waitUntilExit 必然返回，
                // 父进程不再有无限等待面）。
                for _ in 0..<20 where process.isRunning {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
                process.waitUntilExit()
            }
        } else {
            process.waitUntilExit()
        }
        let stdoutData = (try? Data(contentsOf: outURL)) ?? Data()
        let stderrData = (try? Data(contentsOf: errURL)) ?? Data()
        return Result(
            status: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: timedOut
                ? (String(data: stderrData, encoding: .utf8) ?? "")
                  + "\n[wxkeep] 子进程 \(deadline.map { String(format: "%.0f", $0) } ?? "?")s 未完成——已终止（挂死收口，141 轮）"
                : String(data: stderrData, encoding: .utf8) ?? "",
            signalled: process.terminationReason == .uncaughtSignal,
            timedOut: timedOut)
    }
}
