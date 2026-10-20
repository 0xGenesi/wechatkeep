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
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus == 0 }
        catch { return false }
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
    }

    @discardableResult
    static func run(_ executable: String, _ arguments: [String]) -> Result {
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
        process.waitUntilExit()
        let stdoutData = (try? Data(contentsOf: outURL)) ?? Data()
        let stderrData = (try? Data(contentsOf: errURL)) ?? Data()
        return Result(
            status: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "",
            signalled: process.terminationReason == .uncaughtSignal)
    }
}
