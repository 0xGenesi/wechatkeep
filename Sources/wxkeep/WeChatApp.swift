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

    static func isRunning(app: URL) -> Bool {
        let pattern = "\(app.path)/Contents/MacOS"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-f", pattern]
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
    }

    @discardableResult
    static func run(_ executable: String, _ arguments: [String]) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        // stdout: pipe (we parse it). stderr: TEMP FILE — a child whose helper
        // inherits the stderr pipe fd and never exits would make read-to-EOF
        // hang forever (observed as a stuck CI Test step); a file has no such
        // lifecycle, and one pipe alone cannot deadlock.
        let out = Pipe()
        process.standardOutput = out
        let errURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-sh-\(UUID().uuidString).err")
        FileManager.default.createFile(atPath: errURL.path, contents: nil)
        let errHandle = try? FileHandle(forWritingTo: errURL)
        process.standardError = errHandle ?? nil
        defer {
            try? errHandle?.close()
            try? FileManager.default.removeItem(at: errURL)
        }
        do {
            try process.run()
        } catch {
            return Result(status: 127, stdout: "", stderr: error.localizedDescription)
        }
        let stdoutData = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let stderrData = (try? Data(contentsOf: errURL)) ?? Data()
        return Result(
            status: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "")
    }
}
