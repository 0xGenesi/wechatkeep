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
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        do {
            try process.run()
        } catch {
            return Result(status: 127, stdout: "", stderr: error.localizedDescription)
        }
        // Read BOTH pipes concurrently: draining one to EOF first deadlocks if
        // the child fills the other pipe's 64KB buffer (codesign verbose on a
        // 340MB bundle can exceed it).
        let group = DispatchGroup()
        let lock = NSLock()
        var stdoutData = Data(), stderrData = Data()
        group.enter()
        DispatchQueue.global().async {
            let d = out.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); stdoutData = d; lock.unlock(); group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            let d = err.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); stderrData = d; lock.unlock(); group.leave()
        }
        group.wait()
        process.waitUntilExit()
        return Result(
            status: process.terminationStatus,
            stdout: String(data: stdoutData, encoding: .utf8) ?? "",
            stderr: String(data: stderrData, encoding: .utf8) ?? "")
    }
}
