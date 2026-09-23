import Foundation

/// Timestamped safety copies of any binary before its bytes are modified.
/// The engine's restore path inverts patches via `expected[0]`; these backups
/// are the belt-and-suspenders layer for foreign-byte / disk-error situations.
enum Backup {
    enum BackupError: Error, CustomStringConvertible {
        case copyFailed(String)

        var description: String {
            switch self {
            case .copyFailed(let detail):
                "backup failed: \(detail). Refusing to patch without a safety copy."
            }
        }
    }

    /// 同目录下最多保留的 wxkeep-bak 数量（保留最新 N 个；二进制备份
    /// 340MB/个，无上限会吃满磁盘）。
    static let keepCount = 3

    /// binary 是否为某 .app bundle 的主可执行（Contents/MacOS/<CFBundleExecutable>）。
    /// 主可执行的备份**不能留在 bundle 内**（2026-09-23 实测双杀，d28_live
    /// 实弹轮当场炸出）：
    /// - 在场：root 浅签会把 MacOS/ 下的文件封进 CodeResources，且
    ///   `codesign --verify --deep --strict` 把可执行副本当子代码对象校验——
    ///   ad-hoc + restricted entitlements 态的副本脱离主位即验败
    ///   （invalid Info.plist）→ Resigner 硬验证失败 → runtime install/remove 必炸；
    /// - 被删（prune 轮换后）：root 封印缺文件 → sealed resource missing。
    /// dylib 备份（Resources/ 下的副本）实证无害（多轮 restore 后 verify OK），
    /// 维持原位——就近恢复的工作流不变。
    static func isBundleMainExecutable(_ binary: URL) -> Bool {
        let dir = binary.deletingLastPathComponent()   // …/<X>.app/Contents/MacOS
        guard dir.lastPathComponent == "MacOS",
              dir.deletingLastPathComponent().lastPathComponent == "Contents" else { return false }
        let plistURL = dir.deletingLastPathComponent().appendingPathComponent("Info.plist")
        guard let dict = NSDictionary(contentsOf: plistURL) as? [String: Any],
              let exe = dict["CFBundleExecutable"] as? String, !exe.isEmpty else { return false }
        return exe == binary.lastPathComponent
    }

    /// 备份落点目录：主可执行 → 用户数据目录 backups/<bundle 名>/（bundle
    /// 外，目录随备份创建）；其余（dylib 等）→ 二进制同目录（既有行为）。
    /// `userData` 仅测试注入（避免与 _userDataURLOverride 的跨套件并发竞态）。
    static func backupDirectory(for binary: URL, userData: URL? = nil) -> URL {
        guard isBundleMainExecutable(binary) else { return binary.deletingLastPathComponent() }
        let comps = binary.pathComponents
        let appName = comps.count >= 4 ? comps[comps.count - 4] : "unknown.app"
        return (userData ?? Config.userDataURL)
            .appendingPathComponent("backups/\(appName)", isDirectory: true)
    }

    /// Copies `binary` to its backup location as `<name>.wxkeep-bak-<yyyyMMdd-HHmmss>`.
    /// Returns the backup URL.
    @discardableResult
    static func make(binary: URL, userData: URL? = nil) throws -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSSSSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        let stamp = formatter.string(from: Date())
        let directory = backupDirectory(for: binary, userData: userData)
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        var destination = URL(fileURLWithPath:
            directory.appendingPathComponent(binary.lastPathComponent).path + ".wxkeep-bak-" + stamp)
        // 同秒/并发兜底：重名则追加序号
        var n = 0
        while FileManager.default.fileExists(atPath: destination.path) {
            n += 1
            destination = URL(fileURLWithPath:
                directory.appendingPathComponent(binary.lastPathComponent).path + ".wxkeep-bak-" + stamp + "-\(n)")
        }
        do {
            try FileManager.default.copyItem(at: binary, to: destination)
        } catch {
            throw BackupError.copyFailed(error.localizedDescription)
        }
        // A truncated backup is worse than none — verify size.
        let originalSize = (try? FileManager.default.attributesOfItem(atPath: binary.path)[.size] as? Int64) ?? -1
        let backupSize = (try? FileManager.default.attributesOfItem(atPath: destination.path)[.size] as? Int64) ?? -2
        guard originalSize == backupSize, originalSize >= 0 else {
            try? FileManager.default.removeItem(at: destination)
            throw BackupError.copyFailed("size mismatch after copy (\(originalSize) vs \(backupSize))")
        }
        prune(keepingNewest: keepCount,
              matching: directory.appendingPathComponent(binary.lastPathComponent).path + ".wxkeep-bak-")
        return destination
    }

    /// 删除匹配前缀的旧备份，保留最新 `keep` 个（按文件名排序 = 时间序，
    /// 时间戳格式保证字典序即时间序）。
    static func prune(keepingNewest keep: Int, matching prefix: String) {
        let dir = (prefix as NSString).deletingLastPathComponent
        let base = (prefix as NSString).lastPathComponent
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        let backups = entries.filter { $0.hasPrefix(base) }
            .sorted(by: >)   // 新的在前
        for stale in backups.dropFirst(keep) {
            try? FileManager.default.removeItem(atPath: dir + "/" + stale)
        }
    }
}
