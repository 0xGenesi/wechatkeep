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

    /// Copies `binary` next to itself as `<name>.wxkeep-bak-<yyyyMMdd-HHmmss>`.
    /// Returns the backup URL.
    @discardableResult
    static func make(binary: URL) throws -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSSSSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        let stamp = formatter.string(from: Date())
        var destination = URL(fileURLWithPath: binary.path + ".wxkeep-bak-" + stamp)
        // 同秒/并发兜底：重名则追加序号
        var n = 0
        while FileManager.default.fileExists(atPath: destination.path) {
            n += 1
            destination = URL(fileURLWithPath: binary.path + ".wxkeep-bak-" + stamp + "-\(n)")
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
        prune(keepingNewest: keepCount, matching: binary.path + ".wxkeep-bak-")
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
