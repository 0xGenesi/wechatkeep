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
        return destination
    }
}
