import Testing
import Foundation
@testable import wxkeep

/// Backup.prune 保留策略：同前缀备份只保留最新 N 个（时间戳字典序即
/// 时间序），且不误伤其他二进制的备份或无关文件。
struct BackupTests {

    private func makeScratchDir() throws -> (dir: URL, bin: URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-bak-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let bin = dir.appendingPathComponent("wechat.dylib")
        try Data([0xCF]).write(to: bin)
        return (dir, bin)
    }

    @Test func pruneKeepsNewestThree() throws {
        let (dir, bin) = try makeScratchDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 造 5 个备份：乱序写入时间戳，验证按名排序（字典序=时间序）
        for stamp in ["20260919-010000-000000", "20260919-030000-000000",
                      "20260919-020000-000000", "20260919-050000-000000",
                      "20260919-040000-000000"] {
            try Data([0xCF]).write(to: dir.appendingPathComponent("\(bin.lastPathComponent).wxkeep-bak-\(stamp)"))
        }
        Backup.prune(keepingNewest: 3, matching: bin.path + ".wxkeep-bak-")
        let left = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.contains(".wxkeep-bak-") }.sorted()
        #expect(left == [
            "wechat.dylib.wxkeep-bak-20260919-030000-000000",
            "wechat.dylib.wxkeep-bak-20260919-040000-000000",
            "wechat.dylib.wxkeep-bak-20260919-050000-000000",
        ])
    }

    @Test func pruneTouchesOnlyMatchingPrefix() throws {
        let (dir, bin) = try makeScratchDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 另一二进制（前缀不同）+ 无关文件：不得误删
        for stamp in ["20260919-010000-000000", "20260919-020000-000000",
                      "20260919-030000-000000", "20260919-040000-000000"] {
            try Data([0xCF]).write(to: dir.appendingPathComponent("\(bin.lastPathComponent).wxkeep-bak-\(stamp)"))
            try Data([0xCF]).write(to: dir.appendingPathComponent("wxkeep_runtime.dylib.wxkeep-bak-\(stamp)"))
        }
        try Data([0xCF]).write(to: dir.appendingPathComponent("keepme.txt"))
        Backup.prune(keepingNewest: 2, matching: bin.path + ".wxkeep-bak-")
        let left = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(left.filter { $0.contains("wechat.dylib.wxkeep-bak-") }.count == 2)
        #expect(left.filter { $0.contains("wxkeep_runtime.dylib.wxkeep-bak-") }.count == 4,
                "其他二进制的备份不受影响")
        #expect(left.contains("keepme.txt"))
    }

    @Test func makeCreatesAndPrunes() throws {
        let (dir, bin) = try makeScratchDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        for _ in 0..<5 { _ = try Backup.make(binary: bin) }
        let left = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.contains(".wxkeep-bak-") }
        #expect(left.count == Backup.keepCount, "make 循环 5 次后应只剩保留上限 \(Backup.keepCount) 个")
        // 本体未动
        #expect(FileManager.default.fileExists(atPath: bin.path))
    }
}
