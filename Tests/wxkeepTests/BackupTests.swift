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

    /// 主可执行备份必须落 bundle 外（2026-09-23 d28_live 实测双杀）：
    /// MacOS/ 内的备份副本在场 → --deep --strict 子代码对象校验败 +
    /// root 浅签封印它；prune 删掉 → sealed resource missing。dylib 备份
    /// 维持同目录（实证无害）。userData 注入缝：不碰进程级全局（跨套件
    /// 并发竞态）。
    struct MainExecutableBackupTests {

        private func makeFakeApp() throws -> (tmp: URL, main: URL, userDir: URL) {
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("wxkeep-bakmain-\(UUID().uuidString)", isDirectory: true)
            let main = tmp.appendingPathComponent("MyApp.app/Contents/MacOS/WeChat")
            try FileManager.default.createDirectory(
                at: main.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(repeating: 0xCF, count: 64).write(to: main)
            let plist = """
            <?xml version="1.0"?><plist version="1.0"><dict>
            <key>CFBundleExecutable</key><string>WeChat</string>
            </dict></plist>
            """
            try plist.data(using: .utf8)!.write(
                to: tmp.appendingPathComponent("MyApp.app/Contents/Info.plist"))
            let userDir = tmp.appendingPathComponent("user")
            try FileManager.default.createDirectory(at: userDir, withIntermediateDirectories: true)
            return (tmp, main, userDir)
        }

        @Test func mainExecutableBackupLandsOutsideBundle() throws {
            let (tmp, main, userDir) = try makeFakeApp()
            defer { try? FileManager.default.removeItem(at: tmp) }

            #expect(Backup.isBundleMainExecutable(main), "Contents/MacOS/<CFBundleExecutable> 识别")
            let backup = try Backup.make(binary: main, userData: userDir)
            // 落点 = 用户数据目录 backups/<bundle 名>/，且内容完整
            #expect(backup.path.hasPrefix(
                userDir.appendingPathComponent("backups/MyApp.app").path + "/"))
            #expect(FileManager.default.fileExists(atPath: backup.path))
            #expect(try Data(contentsOf: backup).count == 64)
            // MacOS/ 内不得留任何 wxkeep-bak（在场即被 --deep 扫描）
            let macosFiles = try FileManager.default.contentsOfDirectory(
                atPath: main.deletingLastPathComponent().path)
            #expect(!macosFiles.contains { $0.contains(".wxkeep-bak-") },
                    "bundle 内不得留主可执行备份")
        }

        @Test func dylibBackupStaysNextToBinary() throws {
            let (tmp, _, _) = try makeFakeApp()
            defer { try? FileManager.default.removeItem(at: tmp) }
            let dylib = tmp.appendingPathComponent("MyApp.app/Contents/Resources/wechat.dylib")
            try FileManager.default.createDirectory(
                at: dylib.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(repeating: 0xCF, count: 32).write(to: dylib)

            #expect(!Backup.isBundleMainExecutable(dylib))
            let backup = try Backup.make(binary: dylib)
            #expect(backup.deletingLastPathComponent().path
                    == dylib.deletingLastPathComponent().path, "dylib 备份维持同目录")
        }

        /// 非主可执行的 MacOS/ 内文件（CFBundleExecutable 不匹配）不算主程序，
        /// 但也别误伤：仍按同目录处理（现状行为——真实场景不出现，防御语义）。
        @Test func mismatchedExecutableNameIsNotMainExecutable() throws {
            let (tmp, _, _) = try makeFakeApp()
            let other = tmp.appendingPathComponent("MyApp.app/Contents/MacOS/helper")
            try Data([0xCF]).write(to: other)
            #expect(!Backup.isBundleMainExecutable(other))
        }
    }
}
