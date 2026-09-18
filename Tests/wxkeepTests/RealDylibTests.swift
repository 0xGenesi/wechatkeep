import Foundation
import Testing
@testable import wxkeep

/// Full-chain integration against the REAL 269602 fat dylib (327 MB):
/// patch → inspect → restore → inspect, plus recipe resolution on the
/// pristine image. Runs only when WXKEEP_REAL_DYLIB points at the pristine
/// backup (dev machines); CI runners have no WeChat and skip cleanly.
struct RealDylibTests {
    private static var realDylib: URL? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_REAL_DYLIB"],
              FileManager.default.fileExists(atPath: path) else { return nil }
        return URL(fileURLWithPath: path)
    }

    @Test(.disabled(if: realDylib == nil, "WXKEEP_REAL_DYLIB not set — real-dylib chain skipped"))
    func patchInspectRestoreChainOnReal269602() throws {
        let source = try #require(Self.realDylib)
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-real-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        // Work on a copy — never the backup itself.
        let dylib = work.appendingPathComponent("wechat.dylib")
        try FileManager.default.copyItem(at: source, to: dylib)

        let catalogJSON = """
        [{"version":"269602","targets":[
            {"identifier":"revoke","binary":"x","entries":[
                {"arch":"arm64","addr":"44DE938","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
                {"arch":"x86_64","addr":"4BC5940","expected":"554889E553504889FB","asm":"31C0C3909090909090","source":"wxkeep-analysis"}
            ]}
        ]}]
        """
        let config = try Config(data: Data(catalogJSON.utf8), origin: "inline")
        let entry = config.entry(build: "269602")!
        let entries = entry.targets[0].entries

        // 0. pristine: recipe resolves the known x64 address on the REAL image.
        let image = try MachImage(file: dylib, arch: .x86_64)
        let recipe = try RecipeEngine.Recipe(
            anchor: "imm64:revokems", derive: "padding-boundary",
            confirm: ["unique-positive-callers"])
        #expect(try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64) == 0x4BC5940)

        // 1. pristine inspect: both arches pristine.
        var states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.pristine, .pristine])

        // 2. patch both slices.
        let outcomes = try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
        #expect(outcomes == [.written, .written])
        states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.patched, .patched])

        // 3. idempotent re-patch.
        let again = try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
        #expect(again == [.alreadyPatched, .alreadyPatched])

        // 4. recipe STILL resolves on the patched image (two-boundary design).
        let image2 = try MachImage(file: dylib, arch: .x86_64)
        #expect(try RecipeEngine.resolve(recipe: recipe, image: image2, arch: .x86_64) == 0x4BC5940)

        // 5. restore inversion returns both slices to pristine.
        let inverted = entries.map { e -> Config.PatchEntry in
            var copy = e
            copy.asm = e.expected!.values[0]
            copy.expected = Config.ExpectedVariants([e.asm] + e.expected!.values)
            return copy
        }
        let restored = try Patcher.patch(binary: dylib, entries: inverted, identifier: "revoke")
        #expect(restored == [.written, .written])
        states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.pristine, .pristine])
    }
}

/// 通用回填端到端 harness（目录回填 SOP 的机器证明步骤）：
/// WXKEEP_BACKFILL_DYLIB 指向真 wechat.dylib（源不被修改，副本上操作），
/// WXKEEP_BACKFILL_JSON 给出 revoke target 的 entries JSON（locate +
/// parse-guard 产物直接粘贴）。证明链：全 pristine（expected 门对原始字节
/// 成立）→ patch 全写入 → 幂等重打 → restoreAsm 反演 → 文件与原版
/// 字节级一致。无环境自动跳过（CI）。
struct BackfillRoundtripTests {
    private static var dylib: URL? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_BACKFILL_DYLIB"],
              FileManager.default.fileExists(atPath: path) else { return nil }
        return URL(fileURLWithPath: path)
    }
    private static var entriesJSON: String? {
        guard let json = ProcessInfo.processInfo.environment["WXKEEP_BACKFILL_JSON"],
              !json.isEmpty else { return nil }
        return json
    }

    @Test(.disabled(if: dylib == nil || entriesJSON == nil,
                    "WXKEEP_BACKFILL_DYLIB/JSON not set — backfill roundtrip skipped"))
    func backfillPatchRestoreRoundtrip() throws {
        let source = try #require(Self.dylib)
        let json = try #require(Self.entriesJSON)
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-backfill-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let dylib = work.appendingPathComponent("wechat.dylib")
        try FileManager.default.copyItem(at: source, to: dylib)
        let before = try Data(contentsOf: dylib)

        let catalog = try Config(data: Data(
            ("[{\"version\":\"bf\",\"targets\":[{\"identifier\":\"revoke\",\"binary\":\"x\",\"entries\":"
             + json + "}]}]").utf8), origin: "inline")
        let entries = try #require(catalog.entry(build: "bf")?.targets.first?.entries)
        try #require(!entries.isEmpty)

        // 1. 起始态必须已知（pristine，或归一化恢复型条目的 asm==原始字节
        //    而呈 .patched——两种形态都证明定位正确；.unknown 才是定位错误）
        #expect(try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
            .allSatisfy { $0.state != .unknown })
        // 2. patch 全接受（新位点 .written / 归一化条目 .alreadyPatched）+ 终态已知
        #expect(try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
            .allSatisfy { $0 == .written || $0 == .alreadyPatched })
        #expect(try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
            .allSatisfy { $0.state != .unknown })
        // 3. 幂等重打
        #expect(try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
            .allSatisfy { $0 == .alreadyPatched })
        // 4. 反演恢复（通配条目经 restoreAsm 物化前缀），字节级与原版一致
        let inverted = try entries.map { e -> Config.PatchEntry in
            var copy = e
            copy.asm = try #require(Engine.restoreAsm(for: e), "entry not restorable: \(e.addr)")
            copy.expected = Config.ExpectedVariants([e.asm] + (e.expected?.values ?? []))
            return copy
        }
        #expect(try Patcher.patch(binary: dylib, entries: inverted, identifier: "revoke")
            .allSatisfy { $0 == .written || $0 == .alreadyPatched })
        #expect(try Data(contentsOf: dylib) == before)
    }
}
