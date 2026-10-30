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

/// L2 可逆性穷举 harness（ROADMAP 72·L2，sha256 恒等预言）：
/// WXKEEP_L2_PLAN 指向 JSON 计划文件 [{"build":"270101","arm":"…arm64.dylib",
/// "x64":"…x64.dylib"}, …]。每个构建对：lipo 合成 fat（与装机拓扑一致，
/// thin 切片会让单架构目标 noArchMatched 假红）→ 假 app 结构 →
/// 真实 Engine 全状态迁移：
///   每个单点态 {silent, keeptip, --only 各子集}：patch → 全位点字节 ∈ 合法集
///   （asm ∪ expected，inspect 无 .unknown）→ restore → 整文件 sha256 ==
///   pristine sha256（不是位点比对——通配尾部/padding/长度偏差类缺陷位点
///   比对看不见，哈希藏不住）。
///   链式态：silent→keeptip→silent→keeptip→silent+only:update→keeptip+
///   only:revoke→restore→sha（变体切换往返 + 子集路径全交叉）。
/// 无环境自动跳过（CI）。证据行 "L2 <build> <state> legal/sha"。
struct L2ReversibilityTests {
    private static func plan() -> [[String: String]]? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_L2_PLAN"],
              FileManager.default.fileExists(atPath: path),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: String]],
              !json.isEmpty else { return nil }
        return json
    }

    @Test(.disabled(if: plan() == nil, "WXKEEP_L2_PLAN not set — L2 reversibility oracle skipped"))
    func reversibilityOracleOnRealSlices() throws {
        for item in try #require(Self.plan()) {
            let build = try #require(item["build"])
            let arm = try #require(item["arm"])
            let x64 = try #require(item["x64"])
            try runOneBuild(build: build, armPath: arm, x64Path: x64)
        }
    }

    private func runOneBuild(build: String, armPath: String, x64Path: String) throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-l2-\(build)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        // fat 合成：与装机件同构（双架构切片都在 → Engine 按 cputype 选择）
        let fat = work.appendingPathComponent("fat.dylib")
        let lipo = Shell.run("/usr/bin/lipo",
                             ["-create", armPath, x64Path, "-output", fat.path])
        guard lipo.status == 0 else {
            Issue.record("lipo 合成失败: \(lipo.stderr)")
            return
        }

        let config = try Config.load(explicit: "config.json")
        guard let versionEntry = config.entry(build: build) else {
            Issue.record("build \(build) 不在目录")
            return
        }
        // 布局自适应（85 轮）：3.x 主程序时代打 Contents/MacOS/WeChat
        let relative = versionEntry.targets.first.map {
            $0.binary ?? "Contents/MacOS/WeChat" } ?? "Contents/Resources/wechat.dylib"
        let app = work.appendingPathComponent("Fake.app")
        let binaryDir = app
            .appendingPathComponent("Contents")
            .appendingPathComponent(String(relative.dropFirst("Contents/".count).split(separator: "/").first.map(String.init) ?? "Resources"))
        try FileManager.default.createDirectory(
            at: binaryDir, withIntermediateDirectories: true)
        let binary = binaryDir.appendingPathComponent((relative as NSString).lastPathComponent)
        try FileManager.default.copyItem(at: fat, to: binary)
        let allEntries = versionEntry.targets.flatMap(\.entries)
        let pristineSHA = try Manifest.sha256(fileURL: binary)

        func assertLegalSites(_ label: String) throws {
            let inspections = try Patcher.inspect(binary: binary, entries: allEntries,
                                                  identifier: "l2")
            let unknown = inspections.filter { $0.state == .unknown }
            if !unknown.isEmpty {
                let sites = unknown.map { "0x\(String($0.va, radix: 16))" }.joined(separator: ",")
                Issue.record("\(label): \(unknown.count) 个位点字节 ∉ 合法集 (asm ∪ expected)：\(sites)")
            }
        }
        func restoreAndCompareSHA(_ label: String) throws {
            _ = try Engine.restore(app: app, build: build, config: config, dryRun: false)
            try assertLegalSites("\(label)/restored")
            let restored = try Manifest.sha256(fileURL: binary)
            if restored != pristineSHA {
                Issue.record("\(label): restore 后整文件 sha256 \(restored) != pristine \(pristineSHA)")
            }
        }

        // 单点态：每个 {variant × only 子集} 从 pristine 出发，独立 restore 收口
        let states: [(String, [String]?)] = [
            ("silent", nil), ("keeptip", nil),
            ("silent", ["update"]), ("silent", ["revoke"]),
            ("keeptip", ["revoke"]), ("keeptip", ["update"]),
        ]
        for (variant, only) in states {
            let label = "\(build) \(variant)\(only.map { " --only \($0.joined(separator: ","))" } ?? "")"
            try Engine.patch(app: app, versionEntry: versionEntry, variant: variant,
                             dryRun: false, allowUnverified: false, only: only)
            try assertLegalSites(label)
            try restoreAndCompareSHA(label)
        }

        // 链式态：变体切换往返 + 子集路径交叉，一段连续迁移后 restore 收口
        let chain: [(String, [String]?)] = [
            ("silent", nil), ("keeptip", nil), ("silent", nil), ("keeptip", nil),
            ("silent", ["update"]), ("keeptip", ["revoke"]),
        ]
        for (variant, only) in chain {
            try Engine.patch(app: app, versionEntry: versionEntry, variant: variant,
                             dryRun: false, allowUnverified: false, only: only)
            try assertLegalSites("\(build) chain(\(variant))")
        }
        try restoreAndCompareSHA("\(build) chain")
        print("L2 \(build): \(states.count + 1) 状态迁移全部 legal + sha256 恒等 ✓")
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

/// L6 确定性 oracle（V3-DEPTH）：patch(pristine) 必须是数学函数。
/// 每构建两份**独立** fake app（各自 fresh lipo），同一 pristine 出发：
/// silent 全打 → 两份输出 sha256 必须恒等；keeptip（含变体切换还原路径）
/// → 恒等；restore → 各自回到 pristine sha。任何未来的时间戳/随机性/
/// 迭代序引入（HashMap 遍历序写盘等）都会在这里翻红。
/// 证据行 "L6 <build> deterministic ✓"。无 WXKEEP_L6_PLAN 自动跳过（CI）。
struct L6DeterminismTests {
    private static func plan() -> [[String: String]]? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_L6_PLAN"],
              FileManager.default.fileExists(atPath: path),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: String]],
              !json.isEmpty else { return nil }
        return json
    }

    @Test(.disabled(if: plan() == nil, "WXKEEP_L6_PLAN not set — L6 determinism oracle skipped"))
    func determinismOracleOnRealSlices() throws {
        for item in try #require(Self.plan()) {
            let build = try #require(item["build"])
            let arm = try #require(item["arm"])
            let x64 = try #require(item["x64"])
            try runOneBuild(build: build, armPath: arm, x64Path: x64)
        }
    }

    private func runOneBuild(build: String, armPath: String, x64Path: String) throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-l6-\(build)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let config = try Config.load(explicit: "config.json")
        guard let versionEntry = config.entry(build: build) else {
            Issue.record("build \(build) 不在目录")
            return
        }
        // 布局自适应：4.x 时代打 Contents/Resources/wechat.dylib；3.x 主程序
        // 时代打 Contents/MacOS/WeChat（85 轮 L6 泛化）
        let relative = versionEntry.targets.first.map {
            $0.binary ?? "Contents/MacOS/WeChat" } ?? "Contents/Resources/wechat.dylib"
        // 两份独立镜像：各自 fresh lipo（连 lipo 自身的确定性也一并实证）
        var binaries = [URL]()
        var pristineSHAs = [String]()
        for name in ["a", "b"] {
            let fat = work.appendingPathComponent("fat-\(name).dylib")
            let lipo = Shell.run("/usr/bin/lipo", ["-create", armPath, x64Path, "-output", fat.path])
            guard lipo.status == 0 else {
                Issue.record("lipo 合成失败: \(lipo.stderr)")
                return
            }
            let app = work.appendingPathComponent("Fake\(name).app")
            let binaryDir = app
                .appendingPathComponent("Contents")
                .appendingPathComponent(String(relative.dropFirst("Contents/".count).split(separator: "/").first.map(String.init) ?? "Resources"))
            try FileManager.default.createDirectory(at: binaryDir, withIntermediateDirectories: true)
            let binary = binaryDir.appendingPathComponent((relative as NSString).lastPathComponent)
            try FileManager.default.copyItem(at: fat, to: binary)
            try? FileManager.default.removeItem(at: fat)
            binaries.append(binary)
            pristineSHAs.append(try Manifest.sha256(fileURL: binary))
        }
        guard pristineSHAs[0] == pristineSHAs[1] else {
            Issue.record("pristine fat 即不确定：\(pristineSHAs)")
            return
        }

        // …/FakeX.app/Contents/Resources/wechat.dylib → …/FakeX.app
        let apps = binaries.map { $0.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
        func patchedSHA(_ variant: String) throws -> (String, String) {
            for app in apps {
                _ = try Engine.patch(app: app, versionEntry: versionEntry, variant: variant,
                                     dryRun: false, allowUnverified: false, only: nil)
            }
            return (try Manifest.sha256(fileURL: binaries[0]),
                    try Manifest.sha256(fileURL: binaries[1]))
        }

        let (silentA, silentB) = try patchedSHA("silent")
        if silentA != silentB {
            Issue.record("\(build) silent: 两份独立副本输出不一致 \(silentA) != \(silentB)")
        }
        #expect(silentA != pristineSHAs[0], "补丁必须真的写入了字节（防恒真）")

        let (tipA, tipB) = try patchedSHA("keeptip")   // 走变体切换还原→应用路径
        if tipA != tipB {
            Issue.record("\(build) keeptip: 两份独立副本输出不一致 \(tipA) != \(tipB)")
        }

        for (i, binary) in binaries.enumerated() {
            _ = try Engine.restore(app: apps[i], build: build, config: config, dryRun: false)
            let restored = try Manifest.sha256(fileURL: binary)
            if restored != pristineSHAs[i] {
                Issue.record("\(build) copy\(i): restore 后 sha \(restored) != pristine \(pristineSHAs[i])")
            }
        }
        print("L6 \(build): deterministic ✓ silent=\(String(silentA.prefix(8))) keeptip=\(String(tipA.prefix(8)))")
    }
}
