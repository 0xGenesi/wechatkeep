import Foundation
import Testing
@testable import wxkeep

/// L2 可逆性 + L6 确定性 oracle 的**合成镜像**（127 轮遗留③）。
///
/// RealDylibTests 里的 L2/L6 是全链权威（187+200 真切片 × 双架构 × 真体积），
/// 但 CI 无语料 → env 未设 → **静默 skip**——「CI 绿」对这条不变量链什么
/// 都没说（绿≠跑过）。本文件把同一组不变量在合成 fat 夹具上执行，无环境、
/// CI 真跑：
///
/// - L2：每单点态 {variant × --only 子集} 从 pristine 出发 → patch 后
///   ①sha256 必变（**防空洞**：引擎静默不写时 legal-sites 与 restore-sha
///   双双「通过」——真 oracle 靠独立的 269602 链测补这条，合成版内联）；
///   ②逐 target 分组 inspect 无 .unknown（位点字节 ∈ asm ∪ expected）；
///   → restore → 整文件 sha256 == pristine（哈希预言，位点比对藏不住的
///   通配尾部/padding 类缺陷在此现形）。
/// - 链式态：silent→keeptip→silent→keeptip→silent+only:update→
///   keeptip+only:revoke→restore→sha（变体切换 undo + 子集路径全交叉）。
/// - L6：同 pristine 两份独立副本各自跑 silent / keeptip（切换路径）→
///   输出 sha256 恒等 → restore 各自回 pristine sha——任何时间戳/随机性/
///   迭代序写盘都会翻红。
///
/// 与真 oracle 的差距（如实）：合成件无真链接器布局/代码签名/340MB 体积、
/// 单 binary（真 oracle 的多 binary 目录自适应见 123 轮修）、lipo 合成拓扑
/// 不在覆盖内（真件才有的步骤）。CI 从此对 L2/L6 类不变量**有发言权**，
/// 深度覆盖仍是本地 SOP。
struct SyntheticL2L6Tests {
    /// 三 target 交叉目录：silent 位（retify）/ keeptip 位（归一化+cbz+
    /// store-zero）/ update 位（独立位点供 --only 路径）。字节类与真目录
    /// 同族（L9 语义类），位点 VA==fileoff（MachOFixture 布局合同）。
    private static let catalogJSON = """
    [{"version":"999998","targets":[
      {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
        {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"}
      ]},
      {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"100","expected":["00008052C0035FD6","F44FBEA9FD7B01A9"],"asm":"F44FBEA9FD7B01A9"},
        {"arch":"arm64","addr":"140","expected":["40100034","82000014"],"asm":"40100034"},
        {"arch":"arm64","addr":"180","expected":["60E600F9"],"asm":"7FE600F9"},
        {"arch":"x86_64","addr":"140","expected":["4889C2"],"asm":"31D290"}
      ]},
      {"identifier":"update","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"1C0","expected":"9101E65E","asm":"C0035FD6"},
        {"arch":"x86_64","addr":"1C0","expected":"85C00F85CA000000","asm":"31C09090"}
      ]}
    ]}]
    """

    private func makeFatApp(in work: URL, name: String) throws -> (app: URL, binary: URL) {
        let (image, _, _) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),  // 序言
                (0x140, [0x40, 0x10, 0x00, 0x34]),                          // cbz w0,+8
                (0x180, [0x60, 0xE6, 0x00, 0xF9]),                          // str x0,[x19,#8]
                (0x1C0, [0x91, 0x01, 0xE6, 0x5E]),                          // add x8,..（任意原像）
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
                (0x140, [0x48, 0x89, 0xC2]),
                (0x1C0, [0x85, 0xC0, 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00]),  // test al,al; jne rel32
            ]))
        let app = work.appendingPathComponent(name, isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let binary = resources.appendingPathComponent("wechat.dylib")
        try image.write(to: binary)
        return (app, binary)
    }

    private func makeConfig() throws -> Config {
        try Config(data: Data(Self.catalogJSON.utf8), origin: "inline")
    }

    /// 逐 target 分组 inspect（123 轮修同口径）：跨 target 共享 VA 是变体
    /// 互斥设计，合并单次 inspect 会在数据完整性门上假红。
    private func assertLegalSites(_ label: String, app: URL, config: Config) throws {
        let entry = try #require(config.entry(build: "999998"))
        for target in entry.targets {
            let bin = app.appendingPathComponent(target.binary ?? "Contents/MacOS/WeChat")
            let inspections = try Patcher.inspect(binary: bin, entries: target.entries,
                                                  identifier: "l2-synthetic")
            let unknown = inspections.filter { $0.state == .unknown }
            #expect(unknown.isEmpty,
                    "\(label): \(target.identifier) \(unknown.count) 个位点 ∉ 合法集")
        }
    }

    // MARK: - L2 可逆性（合成）

    @Test func syntheticReversibilityStatesAndChain() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-l2syn-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let config = try makeConfig()
        let (app, binary) = try makeFatApp(in: work, name: "Fake.app")
        let pristineSHA = try Manifest.sha256(fileURL: binary)

        // 单点态：每态从 pristine 出发、独立 restore 收口
        let states: [(String, [String]?)] = [
            ("silent", nil), ("keeptip", nil),
            ("silent", ["update"]), ("silent", ["revoke"]),
            ("keeptip", ["revoke"]), ("keeptip", ["update"]),
        ]
        for (variant, only) in states {
            let label = "synthetic \(variant)\(only.map { " --only \($0.joined(separator: ","))" } ?? "")"
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: variant,
                                 dryRun: false, allowUnverified: false, only: only)
            // 防空洞：该态必然写过位点——sha 不变 = 引擎静默不写（legal-sites
            // 与 restore-sha 都会假绿，只有这条抓得住）
            let patchedSHA = try Manifest.sha256(fileURL: binary)
            #expect(patchedSHA != pristineSHA, "\(label): patch 后 sha 未变——空洞绿形态")
            try assertLegalSites(label, app: app, config: config)

            _ = try Engine.restore(app: app, build: "999998", config: config, dryRun: false)
            try assertLegalSites("\(label)/restored", app: app, config: config)
            #expect(try Manifest.sha256(fileURL: binary) == pristineSHA,
                    "\(label): restore 后 sha256 != pristine")
        }

        // 链式态：变体切换往返 + 子集路径交叉后一次收口
        let chain: [(String, [String]?)] = [
            ("silent", nil), ("keeptip", nil), ("silent", nil), ("keeptip", nil),
            ("silent", ["update"]), ("keeptip", ["revoke"]),
        ]
        for (variant, only) in chain {
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: variant,
                                 dryRun: false, allowUnverified: false, only: only)
            try assertLegalSites("synthetic chain(\(variant))", app: app, config: config)
        }
        _ = try Engine.restore(app: app, build: "999998", config: config, dryRun: false)
        try assertLegalSites("synthetic chain/restored", app: app, config: config)
        #expect(try Manifest.sha256(fileURL: binary) == pristineSHA,
                "chain restore 后 sha256 != pristine")
    }

    // MARK: - L6 确定性（合成）

    @Test func syntheticDeterminismAcrossIndependentRuns() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-l6syn-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let config = try makeConfig()
        var apps: [URL] = []
        var binaries: [URL] = []
        for name in ["FakeA", "FakeB"] {
            let (app, binary) = try makeFatApp(in: work, name: name)
            apps.append(app)
            binaries.append(binary)
        }
        let pristine0 = try Manifest.sha256(fileURL: binaries[0])
        let pristine1 = try Manifest.sha256(fileURL: binaries[1])
        #expect(pristine0 == pristine1, "pristine 基线即不等")

        // silent：两份独立运行 → 输出恒等；且确实写了（≠pristine）
        for app in apps {
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: "silent",
                                 dryRun: false, allowUnverified: false, only: nil)
        }
        let silent0 = try Manifest.sha256(fileURL: binaries[0])
        let silent1 = try Manifest.sha256(fileURL: binaries[1])
        #expect(silent0 == silent1, "silent 双副本 patch 输出 sha 不恒等")
        #expect(silent0 != pristine0, "silent patch 未改变字节（空洞）")

        // keeptip（经变体切换 undo 路径）：恒等
        for app in apps {
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: "keeptip",
                                 dryRun: false, allowUnverified: false, only: nil)
        }
        let keeptip0 = try Manifest.sha256(fileURL: binaries[0])
        let keeptip1 = try Manifest.sha256(fileURL: binaries[1])
        #expect(keeptip0 == keeptip1, "keeptip（切换路径）双副本输出 sha 不恒等")
        #expect(keeptip0 != silent0, "keeptip 与 silent 输出同 sha——变体语义丢失")

        // restore：各自回 pristine
        for app in apps {
            _ = try Engine.restore(app: app, build: "999998", config: config, dryRun: false)
        }
        #expect(try Manifest.sha256(fileURL: binaries[0]) == pristine0)
        #expect(try Manifest.sha256(fileURL: binaries[1]) == pristine1)
    }
}
