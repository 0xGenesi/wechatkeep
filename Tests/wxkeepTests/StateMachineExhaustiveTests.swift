import Foundation
import Testing
@testable import wxkeep

/// L11 有界模型检查：命令状态机不变量在**全部 ≤3 长序列**上成立
/// （V6-DEPTH D15/R14，133 轮）。
///
/// L2/SyntheticL2L6 的固定链（silent→keeptip→…→restore）是设计者想象的
/// 一条路径；用户的实际命令序列是任意组合。本套件对 5 命令字母表 BFS
/// 穷举深度 3（5+25+125 = 155 序列），每序列独立副本上断言：
///   ① 每步后全 target inspect 零 .unknown（位点字节 ∈ asm ∪ expected）；
///   ② X;X == X（命令幂等——重复执行零写入）；
///   ③ **折叠预言**：序列终态位点字节 == foldedExpectation(seq)——终态只是
///     净效果（变体态 × update 触达）的函数。任何「序列依赖的记忆效应」
///     （某命令只在新鲜 pristine 上写对 / 某切换路径漏还原）都会在此红。
///     这是比「脚本绿」强得多的状态机主张；
///   ④ restore 是右零元：任意序列 + restore → 位点字节 == pristine。
///
/// 折叠规则（与 Engine.patch 的 undo 臂/only 过滤语义同源）：
///   silent / keeptip           → variantState 置位 + update 触达；
///   silent:only-update         → 只触达 update（undo 臂不触发：selected
///                                经 only 过滤后不含变体域）；
///   keeptip:only-revoke        → variantState=keeptip、update 不动；
///   restore                    → 全部归零。
/// revoke 位点在 keeptip 态的字节 == pristine（归一化条目设计）——预言里
/// 显式体现这一语义。
///
/// 深度封顶 3 的理由见 V6-DEPTH §6（迁移函数不变 ⇒ 深层翻车必先在浅层
/// 露出）；深度 4（625 序列）登记为可选增量。
struct StateMachineExhaustiveTests {
    /// 与 SyntheticL2L6Tests 同款三 target 目录（变体互斥/归一化条目同族）。
    private static let catalogJSON = """
    [{"version":"999996","targets":[
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

    /// 命令字母表：全量双变体 + 两个 --only 子集 + restore。
    private static let alphabet = ["silent", "keeptip", "silent:only-update",
                                   "keeptip:only-revoke", "restore"]

    /// 位点分组（折叠预言的字节选择面）。
    private static let siteSpans: [(arch: Config.Arch, va: UInt64, len: Int, group: String)] = [
        (.arm64, 0x100, 8, "revoke"), (.arm64, 0x140, 4, "keeptip"),
        (.arm64, 0x180, 4, "keeptip"), (.arm64, 0x1C0, 4, "update"),
        (.x86_64, 0x100, 9, "revoke"), (.x86_64, 0x140, 3, "keeptip"),
        (.x86_64, 0x1C0, 8, "update"),
    ]

    // 各态位点字节（与目录 asm 同源的静态知识；目录内联于本文件，一致性强
    // 制于同文件）。pristine 序言按 MachOFixture 生成序。
    // 155 序列穷举抓出的混长语义：x64 update 位点 asm(4B) < expected(8B)，
    // 引擎只写 asm 4 字节——终态 = asm 前缀 + pristine 尾（siteLen 读面
    // 的完整字节），updateHex 按终态登记并注明。
    private static let pristineHex = [
        "arm64:100": "F44FBEA9FD7B01A9", "arm64:140": "40100034",
        "arm64:180": "60E600F9", "arm64:1c0": "9101E65E",
        "x86_64:100": "554889E553504889FB", "x86_64:140": "4889C2",
        "x86_64:1c0": "85C00F85CA000000",
    ]
    private static let silentHex = [
        "arm64:100": "00008052C0035FD6", "x86_64:100": "31C0C3909090909090",
    ]
    private static let keeptipHex = [
        "arm64:180": "7FE600F9", "x86_64:140": "31D290",
    ]
    private static let updateHex = [
        "arm64:1c0": "C0035FD6",
        "x86_64:1c0": "31C09090CA000000",   // asm 4B + pristine 尾 4B（混长）
    ]

    /// 序列深度 3 全穷举：155 条。
    private static func allSequences() -> [[String]] {
        var out: [[String]] = []
        for a in alphabet {
            out.append([a])
            for b in alphabet {
                out.append([a, b])
                for c in alphabet {
                    out.append([a, b, c])
                }
            }
        }
        return out
    }

    // MARK: - 折叠预言（状态机迁移函数的不变量形态）

    private enum VariantState: String { case none, silent, keeptip }

    /// 净效果折叠：终态只依赖 (variantState, updateTouched)。
    private static func fold(_ seq: [String]) -> (variant: VariantState, update: Bool) {
        var variant = VariantState.none
        var update = false
        for cmd in seq {
            switch cmd {
            case "silent": variant = .silent; update = true
            case "keeptip": variant = .keeptip; update = true
            case "silent:only-update": update = true
            case "keeptip:only-revoke": variant = .keeptip
            case "restore": variant = .none; update = false
            default: Issue.record("字母表外命令 \(cmd)")
            }
        }
        return (variant, update)
    }

    /// 折叠态 → 每位点的预期字节 hex。
    private static func expectedHex(variant: VariantState, update: Bool) -> [String: String] {
        var out: [String: String] = [:]
        for span in siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            let pristine = pristineHex[key]!
            switch span.group {
            case "update":
                out[key] = update ? updateHex[key]! : pristine
            case "revoke":
                // silent → silent 补丁字节；keeptip → 归一化条目写回序言
                //（== pristine 字节）；none → pristine。
                out[key] = variant == .silent ? silentHex[key]! : pristine
            case "keeptip":
                // keeptip 态 → keeptip 补丁字节（@140 cbz 归一化恰等于
                // pristine 字节——字典无键则回落 pristine 表达同一事实）；
                // 其余 → pristine（silent 的 undo 臂还原 keeptip 位点）。
                if variant == .keeptip {
                    out[key] = keeptipHex[key] ?? pristine
                } else {
                    out[key] = pristine
                }
            default:
                Issue.record("未知位点分组 \(span.group)")
            }
        }
        return out
    }

    // MARK: - fixtures

    private struct Rig {
        let app: URL
        let dylib: URL
        let armOffset: Int
        let x64Offset: Int
    }

    private static func makeRig(work: URL, name: String) throws -> Rig {
        let (image, armOffset, x64Offset) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
                (0x140, [0x40, 0x10, 0x00, 0x34]),
                (0x180, [0x60, 0xE6, 0x00, 0xF9]),
                (0x1C0, [0x91, 0x01, 0xE6, 0x5E]),
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
                (0x140, [0x48, 0x89, 0xC2]),
                (0x1C0, [0x85, 0xC0, 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00]),
            ]))
        let app = work.appendingPathComponent(name, isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let dylib = resources.appendingPathComponent("wechat.dylib")
        try image.write(to: dylib)
        return Rig(app: app, dylib: dylib, armOffset: armOffset, x64Offset: x64Offset)
    }

    private static func makeConfig() throws -> Config {
        try Config(data: Data(catalogJSON.utf8), origin: "state-machine")
    }

    private static func run(_ cmd: String, app: URL, config: Config) throws -> Engine.RunSummary {
        switch cmd {
        case "restore":
            return try Engine.restore(app: app, build: "999996", config: config, dryRun: false)
        case "silent", "keeptip":
            return try Engine.patch(app: app, build: "999996", config: config, variant: cmd,
                                    dryRun: false, allowUnverified: false, only: nil)
        case "silent:only-update":
            return try Engine.patch(app: app, build: "999996", config: config, variant: "silent",
                                    dryRun: false, allowUnverified: false, only: ["update"])
        case "keeptip:only-revoke":
            return try Engine.patch(app: app, build: "999996", config: config, variant: "keeptip",
                                    dryRun: false, allowUnverified: false, only: ["revoke"])
        default:
            Issue.record("字母表外命令 \(cmd)")
            return Engine.RunSummary()
        }
    }

    private static func sliceBytes(_ rig: Rig, arch: Config.Arch, va: UInt64, len: Int) throws -> Data {
        let data = try Data(contentsOf: rig.dylib)
        let base = arch == .arm64 ? rig.armOffset : rig.x64Offset
        return data.subdata(in: (base + Int(va))..<(base + Int(va) + len))
    }

    /// 全位点字节快照（key = "arch:va"）——净效应幂等断言的面。
    private static func siteHexMap(_ rig: Rig) throws -> [String: String] {
        var out: [String: String] = [:]
        for span in siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            out[key] = try sliceBytes(rig, arch: span.arch, va: span.va,
                                      len: span.len).hexUppercase
        }
        return out
    }

    private static func assertLegalSites(_ label: String, rig: Rig, config: Config) throws {
        let entry = try #require(config.entry(build: "999996"))
        for target in entry.targets {
            let bin = rig.app.appendingPathComponent(target.binary ?? "Contents/MacOS/WeChat")
            let inspections = try Patcher.inspect(binary: bin, entries: target.entries,
                                                  identifier: "state-machine")
            let unknown = inspections.filter { $0.state == .unknown }
            #expect(unknown.isEmpty,
                    "\(label): \(target.identifier) \(unknown.count) 个位点 ∉ 合法集")
        }
    }

    // MARK: - 序列协议（参数化：每序列独立用例）

    @Test(arguments: StateMachineExhaustiveTests.allSequences())
    func invariantsHoldOnEverySequence(_ seq: [String]) throws {
        let config = try Self.makeConfig()
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-sm-\(seq.joined(separator: "_"))-\(UUID().uuidString)",
                                    isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let rig = try Self.makeRig(work: work, name: "SM.app")
        let label = seq.joined(separator: " → ")

        for cmd in seq {
            // ① 每步后合法集；② 净效应幂等（X;X == X 的**值**语义）：双变体
            // 归一化位点上，重复执行可经 undo 臂产生「净零但非零次」的写
            //（undo 把共享 VA 还原为归一化字节、变体 target 再写回——155
            // 穷举实证：silent after keeptip 的第二次 silent 即此形态），故
            // 幂等不变量以位点字节恒等为断言面，而非写入计数。
            _ = try Self.run(cmd, app: rig.app, config: config)
            try Self.assertLegalSites("sm[\(label)] after \(cmd)", rig: rig, config: config)
            let before = try Self.siteHexMap(rig)
            _ = try Self.run(cmd, app: rig.app, config: config)
            let after = try Self.siteHexMap(rig)
            for (key, hex) in before {
                #expect(after[key] == hex,
                        "sm[\(label)]: \(cmd) 不幂等——净效应破坏 @\(key)（\(hex) → \(after[key] ?? "?")）")
            }
        }

        // ③ 折叠预言：终态位点字节 == 净效果的函数
        let folded = Self.fold(seq)
        let expectation = Self.expectedHex(variant: folded.variant, update: folded.update)
        for span in Self.siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            let onDisk = try Self.sliceBytes(rig, arch: span.arch, va: span.va, len: span.len)
            let predicted = expectation[key] ?? "?"
            #expect(onDisk.hexUppercase == expectation[key],
                    "sm[\(label)]: \(key) 终态 \(onDisk.hexUppercase) ≠ 折叠预言 \(predicted)（序列依赖的记忆效应）")
        }

        // ④ restore 右零元
        _ = try Engine.restore(app: rig.app, build: "999996", config: config, dryRun: false)
        for span in Self.siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            let onDisk = try Self.sliceBytes(rig, arch: span.arch, va: span.va, len: span.len)
            #expect(onDisk.hexUppercase == Self.pristineHex[key],
                    "sm[\(label)]: restore 右零元破坏（\(key) ≠ pristine）")
        }
    }

    /// 穷举完备性自证：字母表 × 深度生成的序列数必须 = 5+25+125（防手滑
    /// 把 BFS 写浅）。
    @Test func enumerationCoversFullDepth3() {
        #expect(Self.allSequences().count == 155)
    }
}
