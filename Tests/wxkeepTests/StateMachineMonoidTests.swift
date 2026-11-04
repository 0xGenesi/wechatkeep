import Foundation
import Testing
@testable import wxkeep

/// L15 变换单群闭包（V7-DEPTH D19/R19，134 轮）。
///
/// L11（StateMachineExhaustiveTests）穷举到深度 3/4（155/780 序列）——
/// 「更长序列也成立」靠「迁移函数不变 ⇒ 深层翻车必先浅层露出」的**论证**
/// 支撑。论证不是证明：无限长度的尾巴还在。
///
/// 本套件用代数闭包消灭尾巴（FSM 一致性测试的 W-方法脉络，Chow 1978）：
/// 不枚举序列，枚举**状态变换**。5 条命令各自是抽象态
/// （variant ∈ {none, silent, keeptip} × update ∈ {false, true}，共 6 态）
/// 上的一个函数；它们生成的变换集合（变换半群的可达部分）**有限**。
/// BFS 枚举到饱和后：
///   ① 闭包自证：任一可达变换 × 任一生成元（左复合）仍可达；
///   ② 饱和半径 R = 每类最短代表词长度的最大值——此后任何长度的词，
///      其变换必然等于某个 ≤R 长代表词的变换（无限词空间折叠进有限类）；
///   ③ 每类最短代表词在**真引擎**上执行（与 L11 同款 rig/位点级直证），
///      折叠预言成立；
///   ④ 类内一致采样：每类另取一个**非最短**词（优先长度 > R）在真引擎上
///      执行，终态与代表词**逐字节恒等**——「同变换类在引擎上行为一致」
///      残差假设的直接采样；
///   ⑤ 生成元幂等（T_g∘T_g == T_g）——fold 规则的代数面钉死。
///
/// 全称性来源（诚实边界，V7-DEPTH §6）：「任意长度全部成立」= 闭包事实 ②
/// + 代表词实测 ③ + 模型假设「引擎是确定性状态机且终态字节只依赖抽象态」。
/// 最后一项由 ④ 的采样 + L17 差分孪生（独立实现交叉）背书，不是本套件
/// 单独证明的。
struct StateMachineMonoidTests {
    /// 与 StateMachineExhaustiveTests/CrashMatrixTests 同款三 target 目录
    /// （变体互斥 / 归一化条目 / 混长位点语义全保留）。
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

    private static let alphabet = ["silent", "keeptip", "silent:only-update",
                                   "keeptip:only-revoke", "restore"]

    private static let siteSpans: [(arch: Config.Arch, va: UInt64, len: Int, group: String)] = [
        (.arm64, 0x100, 8, "revoke"), (.arm64, 0x140, 4, "keeptip"),
        (.arm64, 0x180, 4, "keeptip"), (.arm64, 0x1C0, 4, "update"),
        (.x86_64, 0x100, 9, "revoke"), (.x86_64, 0x140, 3, "keeptip"),
        (.x86_64, 0x1C0, 8, "update"),
    ]

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
        "x86_64:1c0": "31C09090CA000000",   // 混长：asm 4B + pristine 尾
    ]

    // MARK: - 抽象态与变换

    private enum VariantState: String { case none, silent, keeptip }

    private struct AbstractState: Hashable {
        let variant: VariantState
        let update: Bool
        static let all: [AbstractState] = {
            var out: [AbstractState] = []
            for v in [VariantState.none, .silent, .keeptip] {
                for u in [false, true] { out.append(AbstractState(variant: v, update: u)) }
            }
            return out
        }()
        var index: Int { Self.all.firstIndex(of: self)! }
    }

    private static let initialState = AbstractState(variant: .none, update: false)

    /// 命令语义（fold 规则，与 L11 同源）：每个生成元 = 6 态 → 6 态下标映射。
    private static let generatorImages: [String: [Int]] = {
        func images(_ f: (AbstractState) -> AbstractState) -> [Int] {
            AbstractState.all.map { f($0).index }
        }
        return [
            "silent": images { _ in AbstractState(variant: .silent, update: true) },
            "keeptip": images { _ in AbstractState(variant: .keeptip, update: true) },
            "silent:only-update": images { AbstractState(variant: $0.variant, update: true) },
            "keeptip:only-revoke": images { AbstractState(variant: .keeptip, update: $0.update) },
            "restore": images { _ in AbstractState(variant: .none, update: false) },
        ]
    }()

    /// 左复合：词 w 追加命令 c 后的变换（T_{w+c}[i] = g_c[T_w[i]]）。
    private static func append(_ c: String, to images: [Int]) -> [Int] {
        let g = generatorImages[c]!
        return images.map { g[$0] }
    }

    private static func key(_ images: [Int]) -> String { images.map(String.init).joined(separator: ",") }

    // MARK: - 闭包枚举

    private struct Class {
        let images: [Int]
        let representative: [String]   // 最短词（同长度取首见——字母表顺序稳定）
        var alternates: [[String]] = [] // 同类的更长词（≤R+2 域内收集）
    }

    /// BFS 枚举全部可达变换直到饱和。返回（类列表，饱和半径 R）。
    private static func enumerateMonoid() -> (classes: [Class], radius: Int) {
        var byKey: [String: Int] = [:]   // transformation key → class index
        var classes: [Class] = []
        var queue: [[Int]] = []

        for c in alphabet {
            let t = generatorImages[c]!
            let k = key(t)
            if byKey[k] == nil {
                byKey[k] = classes.count
                classes.append(Class(images: t, representative: [c]))
                queue.append(t)
            }
        }
        while let t = queue.first {
            queue.removeFirst()
            for c in alphabet {
                let next = append(c, to: t)
                let k = key(next)
                if byKey[k] == nil {
                    let repIndex = byKey[key(t)]!
                    byKey[k] = classes.count
                    classes.append(Class(images: next,
                                         representative: classes[repIndex].representative + [c]))
                    queue.append(next)
                }
            }
        }
        let radius = classes.map(\.representative.count).max() ?? 0
        return (classes, radius)
    }

    /// 全部 ≤B 长词按变换分组（纯内存枚举；B = R+2）——类内一致采样的
    /// 备选词来源。
    private static func wordsByClass(bound: Int) -> [String: [[String]]] {
        var out: [String: [[String]]] = [:]
        var level: [[String]] = [[]]
        for _ in 0...bound {
            for w in level where !w.isEmpty {
                var t = generatorImages[w[0]]!
                for c in w.dropFirst() { t = append(c, to: t) }
                out[key(t), default: []].append(w)
            }
            if level.first?.count == bound { break }
            level = level.flatMap { seq in alphabet.map { seq + [$0] } }
        }
        return out
    }

    // MARK: - 折叠预言（与 L11 同源的位点级语义）

    private static func expectedHex(variant: VariantState, update: Bool) -> [String: String] {
        var out: [String: String] = [:]
        for span in siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            let pristine = pristineHex[key]!
            switch span.group {
            case "update": out[key] = update ? updateHex[key]! : pristine
            case "revoke": out[key] = variant == .silent ? silentHex[key]! : pristine
            case "keeptip":
                out[key] = variant == .keeptip ? (keeptipHex[key] ?? pristine) : pristine
            default: Issue.record("未知位点分组 \(span.group)")
            }
        }
        return out
    }

    // MARK: - fixtures（与 L11 同款）

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
        try Config(data: Data(catalogJSON.utf8), origin: "monoid")
    }

    private static func run(_ cmd: String, app: URL, config: Config) throws {
        switch cmd {
        case "restore":
            _ = try Engine.restore(app: app, build: "999998", config: config, dryRun: false)
        case "silent", "keeptip":
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: cmd,
                                 dryRun: false, allowUnverified: false, only: nil)
        case "silent:only-update":
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: "silent",
                                 dryRun: false, allowUnverified: false, only: ["update"])
        case "keeptip:only-revoke":
            _ = try Engine.patch(app: app, build: "999998", config: config, variant: "keeptip",
                                 dryRun: false, allowUnverified: false, only: ["revoke"])
        default:
            Issue.record("字母表外命令 \(cmd)")
        }
    }

    private static func sliceBytes(_ rig: Rig, arch: Config.Arch, va: UInt64, len: Int) throws -> Data {
        let data = try Data(contentsOf: rig.dylib)
        let base = arch == .arm64 ? rig.armOffset : rig.x64Offset
        return data.subdata(in: (base + Int(va))..<(base + Int(va) + len))
    }

    private static func siteHexMap(_ rig: Rig) throws -> [String: String] {
        var out: [String: String] = [:]
        for span in siteSpans {
            let key = "\(span.arch.rawValue):\(String(span.va, radix: 16))"
            out[key] = try sliceBytes(rig, arch: span.arch, va: span.va,
                                      len: span.len).hexUppercase
        }
        return out
    }

    /// 在真引擎上执行词并返回终态位点字节。
    private static func execute(_ word: [String]) throws -> [String: String] {
        let config = try makeConfig()
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-monoid-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let rig = try makeRig(work: work, name: "MON.app")
        for cmd in word { try run(cmd, app: rig.app, config: config) }
        return try siteHexMap(rig)
    }

    // MARK: - 断言面

    /// ①② 闭包自证 + 类数/半径 tripwire。
    ///
    /// 类数 7 的推导（fold 规则的代数事实，变更字母表/语义时此断言以红指路）：
    /// 三个常变换 C_silent/C_keeptip/C_restore、两个非幂等位面
    /// U=(v,u→v,1)、K=(v,u→keeptip,u)，加上 U/C_restore 与 K/C_restore
    /// 的复合产物 C_{(none,1)}/C_{(keeptip,false)}——其余复合全部坍缩回
    /// 这 7 个。
    @Test func monoidSaturates() {
        let (classes, radius) = Self.enumerateMonoid()
        #expect(classes.count == 7, "可达变换类 = \(classes.count) ≠ 7——fold 语义变更时此 tripwire 指路")
        #expect(radius >= 1 && radius <= 3, "饱和半径异常：\(radius)")

        // ① 闭包自证：每个可达变换 × 每个生成元的左复合仍可达。
        let reachable = Set(classes.map { Self.key($0.images) })
        for c in classes {
            for g in Self.alphabet {
                let next = Self.append(g, to: c.images)
                #expect(reachable.contains(Self.key(next)),
                        "闭包破坏：\(c.representative.joined(separator: "→")) + \(g) 枚举出未收录变换")
            }
        }
        // ② 半径即封口：>R 长词全部落入已收录类（wordsByClass 域内复核）。
        let grouped = Self.wordsByClass(bound: radius + 2)
        #expect(Set(grouped.keys) == reachable,
                "≤R+2 词域的变换集合 ≠ BFS 闭包集合（域内出现新类 = 半径主张不成立）")
    }

    /// ⑤ 生成元幂等（fold 规则代数面）。
    @Test func generatorsAreIdempotent() {
        for g in Self.alphabet {
            let once = Self.generatorImages[g]!
            let twice = Self.append(g, to: once)
            #expect(once == twice, "生成元 \(g) 非幂等（T_g∘T_g ≠ T_g）")
        }
    }

    /// ③④ 每类代表词实测 + 类内一致采样（真引擎，位点级字节直证）。
    @Test func everyClassExecutesAndAgreesOnRealEngine() throws {
        let (classes, radius) = Self.enumerateMonoid()
        let grouped = Self.wordsByClass(bound: radius + 2)

        for cls in classes {
            let k = Self.key(cls.images)
            let label = cls.representative.joined(separator: " → ")

            // ③ 代表词：终态 == 变换作用于初始态的折叠预言。
            let terminal = AbstractState.all[cls.images[Self.initialState.index]]
            let prophecy = Self.expectedHex(variant: terminal.variant, update: terminal.update)
            let actual = try Self.execute(cls.representative)
            for (site, hex) in prophecy {
                #expect(actual[site] == hex,
                        "monoid[\(label)]: \(site) 终态 \(actual[site] ?? "?") ≠ 折叠预言 \(hex)")
            }

            // ④ 类内一致：取一个非最短同类词（优先 >R 长），终态逐字节恒等。
            let alternates = (grouped[k] ?? []).filter { $0 != cls.representative && $0.count > cls.representative.count }
            #expect(!alternates.isEmpty,
                    "monoid[\(label)]: ≤R+2 词域内无更长同类词——类内一致采样不可行（半径/域界需复核）")
            if let longer = alternates.max(by: { $0.count < $1.count }) {
                let altTerminal = try Self.execute(longer)
                for (site, hex) in actual {
                    #expect(altTerminal[site] == hex,
                            "monoid[\(label)] vs \(longer.joined(separator: " → ")): \(site) 类内不一致（\(hex) → \(altTerminal[site] ?? "?")）——同变换类在引擎上行为分叉")
                }
            }
        }
    }
}
