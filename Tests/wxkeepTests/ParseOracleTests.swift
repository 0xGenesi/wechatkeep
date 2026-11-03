import Testing
import Foundation
@testable import wxkeep

/// L7 合成 parse oracle（V4-REQUIREMENTS §3）：进程外调用真实 parse
/// （270100 arm64 0x4bc4d34），16 条实弹捕获为语料，断言输出 struct
/// 不变量——他人：newmsgid 数值提取正确、replacemsg 逐字节透传、
/// keep/zero 门行为=配置；自发：门=0（零干预）。变异负控：翻转语料
/// 任一 tag 字节 → 对应变体断言必红。
///
/// 资产门槛（CI 空过，同 HotReloadTests 模式）：
/// - var/wxarm 实弹捕获（gitignored 本机资产）
/// - var/ab/270100_arm64.dylib pristine 切片（169MB 本机资产）
/// - 宿主必须 arm64（映射代码原生执行）
struct ParseOracleTests {

    // MARK: - 资产门槛

    static var hostIsARM64: Bool {
        #if arch(arm64)
        true
        #else
        false
        #endif
    }

    static var corpusFiles: [URL] {
        ((try? FileManager.default.contentsOfDirectory(
            at: repoRoot.appendingPathComponent("var/wxarm"), includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.lastPathComponent.hasPrefix("d") && $0.pathExtension == "xml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    /// Tests/ → 仓库根（资产全按绝对路径传，worker 的 CWD 不再参与）。
    static var repoRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    static var assetsPresent: Bool {
        hostIsARM64
            && FileManager.default.fileExists(atPath: "var/ab/270100_arm64.dylib")
            && corpusFiles.count >= 16
    }

    /// CLI 可执行件（本仓构建布局 .build/out/Products/Debug；兼容旧布局）。
    static var wxkeepBinary: URL? {
        for p in [".build/out/Products/Debug/wxkeep", ".build/debug/wxkeep"] {
            let url = repoRoot.appendingPathComponent(p)
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        return nil
    }

    static var binary: URL { repoRoot.appendingPathComponent("var/ab/270100_arm64.dylib") }
    static let parseVA: UInt64 = 0x4bc4d34

    // MARK: - 独立期望计算（oracle 的另一半：不复制 WeChat 的实现）

    /// 语料事实：文件名 → (group, self, newmsgid?, replacemsg-inner?)
    struct CorpusFact {
        let file: String
        let group: Bool          // 有 <replacemsg> = 群形态；有 <content> = 私形态
        let isSelf: Bool         // 内文含「你撤回」needle（HotReloadTests 同判据）
        let newmsgid: UInt64?    // <newmsgid> 数值
        let replacemsg: Data?    // <replacemsg> 内文（CDATA 剥壳）
    }

    static func facts(from data: Data, file: String) -> CorpusFact {
        func inner(_ open: String, _ close: String) -> Data? {
            guard let r = data.range(of: Data(open.utf8)) else { return nil }
            var body = data[r.upperBound...]
            if let cd = body.range(of: Data("<![CDATA[".utf8)) {
                body = body[cd.upperBound...]
                if let end = body.range(of: Data("]]>".utf8)) { body = body[..<end.lowerBound] }
            } else if let end = body.range(of: Data(close.utf8)) {
                body = body[..<end.lowerBound]
            } else { return nil }
            return Data(body)
        }
        let newmsgid = inner("<newmsgid>", "</newmsgid>")
            .flatMap { String(data: $0, encoding: .utf8) }
            .flatMap { UInt64($0.trimmingCharacters(in: .whitespaces)) }
        return CorpusFact(
            file: file,
            group: data.range(of: Data("<replacemsg>".utf8)) != nil,
            isSelf: data.range(of: Data("你撤回".utf8)) != nil,
            newmsgid: newmsgid,
            replacemsg: inner("<replacemsg>", "</replacemsg>"))
    }

    // MARK: - 断言矩阵

    /// 语料全绿（77 续㊰ 树级断言面）：16 条 × (orig/zero/zmsgid)。
    ///
    /// 断言面 = **parse 树**（treedump——conv 后 pugixml 布局扁平化）而非
    /// 深提取臂：0x4bc4d34 的嵌套提取块是零前驱死代码（77 续㉞ 裁定），
    /// 树级断言锁住的契约才是 runtime 改写真正依赖的——「我们的 XML
    /// 变体（newmsgid/msgid 等长清零）在真实 parse 面上：
    /// ① 树结构与其余节点值逐字节不变；② 被清零字段的值=等长零串；
    /// ③ 未清零字段（replacemsg/newmsgid）不受影响」。parse 接受性
    /// （ret=1，subtype=1 调用方契约）一并断言。
    @Test(.disabled(if: !ParseOracleTests.assetsPresent,
                    "实弹语料/pristine 切片不在场（CI）——空过"))
    func corpusGreenMatrix() throws {
        let corpusDir = ParseOracleTests.repoRoot.appendingPathComponent("var/wxarm")
        // —— parse 接受性：三模式全 ret=1 ——
        let outcomes = try ParseOracle.run(binary: ParseOracleTests.binary,
                                           parseVA: ParseOracleTests.parseVA,
                                           corpusDir: corpusDir,
                                           executable: ParseOracleTests.wxkeepBinary)
        for o in outcomes {
            #expect(o.ret == 1, "\(o.file)|\(o.mode): parse 应接受（ret=\(o.ret)）")
        }
        // —— 树级契约 ——
        let dumps = try ParseOracle.runTreeDumps(binary: ParseOracleTests.binary,
                                                 corpusDir: corpusDir,
                                                 executable: ParseOracleTests.wxkeepBinary)
        func value(_ kvs: [ParseOracle.TreeKV], _ tag: String) -> String? {
            kvs.first { $0.tag == tag }?.value
        }
        for url in ParseOracleTests.corpusFiles {
            let fact = ParseOracleTests.facts(from: try Data(contentsOf: url), file: url.lastPathComponent)
            guard let orig = dumps["\(fact.file)|orig"],
                  let zero = dumps["\(fact.file)|zero"],
                  let zmsgid = dumps["\(fact.file)|zmsgid"] else {
            Issue.record("\(fact.file): treedump 三模式齐全")
                continue
            }
            // 树结构（tag 序列）三模式恒等
            #expect(orig.map(\.tag) == zero.map(\.tag) && orig.map(\.tag) == zmsgid.map(\.tag),
                    "\(fact.file): 清零不改树结构")
            if let expected = fact.newmsgid {
                let zeros = String(repeating: "0", count: String(expected).count)
                #expect(value(orig, "newmsgid") == String(expected),
                        "\(fact.file): orig newmsgid 原样")
                #expect(value(zero, "newmsgid") == zeros,
                        "\(fact.file): zero 后 newmsgid=等长零串")
                #expect(value(zmsgid, "newmsgid") == String(expected),
                        "\(fact.file): zmsgid 后 newmsgid 不变（删除键单字段化）")
                // tip 前提（R2 契约的树级形式）：replacemsg 逐字节不受清零影响
                if let repData = fact.replacemsg, !repData.isEmpty,
                   let rep = String(data: repData, encoding: .utf8) {
                    let r0 = value(orig, "replacemsg"), r1 = value(zero, "replacemsg")
                    #expect(r0 == rep, "\(fact.file): orig replacemsg 透传")
                    #expect(r1 == rep, "\(fact.file): zero 后 replacemsg 不变（tip 保留前提）")
                }
            } else if let content = value(orig, "content"), !content.isEmpty {
                // 私形态（content 简式）：无 newmsgid/msgid 可清——三模式 content 恒等
                #expect(value(zero, "content") == content && value(zmsgid, "content") == content,
                        "\(fact.file): content 形态清零不动 content")
                // 自发判别门前提：内文含「你撤回」needle（他人私形态同样走此断言，
                // needle 在场与否则是捕获形态学事实）
                if fact.isSelf {
                    #expect(content.contains("你撤回"), "\(fact.file): 自发捕获形态自洽")
                }
            }
        }
    }

    /// 变异负控（127 轮收口，遗留②）——A/B 双 dump 灵敏度证明：
    /// 同一 worker 对**原始语料**与**变异语料**各跑一次 treedump，逐变异
    /// 文件断言双向：liveness（原始 dump 里目标节点在场且取到值——
    /// oracle 看得见本该存在的东西）+ sensitivity（变异后节点消失/值
    /// 改变——oracle 能报出损伤）。判据完全自持，不再依赖
    /// corpusGreenMatrix 的旁证。
    ///
    /// 126 轮前的两代空洞及其关闭：
    /// - 一代（run() struct 判分歧）：0x4bc4d34 提取臂是死代码，恒真绿；
    /// - 二代（树级但单向）：判据自持了，但 `guard let m = dumps[…] else
    ///   continue` 是静默跳过洞（worker 对变异件整树失败 → 零断言仍绿），
    ///   且无 liveness 半边（「变异后节点消失」对「oracle 从来什么都
    ///   看不见」也成立）。三代：断言计数 == 变异数（零跳过）+ A/B 双向。
    @Test(.disabled(if: !ParseOracleTests.assetsPresent,
                    "实弹语料/pristine 切片不在场（CI）——空过"))
    func mutationNegativeControls() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-oracle-mut-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // —— A/B 基准面先立：原始语料 dump ——
        // 变异选择以 dumpOrig 为基准（首跑实证：CDATA 形的元素 .value()
        // 是空串——文本在子节点，「翻转后值改变」对空→空不成立。oracle
        // 自称看得见的面才需要证明灵敏度：tag 改名恒可用；字节翻转只选
        // dump 值非空的 tag）。
        let dumpOrig = try ParseOracle.runTreeDumps(binary: ParseOracleTests.binary,
                                                    corpusDir: ParseOracleTests.repoRoot.appendingPathComponent("var/wxarm"),
                                                    executable: ParseOracleTests.wxkeepBinary)
        func value(_ kvs: [ParseOracle.TreeKV]?, _ tag: String) -> String? {
            kvs?.first { $0.tag == tag }?.value
        }

        // 变异面（按基准面择伤）：①newmsgid tag 改名（'d'→'e' → 节点
        // 消失，对 CDATA 形恒有效）；②否则取 dump 值非空的 replacemsg/
        // content 翻内文首字节（值改变）。都不满足 = 该件不在 oracle
        // 可见面内 = 不 eligible（如实跳过，不计入证明面）。
        var mutatedFiles: [(file: String, kind: String)] = []
        for url in ParseOracleTests.corpusFiles {
            guard var data = try? Data(contentsOf: url) else { continue }
            let origDump = dumpOrig["\(url.lastPathComponent)|orig"]
            var kind: String? = nil
            if data.range(of: Data("<newmsgid>".utf8)) != nil {
                if let r = data.range(of: Data("<newmsgid>".utf8)) {
                    data[r.lowerBound + 9] = UInt8(ascii: "e")
                    kind = "newmsgid-tag"
                }
            } else {
                for tag in ["replacemsg", "content"] {
                    guard value(origDump, tag)?.isEmpty == false,
                          let r = data.range(of: Data("<\(tag)>".utf8)),
                          r.upperBound < data.count else { continue }
                    data[r.upperBound] ^= 0x20
                    kind = "\(tag)-byte"
                    break
                }
            }
            guard let k = kind else { continue }
            try data.write(to: dir.appendingPathComponent(url.lastPathComponent))
            mutatedFiles.append((url.lastPathComponent, k))
        }
        // 灵敏度 floor：实弹语料 ≥16 件（assetsPresent），群/私形态 16/16
        // 零例外（T5 语料事实）——eligible 全量变异后必须仍成规模，防
        // 「语料漂移后只剩零星件」让证明力悄然缩水。
        #expect(mutatedFiles.count >= 8,
                "可变异语料件 \(mutatedFiles.count) < 8——语料漂移，灵敏度 floor 失守")

        // —— 变异语料 dump（同一 worker、同一模式）——
        let dumpMut = try ParseOracle.runTreeDumps(binary: ParseOracleTests.binary,
                                                   corpusDir: dir,
                                                   executable: ParseOracleTests.wxkeepBinary)

        // 零静默跳过：每个变异件两条断言（liveness + sensitivity）都必须
        // 实际执行——dump 缺键 = worker 对该件整树失败 = 红（这正是二代
        // 的跳过洞，反转为断言）。
        var asserted = 0
        for m in mutatedFiles {
            let o = dumpOrig["\(m.file)|orig"]
            let v = dumpMut["\(m.file)|orig"]
            guard o != nil, v != nil else {
                Issue.record("\(m.file): dump 缺键（orig=\(o != nil) mut=\(v != nil)）——worker 对该件失败，负控链断裂")
                continue
            }
            switch m.kind {
            case "newmsgid-tag":
                let live = value(o, "newmsgid")
                #expect(live != nil, "\(m.file): liveness——原始 dump 必须含 newmsgid 节点（oracle 看得见在场物）")
                #expect(value(v, "newmsgid") == nil,
                        "\(m.file): sensitivity——<newmsgie> 变异后节点必须消失")
                if live != nil && value(v, "newmsgid") == nil { asserted += 1 }
            case "replacemsg-byte", "content-byte":
                let tag = String(m.kind.dropLast(5))
                let origVal = value(o, tag)
                #expect(origVal?.isEmpty == false,
                        "\(m.file): liveness——\(tag) 原始值非空（变异即按此面选的伤）")
                let mutVal = value(v, tag)
                #expect(mutVal != origVal,
                        "\(m.file): sensitivity——首字节翻转后 \(tag) 值必须改变（got \(mutVal.map { String($0.prefix(24)) } ?? "nil")）")
                if origVal?.isEmpty == false && mutVal != origVal { asserted += 1 }
            default:
                Issue.record("\(m.file): 未知变异类 \(m.kind)")
            }
        }
        #expect(asserted == mutatedFiles.count,
                "断言执行 \(asserted)/变异 \(mutatedFiles.count)——差额 = 静默跳过（灵敏度证明不完整）")
    }

    /// 纯逻辑面（不依赖资产，CI 可跑）：zero_tag_digits 移植与
    /// runtime.m zero_tag_digits 的语义等价——tag 内 '1'-'9' 等长清零、
    /// 非数字即停、无 tag 不动。
    @Test func zeroTagDigitsSemantics() {
        var xml = Data("<sysmsg><newmsgid>462001335750234475</newmsgid><replacemsg>x</replacemsg></sysmsg>".utf8)
        ParseOracle.zeroTagDigits(&xml, tag: "<newmsgid>")
        let s = String(data: xml, encoding: .utf8) ?? ""
        #expect(s.contains("<newmsgid>000000000000000000</newmsgid>"), "等长清零: \(s)")
        #expect(s.contains("<replacemsg>x</replacemsg>"), "其余字节不动")
        var none = Data("no tags here".utf8)
        ParseOracle.zeroTagDigits(&none, tag: "<newmsgid>")
        #expect(none == Data("no tags here".utf8), "无 tag 原样")
        var mixed = Data("<msgid>12a3</msgid>".utf8)
        ParseOracle.zeroTagDigits(&mixed, tag: "<msgid>")
        #expect(mixed == Data("<msgid>00a3</msgid>".utf8), "非数字即停（a 不清、3 保留）")
    }
}
