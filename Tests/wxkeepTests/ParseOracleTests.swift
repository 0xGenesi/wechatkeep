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

    /// 变异负控：翻转 tag 字节 → 对应变体断言必红（oracle 灵敏度证明，
    /// 防空转绿灯）。每语料至少一个变异体，断言其与原始期望分歧。
    /// ⚠️ 提取面待迁 0x4bd26a8 前，分歧判据 `m.newmsgid != expected` 对
    /// "oracle 什么都提取不出"也成立——本测当前为**空洞绿**（灵敏度
    /// 证明力要等断言面迁移后恢复；见 corpusGreenMatrix 注）。
    @Test(.disabled(if: !ParseOracleTests.assetsPresent,
                    "实弹语料/pristine 切片不在场（CI）——空过"))
    func mutationNegativeControls() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-oracle-mut-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        // 变异面：newmsgid tag 字节（'d'→'e'）/ newmsgid 数字 / replacemsg 内容字节
        var mutated = 0
        for url in ParseOracleTests.corpusFiles {
            guard var data = try? Data(contentsOf: url) else { continue }
            let fact = ParseOracleTests.facts(from: data, file: url.lastPathComponent)
            var did = false
            if let r = data.range(of: Data("<newmsgid>".utf8)) {
                data[r.lowerBound + 9] = UInt8(ascii: "e")   // <newmsgie>
                did = true
            } else if let r = data.range(of: Data("<replacemsg>".utf8)), r.upperBound < data.count {
                data[r.upperBound] ^= 0x20                    // replacemsg 内文首字节翻转
                did = true
            } else if let r = data.range(of: Data("<content>".utf8)), r.upperBound < data.count {
                data[r.upperBound] ^= 0x20
                did = true
            }
            guard did, fact.newmsgid != nil || (fact.replacemsg?.isEmpty == false) else { continue }
            try data.write(to: dir.appendingPathComponent(url.lastPathComponent))
            mutated += 1
        }
        guard mutated > 0 else { return }

        // 树级负控（77 续㊰）：变异体经 treedump 与原始期望比对——
        // tag 改名 → 对应节点消失；内容字节翻转 → 对应节点值改变。
        // （旧实现用 run() 的 struct 提取判分歧——0x4bc4d34 提取臂是死代码，
        // 恒真绿；树级判定无此空洞。）
        let dumps = try ParseOracle.runTreeDumps(binary: ParseOracleTests.binary,
                                                 corpusDir: dir,
                                                 executable: ParseOracleTests.wxkeepBinary)
        func value(_ kvs: [ParseOracle.TreeKV], _ tag: String) -> String? {
            kvs.first { $0.tag == tag }?.value
        }
        for url in ParseOracleTests.corpusFiles {
            guard let m = dumps["\(url.lastPathComponent)|orig"] else { continue }
            let original = ParseOracleTests.facts(from: try Data(contentsOf: url),
                                                  file: url.lastPathComponent)
            guard original.newmsgid != nil || (original.replacemsg?.isEmpty == false) else { continue }
            var diverged = false
            if original.newmsgid != nil {
                // <newmsgie> 变异 → newmsgid 节点从树中消失
                diverged = value(m, "newmsgid") == nil
            } else if let repData = original.replacemsg, !repData.isEmpty,
                      let rep = String(data: repData, encoding: .utf8) {
                // 内容字节翻转 → replacemsg/content 节点值 != 原文
                if let mv = value(m, "replacemsg") { diverged = mv != rep }
                else if let cv = value(m, "content"), let oc = String(data: repData, encoding: .utf8) {
                    diverged = cv != oc
                } else { diverged = true }
            }
            #expect(diverged, "\(url.lastPathComponent): 变异体应使树级断言变红（oracle 灵敏度）")
        }
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
