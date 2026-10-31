import Foundation
import Testing
@testable import wxkeep

struct RecoverTests {
    // MARK: FTS 文档判定

    @Test func tipDocumentDetection() {
        // 灰条模板（若出现=被同步覆盖，实测 synced=0，防御分支）
        #expect(RevokeRecovery.isTipDocument("你撤回了一条消息"))
        #expect(RevokeRecovery.isTipDocument("\"nick\" 撤回了一条消息"))
        #expect(RevokeRecovery.isTipDocument("<?xml version=\"1.0\"?><sysmsg type=\"revokemsg\">"))
        // 原文（复原目标）
        #expect(!RevokeRecovery.isTipDocument("看看哪些是目前没"))
        #expect(!RevokeRecovery.isTipDocument("gdjh@cbs888 "))
        #expect(!RevokeRecovery.isTipDocument(""))
        // 边界：原文里恰好含「撤回」但非模板——不误判
        #expect(!RevokeRecovery.isTipDocument("明天开会讨论撤回方案"))
    }

    // MARK: 文档解码（content 表 c0=明文 UTF-8）

    @Test func documentDecoding() {
        #expect(RevokeRecovery.decodeDocument("e4b8ad0a") == "中\n")
        #expect(RevokeRecovery.decodeDocument("") == nil)
        #expect(RevokeRecovery.decodeDocument("zz") == nil)
        #expect(RevokeRecovery.decodeDocument("e4") == nil)   // 截断序列
    }

    // MARK: 反查批切分（cap 硬约束）

    @Test func ftsQueryBatchesRespectCap() {
        let sessions: [(sid: Int, lids: [Int])] = [
            (1, Array(0..<300)),
            (2, [10, 20]),
            (3, Array(0..<250)),
        ]
        let batches = RevokeRecovery.ftsQueryBatches(sessions, cap: 500)
        // 贪心打包：300+2+198=500 → 2 批；每批总项数 ≤ cap；项不丢不重
        #expect(batches.count == 2)
        func terms(_ s: String) -> Int {
            s.split(separator: " OR ").reduce(0) { n, g in
                let ids = g.split(separator: "IN (")[1].dropLast().split(separator: ",")
                return n + ids.count
            }
        }
        for b in batches { #expect(terms(b) <= 500) }
        var counts: [Int: Int] = [:]
        for b in batches {
            for g in b.split(separator: " OR ") {
                let sid = Int(g.split(separator: " ")[0].split(separator: "=")[1])!
                let ids = g.split(separator: "IN (")[1].dropLast().split(separator: ",")
                counts[sid, default: 0] += ids.count
            }
        }
        #expect(counts == [1: 300, 2: 2, 3: 250])
        #expect(batches[0].contains(" OR "))   // 多会话合批
    }

    @Test func ftsQueryBatchesOversizedSingleSession() {
        // 单会话 lid 数 > cap → 拆多批，不丢项
        let lids = Array(1000..<1000 + 1200)
        let batches = RevokeRecovery.ftsQueryBatches([(7, lids)], cap: 500)
        #expect(batches.count == 3)
        var seen = 0
        for b in batches {
            let ids = b.split(separator: "IN (")[1].dropLast().split(separator: ",")
            seen += ids.count
            #expect(b.contains("c4=7"))
        }
        #expect(seen == 1200)
    }

    @Test func ftsQueryBatchesEmpty() {
        #expect(RevokeRecovery.ftsQueryBatches([]).isEmpty)
        #expect(RevokeRecovery.ftsQueryBatches([(1, [])]).isEmpty)
    }

    // MARK: 导出记录

    @Test func recoveredRecordJSONRoundTrip() throws {
        let r = RevokeRecovery.RecoveredRecord(
            chat: "wxid_x", name: "备注名", time: 1_793_241_600, form: "other",
            localId: 256, db: "message_0.db", length: 9, text: "原始消息文本")
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
        let data = try enc.encode(r)
        let back = try JSONDecoder().decode(RevokeRecovery.RecoveredRecord.self, from: data)
        #expect(back == r)
        // name 缺省（旧文件兼容）可解码为 nil
        let legacy = #"{"chat":"wxid_y","db":"m.db","form":"self","length":2,"localId":1,"text":"hi","time":5}"#
        let old = try JSONDecoder().decode(RevokeRecovery.RecoveredRecord.self, from: Data(legacy.utf8))
        #expect(old.name == nil)
    }

    // MARK: 显示名解析

    @Test func displayNameFallbackChain() {
        #expect(RevokeRecovery.displayName(remark: "备注", nickName: "昵称", alias: "wxid", username: "u") == "备注")
        #expect(RevokeRecovery.displayName(remark: "  ", nickName: "昵称", alias: "wxid", username: "u") == "昵称")
        #expect(RevokeRecovery.displayName(remark: "", nickName: "", alias: "alias_here", username: "u") == "alias_here")
        #expect(RevokeRecovery.displayName(remark: "", nickName: "", alias: "", username: "raw_id") == "raw_id")
    }

    // MARK: Markdown 渲染

    @Test func markdownRenderGroupsAndQuotes() {
        let records = [
            RevokeRecovery.RecoveredRecord(chat: "wxid_b", name: "乙", time: 200, form: "other",
                                           localId: 2, db: "m.db", length: 5, text: "乙的消息"),
            RevokeRecovery.RecoveredRecord(chat: "wxid_a", name: nil, time: 100, form: "self",
                                           localId: 1, db: "m.db", length: 9, text: "第一行\n第二行"),
            RevokeRecovery.RecoveredRecord(chat: "wxid_a", name: nil, time: 150, form: "self",
                                           localId: 3, db: "m.db", length: 4, text: "后来的"),
        ]
        let md = RevokeRecovery.renderMarkdown(records: records, generatedAt: Date(timeIntervalSince1970: 0))
        #expect(md.contains("# 撤回原文复原报告"))
        #expect(md.contains("记录：3 条 / 会话：2 个"))
        // 最近活跃会话在前（wxid_b max=200 > wxid_a max=150）
        let bRange = md.range(of: "## 乙")!
        let aRange = md.range(of: "`wxid_a`")!
        #expect(bRange.lowerBound < aRange.lowerBound)
        // 会话内时间升序 + 多行 blockquote
        let first = md.range(of: "第一行")!
        let third = md.range(of: "后来的")!
        #expect(first.lowerBound < third.lowerBound)
        #expect(md.contains("> 第二行"))
        // 显示名解析与自称标注
        #expect(md.contains("### ") && md.contains("对方撤回") && md.contains("我撤回"))
    }
}

// MARK: - 102 轮：多账号隔离（sid/localId 跨账号编号独立，全局合并会张冠李戴）

extension RecoverTests {
    @Test func assembleRecordsIsolatesAccounts() throws {
        // 两账号 sid 撞号：A 的 sid=5 与 B 的 sid=5 是不同会话
        let tipA = RevokeRecovery.RecoverTip(
            account: "accA", username: "wxid_a", sid: 5, localId: 7, ts: 100,
            form: .otherRevoke, db: "message_0.db")
        let tipB = RevokeRecovery.RecoverTip(
            account: "accB", username: "wxid_b", sid: 5, localId: 7, ts: 200,
            form: .selfRevoke, db: "message_0.db")
        let tipC = RevokeRecovery.RecoverTip(
            account: "accC", username: "wxid_c", sid: 5, localId: 7, ts: 300,
            form: .otherRevoke, db: "message_0.db")   // accC 无 FTS 文档 → absent
        let textA = "账号A的原文"
        let textB = "账号B的原文"
        let docs: [String: [Int: [Int: String]]] = [
            "accA": [5: [7: Data(textA.utf8).hexUppercase]],
            "accB": [5: [7: Data(textB.utf8).hexUppercase]],
        ]
        // 显示名同账号隔离：A 的 wxid_a→名字甲，B 的 wxid_b→名字乙
        let names: [String: [String: String]] = [
            "accA": ["wxid_a": "名字甲"],
            "accB": ["wxid_b": "名字乙"],
        ]
        let out = RevokeRecovery.assembleRecords(
            tips: [tipA, tipB, tipC], docs: docs, displayNames: names)
        #expect(out.records.count == 2)
        #expect(out.absent == 1)
        #expect(out.records.contains { $0.text == textA && $0.name == "名字甲" })
        #expect(out.records.contains { $0.text == textB && $0.name == "名字乙" })
        // 跨账号污染的具体形态（回归前会发生）：A 的 tip 配到 B 的原文
        #expect(!out.records.contains { $0.text == textB && $0.chat == "wxid_a" })
        #expect(!out.records.contains { $0.text == textA && $0.chat == "wxid_b" })
    }

    @Test func assembleRecordsCountsSyncedAndUndecodable() throws {
        let tip = RevokeRecovery.RecoverTip(
            account: "a", username: "u", sid: 1, localId: 1, ts: 1,
            form: .otherRevoke, db: "db")
        let synced = RevokeRecovery.RecoverTip(
            account: "a", username: "u", sid: 1, localId: 2, ts: 2,
            form: .otherRevoke, db: "db")
        let bad = RevokeRecovery.RecoverTip(
            account: "a", username: "u", sid: 1, localId: 3, ts: 3,
            form: .otherRevoke, db: "db")
        let docs: [String: [Int: [Int: String]]] = [
            "a": [1: [1: "6162",                                  // "ab" 正常
                      2: Data("xx撤回了一条消息".utf8).hexUppercase,  // 同步覆盖
                      3: "ZZZZ"]],                                  // 非 hex → 不可解码
        ]
        let out = RevokeRecovery.assembleRecords(
            tips: [tip, synced, bad], docs: docs, displayNames: [:])
        #expect(out.records.count == 1 && out.records.first?.text == "ab")
        #expect(out.synced == 1)
        #expect(out.undecodable == 1)
    }
}
