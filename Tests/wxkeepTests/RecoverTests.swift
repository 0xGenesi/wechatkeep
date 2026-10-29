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
            chat: "wxid_x", time: 1_793_241_600, form: "other",
            localId: 256, db: "message_0.db", length: 9, text: "原始消息文本")
        let enc = JSONEncoder(); enc.outputFormatting = [.sortedKeys]
        let data = try enc.encode(r)
        let back = try JSONDecoder().decode(RevokeRecovery.RecoveredRecord.self, from: data)
        #expect(back == r)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["chat"] as? String == "wxid_x")
        #expect(obj?["text"] as? String == "原始消息文本")
    }
}
