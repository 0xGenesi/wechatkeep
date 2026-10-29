import Foundation
import Testing
@testable import wxkeep

struct DbKeysTests {
    // MARK: 加密核——RFC/公开测试向量 + 合成页回环

    @Test func pbkdf2SHA512KnownVector() {
        // PBKDF2-HMAC-SHA512 P="password" S="salt" c=1 dkLen=64（社区公认向量，
        // 与 python hashlib.pbkdf2_hmac('sha512', b'password', b'salt', 1, 64) 一致）
        let out = SQLCipherGeometry.pbkdf2SHA512(
            password: Array("password".utf8), salt: Array("salt".utf8),
            rounds: 1, outLen: 64)
        #expect(out.hexString == "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")
    }

    @Test func pbkdf2HighBitsDoNotTrap() {
        // 密码/盐含高位字节（0x80+）必须原样过桥——曾因 Int8 转换 trap
        let out = SQLCipherGeometry.pbkdf2SHA512(
            password: [0xFF, 0x80, 0x7F], salt: [0xFE, 0x01], rounds: 2, outLen: 32)
        #expect(out.count == 32)
        #expect(!out.allSatisfy { $0 == 0 })
    }

    @Test func hmacSHA512RFC4231Case1() {
        let mac = SQLCipherGeometry.hmacSHA512(
            key: [UInt8](repeating: 0x0b, count: 20), message: Array("Hi There".utf8))
        #expect(mac.hexString == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    }

    @Test func macSaltXor3a() {
        let salt: [UInt8] = [0x00, 0x3a, 0xff, 0x41]
        #expect(SQLCipherGeometry.macSalt(salt) == [0x3a, 0x00, 0xc5, 0x7b])
    }

    @Test func verifyPage1SyntheticRoundTrip() {
        var page = [UInt8](repeating: 0xA5, count: SQLCipherGeometry.pageSize)
        let salt: [UInt8] = (0..<16).map { UInt8($0 ^ 0x5A) }
        for (i, b) in salt.enumerated() { page[i] = b }
        let key = SQLCipherGeometry.pbkdf2SHA512(
            password: Array("synthetic-key".utf8), salt: Array("synthetic-secret".utf8),
            rounds: 8, outLen: 32)
        let mac = SQLCipherGeometry.hmacSHA512(
            key: SQLCipherGeometry.macKey(key: key, salt: salt),
            message: Array(page[16..<4032]) + [1, 0, 0, 0])
        for (i, b) in mac.enumerated() { page[4032 + i] = b }
        #expect(SQLCipherGeometry.verifyPage1(page: page, key: key))
        var corrupted = page
        corrupted[100] ^= 0xFF
        #expect(!SQLCipherGeometry.verifyPage1(page: corrupted, key: key))
        #expect(!SQLCipherGeometry.verifyPage1(page: page, key: [UInt8](repeating: 0x11, count: 32)))
        var plain = page
        for (i, b) in SQLCipherGeometry.plainHeader.enumerated() { plain[i] = b }
        #expect(!SQLCipherGeometry.verifyPage1(page: plain, key: key))
        #expect(!SQLCipherGeometry.verifyPage1(page: Array(page.prefix(100)), key: key))
    }

    // MARK: 字节/hex

    @Test func hexRoundTripAndRejection() {
        let bytes: [UInt8] = [0x00, 0x0f, 0xa5, 0xff]
        #expect(bytes.hexString == "000fa5ff")
        #expect([UInt8](hexString: "000FA5FF") == bytes)
        #expect([UInt8](hexString: "0x1") == nil)
        #expect([UInt8](hexString: "abc") == nil)
        #expect([UInt8](hexString: "zz") == nil)
        #expect([UInt8](hexString: "") == nil)
    }

    // MARK: 密钥库

    @Test func storeRoundTripAndPromote() throws {
        var store = DbKeysStore()
        store.secrets = [String(repeating: "aa", count: 16)]
        store.dbs = ["message_0.db": String(repeating: "be", count: 16)]
        let enc = JSONEncoder()
        let dec = JSONDecoder()
        let back = try dec.decode(DbKeysStore.self, from: enc.encode(store))
        #expect(back == store)

        var empty = DbKeysStore()
        empty.secrets = [String(repeating: "ff", count: 32)]
        // 全零页 HMAC 必不匹配——promote 不得误存
        let page = [UInt8](repeating: 0, count: SQLCipherGeometry.pageSize)
        let promoted = empty.promote(basename: "x.db", salt: [UInt8](repeating: 1, count: 16), page: page)
        #expect(!promoted)
        #expect(empty.dbs.isEmpty)
    }

    // MARK: 灰条分类（形态标签，永不外泄内容）

    @Test func classifierForms() {
        func cls(_ s: String) -> RevokeTipClassifier.Form {
            RevokeTipClassifier.classify(Data(s.utf8))
        }
        #expect(cls("<?xml version=\"1.0\"?><sysmsg type=\"revokemsg\"><revokemsg><content>你撤回了一条消息</content></revokemsg></sysmsg>") == .xmlRevoke)
        #expect(cls("你撤回了一条消息") == .selfRevoke)
        #expect(cls("\"nick\" 撤回了一条消息") == .otherRevoke)
        #expect(cls("你已添加了某某，以上是打招呼的消息。") == .otherSystem)
        #expect(cls("\"张三\" 加入群聊") == .otherSystem)
        #expect(cls("非 UTF-8：\u{FFFD}") == .otherSystem)
    }

    // MARK: 捕获

    @Test func captureHitParsing() {
        let dir = NSTemporaryDirectory()
        let path = dir + "wxkeep-test-hits-\(UUID().uuidString).jsonl"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let lines = """
        {"ts":1.0,"prf":5,"rounds":256000,"pw":"aabb","salt":"0011"}
        {"error": "boom"}
        not-json
        {"ts":2.0,"prf":5,"rounds":2,"pw":"cc","salt":"dd"}
        """
        try? lines.write(toFile: path, atomically: true, encoding: .utf8)
        let hits = CaptureHit.parse(file: path)
        #expect(hits.count == 2)
        #expect(hits[0].rounds == 256_000 && hits[0].pw == "aabb" && hits[0].salt == "0011")
        #expect(hits[1].rounds == 2)
    }

    @Test func captureScriptEssentials() {
        let script = Wxkeep.DbKeysCommand.Capture.captureScript(hitsPath: "/tmp/h.jsonl")
        #expect(script.contains("CCKeyDerivationPBKDF"))
        #expect(script.contains("$x6 > 32000"))
        // 模块名不得含横线（command script add -f 点号路径要求）
        #expect(script.contains("wxkeep_capture_lldb.hkstart") == false) // 脚本体不含 CLI 侧注册行
        #expect(script.contains("bp_callback"))
        #expect(script.contains("\"/tmp/h.jsonl\""))
    }

    // MARK: 工具

    @Test func chunkedSplits() {
        let xs = Array(0..<7)
        #expect(xs.chunked(into: 3) == [[0, 1, 2], [3, 4, 5], [6]])
        #expect(xs.chunked(into: 10) == [xs])
        #expect((xs as [Int]).chunked(into: 0) == [xs])
    }

    @Test func timestampParsing() throws {
        #expect(try Wxkeep.DbKeysCommand.Audit.parseTimestamp("2026-10-29 00:00") != nil)
        #expect(try Wxkeep.DbKeysCommand.Audit.parseTimestamp("1793241600") == 1793241600)
        #expect(try Wxkeep.DbKeysCommand.Audit.parseTimestamp(nil) == nil)
        #expect(throws: (any Error).self) {
            _ = try Wxkeep.DbKeysCommand.Audit.parseTimestamp("not-a-time")
        }
    }

    @Test func zstdRoundTripWhenAvailable() throws {
        guard Zstd.available else {
            struct ZstdUnavailable: Error {}
            throw ZstdUnavailable() // libzstd 不可达（CI/纯净机）——分类退化路径已由 classifier 单测覆盖
        }
        // 非 zstd 输入原样透传；畸形帧必须失败而非崩溃
        let plain = Data("plain text".utf8)
        #expect(Zstd.decompress(plain) == plain)
        let fakeFrame = Data([0x28, 0xB5, 0x2F, 0xFD]) + Data([0xFF, 0xFF])
        #expect(Zstd.decompress(fakeFrame) == nil)
    }
}
