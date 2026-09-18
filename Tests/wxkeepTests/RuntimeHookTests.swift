import Testing
import Foundation
@testable import WxkeepRuntime

// M-R2 runtime hook 核心纯逻辑：<replacemsg> 内文等长改写。
// hook 点 = 撤回解析汇点 wrapper（0x537d910@270099，drive22 终验定案），
// XML SSO 嵌在 rsi+0x130（tag@0 = len<<1|isLong；长串 size@+8、ptr@+0x10）。
// 规则：内文须含「撤回」needle；文案 ≤ 内文才改写，差额空格填充——
// SSO 结构与分配器零接触。SSO 构造在 C 侧完成（wxkeep_runtime_test_rewrite），
// 返回内文长度；-1 = 未命中/放弃。
// serialized：测试缝会临时改写 C 侧全局（g_tip_text/g_tip_len），
// 并行执行会互相踩——必须串行。

@Suite(.serialized) struct RuntimeHookTests {

    private func run(_ xml: [UInt8], tip: [UInt8]) -> Int {
        var data = xml
        let r: Int = data.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        return r
    }

    /// 私聊撤回 sysmsg：内文整体替换为固定文案，短则空格填充，XML 其余部分不动
    @Test func replacesInnerTextSpacePadded() throws {
        let inner = "\"张三\" 撤回了一条消息"
        let xml = Array(("<sysmsg type=\"revokemsg\"><revokemsg><session>wxid_z</session>"
                         + "<replacemsg>" + inner + "</replacemsg>"
                         + "</revokemsg></sysmsg>").utf8)
        let tip = Array("🔒 已拦截撤回".utf8)
        var data = xml
        let innerLen: Int = data.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(innerLen == Array(inner.utf8).count)
        let got = Array(data)
        let openTag = Array("<replacemsg>".utf8)
        let closeTag = Array("</replacemsg>".utf8)
        let openIdx = got.firstRange(of: openTag)!.upperBound
        let closeIdx = got.firstRange(of: closeTag)!.lowerBound
        #expect(Array(got[openIdx..<openIdx + tip.count]) == tip)
        #expect(Array(got[(openIdx + tip.count)..<closeIdx])
                == Array(repeating: UInt8(ascii: " "), count: closeIdx - openIdx - tip.count))
        // 标签与外层 XML（含 <session> 等兄弟元素）保持原样
        #expect(Array(got[0..<openIdx])
                == Array(("<sysmsg type=\"revokemsg\"><revokemsg><session>wxid_z</session><replacemsg>").utf8))
        #expect(Array(got[closeIdx...]) == Array(("</replacemsg></revokemsg></sysmsg>").utf8))
    }

    /// 线上实测形态（drive25，270099 推送撤回 XML）：<content> 承载提示文本
    /// `<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg><content>"joy👀" 撤回…`
    @Test func contentElementLiveSchemaRewrite() {
        let inner = "\"joy👀\" 撤回了一条消息"
        let xml = Array(("<?xml version=\"1.0\"?><sysmsg type=\"revokemsg\">"
                         + "<revokemsg><content>" + inner + "</content>"
                         + "</revokemsg></sysmsg>").utf8)
        let tip = Array("🔒wxkeep M-R2 hook OK".utf8)
        var data = xml
        let innerLen: Int = data.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(innerLen == Array(inner.utf8).count)
        let got = Array(data)
        let openIdx = got.firstRange(of: Array("<content>".utf8))!.upperBound
        let closeIdx = got.firstRange(of: Array("</content>".utf8))!.lowerBound
        #expect(Array(got[openIdx..<openIdx + tip.count]) == tip)
        #expect(Array(got[(openIdx + tip.count)..<closeIdx])
                == Array(repeating: UInt8(ascii: " "), count: closeIdx - openIdx - tip.count))
    }

    /// CDATA 包裹形态（<content><![CDATA[…]]></content>）：跳过前缀改写内文
    @Test func cdataWrappedRewrite() {
        let inner = "\"张三\" 撤回了一条消息"
        let xml = Array(("<sysmsg type=\"revokemsg\"><revokemsg>"
                         + "<content><![CDATA[" + inner + "]]></content>"
                         + "</revokemsg></sysmsg>").utf8)
        let tip = Array("已拦截".utf8)
        var data = xml
        let innerLen: Int = data.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(innerLen == Array(inner.utf8).count)
        let got = Array(data)
        let openIdx = got.firstRange(of: Array("<![CDATA[".utf8))!.upperBound
        let closeIdx = got.firstRange(of: Array("</content>".utf8))!.lowerBound
        #expect(Array(got[openIdx..<openIdx + tip.count]) == tip)
        _ = closeIdx
    }

    /// 内文未含「撤回」针（如普通系统提示复用该标签）不得被改写
    @Test func nonRevokeInnerUntouched() {
        let xml = Array("<sysmsg type=\"revokemsg\"><revokemsg><replacemsg>\"李四\" 邀请你加入了群聊</replacemsg></revokemsg></sysmsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: Array("test".utf8)) == -1)
        #expect(xml == snapshot)
    }

    /// 文案比内文长 → 放弃（返回 -1，数据不动）
    @Test func longerTipRejected() {
        let xml = Array("<revokemsg><replacemsg>王五撤回了</replacemsg></revokemsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: [UInt8](repeating: 0x41, count: 64)) == -1)
        #expect(xml == snapshot)
    }

    /// 无 <replacemsg> 标签的普通消息 XML → 不动
    @Test func plainXmlUntouched() {
        let xml = Array("<sysmsg type=\"delchatroommember\"><op>10000</op></sysmsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: Array("test".utf8)) == -1)
        #expect(xml == snapshot)
    }

    /// 标签截断（有开无闭）→ 放弃
    @Test func truncatedTagDeclined() {
        let xml = Array("<revokemsg><replacemsg>张三撤回了一条消息".utf8)
        let snapshot = xml
        #expect(run(xml, tip: Array("ok".utf8)) == -1)
        #expect(xml == snapshot)
    }

    /// 超过 128B 配置缓冲的文案在测试缝入口就被拒（load_config 同上限）
    @Test func tipLengthLimit() {
        let xml = Array("<revokemsg><replacemsg>\"张三\" 撤回了一条消息，内容比较长用于填充内文长度</replacemsg></revokemsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: [UInt8](repeating: 0x42, count: 200)) == -1)
        #expect(xml == snapshot)
    }

    /// UUID 身份门回归：构造 32B mach_header_64 + LC_UUID 的伪头，目标构建
    /// 必须判匹配、异构建必须判不匹配。锁死「比对恒假 → hook 永不安装」的
    /// 静默失效（buf+'----' 填充实现曾对相同 UUID 也返回 0）。
    private func machHeaderWith(uuid: [UInt8]) -> [UInt8] {
        var h = [UInt8]()
        func le32(_ v: UInt32) {
            h += [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF),
                  UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)]
        }
        le32(0xFEEDFACF)              // MH_MAGIC_64
        le32(0x01000007)              // cputype x86_64
        le32(3); le32(6)              // cpusubtype / filetype MH_DYLIB
        le32(1); le32(24)             // ncmds / sizeofcmds
        le32(0); le32(0)              // flags / reserved
        le32(0x1B); le32(24)          // LC_UUID / cmdsize
        h += uuid
        return h
    }

    @Test func uuidGateMatchesTargetBuildOnly() {
        let target: [UInt8] = [0x97,0xe2,0x14,0x36,0xab,0xda,0x3b,0x79,
                               0xbe,0xc0,0xef,0x26,0x53,0xc6,0xb4,0x23]
        let hit = machHeaderWith(uuid: target)
        #expect(hit.withUnsafeBufferPointer {
            wxkeep_runtime_test_uuid_match(UnsafeRawPointer($0.baseAddress!))
        } == 1)
        let miss = machHeaderWith(uuid: Array(target[0..<15]) + [0x24])   // 末字节漂移
        #expect(miss.withUnsafeBufferPointer {
            wxkeep_runtime_test_uuid_match(UnsafeRawPointer($0.baseAddress!))
        } == 0)
    }
}
