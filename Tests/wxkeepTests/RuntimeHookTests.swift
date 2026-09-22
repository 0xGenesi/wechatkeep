import Testing
import Foundation
@testable import WxkeepRuntime
@testable import wxkeep   // RuntimeConfig.knownHooks（跨边界回归用）

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

    // ---- {from} 占位符（M-R3-lite：昵称取自原内文首对引号） ----

    /// tip 写 {from} → 以原内文 `"张三" 撤回了一条消息` 的昵称展开
    @Test func fromPlaceholderSubstituted() {
        let inner = "\"张三\" 撤回了一条消息"
        var xml = Array(("<revokemsg><replacemsg>" + inner + "</replacemsg></revokemsg>").utf8)
        let tip = Array("{from} 想撤回已拦截".utf8)
        let r: Int = xml.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(r == Array(inner.utf8).count)
        let got = Array(xml)
        let openIdx = got.firstRange(of: Array("<replacemsg>".utf8))!.upperBound
        let expect = Array("张三 想撤回已拦截".utf8)
        #expect(Array(got[openIdx..<openIdx + expect.count]) == expect)
        #expect(Array(got[(openIdx + expect.count)..<got.firstRange(of: Array("</replacemsg>".utf8))!.lowerBound]
                .filter { $0 != UInt8(ascii: " ") }) == [])
    }

    /// 内文无引号形态（昵称不可解析）→ 占位符展开为空，不放弃改写
    @Test func fromPlaceholderWithoutQuotesExpandsEmpty() {
        var xml = Array("<revokemsg><replacemsg>张三撤回了一条消息</replacemsg></revokemsg>".utf8)
        let tip = Array("已拦截{from}".utf8)
        let r: Int = xml.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(r == Array("张三撤回了一条消息".utf8).count)
        let got = Array(xml)
        let openIdx = got.firstRange(of: Array("<replacemsg>".utf8))!.upperBound
        let expect = Array("已拦截".utf8)
        #expect(Array(got[openIdx..<openIdx + expect.count]) == expect)
        #expect(got[openIdx + expect.count] == UInt8(ascii: " "))   // {from} → 空，紧跟填充空格
    }

    /// 展开后超内文长 → 放弃保原文（截断昵称会切碎 UTF-8，宁可不写）
    @Test func fromExpansionTooLongDeclined() {
        let xml = Array("<revokemsg><replacemsg>\"李\" 撤回</replacemsg></revokemsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: Array("{from}的这条消息被拦截保留展示".utf8)) == -1)
        #expect(xml == snapshot)
    }

    // ---- 自发撤回门（默认不改写「你撤回了一条消息」） ----

    @Test func selfRevokeTipSkippedByDefault() {
        let xml = Array("<revokemsg><replacemsg>你撤回了一条消息</replacemsg></revokemsg>".utf8)
        let snapshot = xml
        #expect(run(xml, tip: Array("已拦截".utf8)) == -1)
        #expect(xml == snapshot)   // 自发撤回保持诚实反馈
    }

    @Test func selfRevokeRewrittenWhenPolicyEnabled() {
        defer { wxkeep_runtime_test_set_policy(0) }
        wxkeep_runtime_test_set_policy(1)
        var xml = Array("<revokemsg><replacemsg>你撤回了一条消息</replacemsg></revokemsg>".utf8)
        let tip = Array("已拦截".utf8)
        let r: Int = xml.withUnsafeMutableBufferPointer { d -> Int in
            tip.withUnsafeBufferPointer { t -> Int in
                wxkeep_runtime_test_rewrite(
                    d.baseAddress, CUnsignedLong(d.count),
                    UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self),
                    CUnsignedLong(t.count))
            }
        }
        #expect(r == Array("你撤回了一条消息".utf8).count)
    }

    // ---- 外部 hooks 地址表（runtime.json 数据通道） ----

    private func parseHooks(_ json: String) -> Int32 {
        json.withCString { p -> Int32 in
            wxkeep_runtime_test_parse_hooks(p, CUnsignedLong(strlen(p)))
        }
    }

    /// 合法行（270099 wrapper 形态）被接受，字段逐一可回读
    @Test func hooksParseValidRow() {
        let n = parseHooks("""
        {"hooks":[{"build":"270099","uuid":"97e21436-abda-3b79-bec0-ef2653c6b423",
        "arch":"x86_64","hook_off":"0x537d910","msg_arg":1,"xml_sso_off":304,
        "expected":"554889E54157415641554154"}]}
        """)
        #expect(n == 1)
        var off: CUnsignedLong = 0, marg: CUnsignedLong = 0, soff: CUnsignedLong = 0
        var arm: CInt = 0, elen: CInt = 0
        #expect(wxkeep_runtime_test_hook_row(0, &off, &marg, &soff, &arm, &elen) == 0)
        #expect(off == 0x537d910)
        #expect(marg == 1)
        #expect(soff == 0x130)
        #expect(arm == 0)
        #expect(elen == 12)
        #expect(wxkeep_runtime_test_hook_row(1, &off, &marg, &soff, &arm, &elen) == -1)
    }

    /// 坏行整表拒绝（宁可不挂也不挂错）：坏 hex / expected 长度不符 /
    /// arm64 序言含 ADRP（PC 相对，换址即崩）。每行都带合法 xml_sso_off——
    /// 缺字段门（见 hooksRejectRowMissingXmlSsoOff）不得掩盖各自被测的门。
    @Test func hooksRejectBadRows() {
        #expect(parseHooks("""
        {"hooks":[{"uuid":"97e21436-abda-3b79-bec0-ef2653c6b423","hook_off":"0x1",
        "xml_sso_off":0,"expected":"ZZGG"}]}
        """) == 0)
        #expect(parseHooks("""
        {"hooks":[{"uuid":"97e21436-abda-3b79-bec0-ef2653c6b423","hook_off":"0x1",
        "arch":"x86_64","xml_sso_off":0,"expected":"554889E5"}]}
        """) == 0)   // x64 必须 12B
        // ADRP x0, #0（字 0x90000000，LE 字节 00 00 00 90）+ 合法栈序言凑 16B → 必须被拒
        #expect(parseHooks("""
        {"hooks":[{"uuid":"97e21436-abda-3b79-bec0-ef2653c6b423","hook_off":"0x1",
        "arch":"arm64","xml_sso_off":0,"expected":"00000090A9BF7BFDFD7BBFA9FD6F01A9"}]}
        """) == 0)
        // 非法 UUID 形制
        #expect(parseHooks("""
        {"hooks":[{"uuid":"not-a-uuid","hook_off":"0x1","xml_sso_off":0,
        "expected":"554889E54157415641554154"}]}
        """) == 0)
        // 非 JSON / hooks 缺失 → -1 / 0
        #expect(parseHooks("not-json") == -1)
        #expect(parseHooks("{\"tip_text\":\"x\"}") == 0)
    }

    /// 缺 xml_sso_off 的行整行拒绝：该字段决定 hook 从哪个地址读 SSO 头，
    /// 旧缺省 0x130 是被 ㉒ 证伪的 wrapper 模型残值（parse 直挂语义下是
    /// 错误偏移）——静默读错位置不如不挂。
    @Test func hooksRejectRowMissingXmlSsoOff() {
        #expect(parseHooks("""
        {"hooks":[{"uuid":"97e21436-abda-3b79-bec0-ef2653c6b423","arch":"x86_64",
        "hook_off":"0x537d910","msg_arg":1,"expected":"554889E54157415641554154"}]}
        """) == 0)
    }

    /// 容量回归锁：外部表必须全收 128 行合法数据。knownHooks 现量 30 行
    /// 且随 update-data 分发新构建行单调增长；旧上限 32 时越限行（追加在
    /// 尾部的新构建行——恰是未来最需要武装的）被 parse 循环静默丢弃。
    @Test func hooksTableAccepts128Rows() {
        var rows = ""
        for i in 0..<128 {
            if !rows.isEmpty { rows += "," }
            let uuid = String(format: "%08d-0000-0000-0000-000000000000", i)
            rows += "{\"uuid\":\"\(uuid)\",\"arch\":\"x86_64\",\"hook_off\":\"0x537d910\","
                + "\"msg_arg\":1,\"xml_sso_off\":0,\"expected\":\"554889E54157415641554154\"}"
        }
        #expect(parseHooks("{\"hooks\":[\(rows)]}") == 128)
    }

    /// 好坏混合：只收好行
    @Test func hooksMixedRowsKeepGood() {
        let n = parseHooks("""
        {"hooks":[
          {"uuid":"bad","hook_off":"0x1","expected":"554889E54157415641554154"},
          {"build":"270099","uuid":"97e21436-abda-3b79-bec0-ef2653c6b423",
           "arch":"x86_64","hook_off":"0x537d910","msg_arg":1,"xml_sso_off":304,
           "expected":"554889E54157415641554154"}]}
        """)
        #expect(n == 1)
    }

    /// 合法 arm64 行（纯栈序言 16B，无 PC 相对）被接受
    @Test func hooksAcceptRelocatableArm64Row() {
        let n = parseHooks("""
        {"hooks":[{"build":"x","uuid":"97e21436-abda-3b79-bec0-ef2653c6b423",
        "arch":"arm64","hook_off":"0x4000000","msg_arg":1,"xml_sso_off":304,
        "expected":"FD7BBFA9FD6F01A9F85FBCA9F44F02A9"}]}
        """)
        #expect(n == 1)
        var off: CUnsignedLong = 0, marg: CUnsignedLong = 0, soff: CUnsignedLong = 0
        var arm: CInt = 0, elen: CInt = 0
        #expect(wxkeep_runtime_test_hook_row(0, &off, &marg, &soff, &arm, &elen) == 0)
        #expect(arm == 1)
        #expect(elen == 16)
    }
}

/// 跨边界回归：RuntimeConfig.knownHooks（Swift 管理面）必须被 C 侧
/// hook_row_parse 全数接受——两侧行 schema 漂移（字段改名/形制不符/
/// 序言含 PC 相对编码）在此锁死，而不是等 runtime install 后 hook 静默不装。
/// （本测试通过 RuntimeConfig 常量驱动；RuntimeHookTests 文件内
/// @testable WxkeepRuntime + wxkeep 双模块可用。）
extension RuntimeHookTests {
    @Test func knownHooksRowsAllPassCParser() throws {
        #if canImport(wxkeep)
        let rows = RuntimeConfig.knownHooks
        try #require(!rows.isEmpty)
        let enc = JSONEncoder()
        var json = "{\"hooks\":["
        for (i, row) in rows.enumerated() {
            if i > 0 { json += "," }
            json += String(decoding: try enc.encode(row), as: UTF8.self)
        }
        json += "]}"
        let accepted = json.withCString { p -> Int32 in
            wxkeep_runtime_test_parse_hooks(p, CUnsignedLong(strlen(p)))
        }
        #expect(accepted == Int32(rows.count),
                "knownHooks 必须全数通过 C 侧解析门（accepted=\(accepted), rows=\(rows.count)）")
        // 唯一性：uuid 不得重复（重复行会静默覆盖 match_target 的先后序）；
        // 同一构建 x64/arm64 双切片各一行，(build, arch) 亦须唯一
        #expect(Set(rows.map(\.uuid)).count == rows.count)
        #expect(Set(rows.map { "\($0.build)/\($0.arch)" }).count == rows.count)
        #endif
    }
}

/// 通用 keeptip（runtime XML 清零）：parse 前把 <newmsgid> 数字等长清零
/// → 撤回删除按目标查不到 → 消息保留。跨构建通用（不依赖指令地址）。
extension RuntimeHookTests {
    @Test func zeroNewmsgidDigits() {
        var xml = Array("<msg><newmsgid>467688165590285950</newmsgid><msgid>720</msgid></msg>".utf8)
        var copy = xml
        let n = copy.withUnsafeMutableBufferPointer { b -> Int32 in
            wxkeep_runtime_test_zero(b.baseAddress, CUnsignedLong(b.count))
        }
        #expect(n == 16, "18 位中 16 位非零数字清零（已有 0 不计）")
        let expect = Array("<msg><newmsgid>000000000000000000</newmsgid><msgid>720</msgid></msg>".utf8)
        #expect(copy == expect, "数字等长替换为 0，其余（含 msgid）不动")
        _ = xml
    }

    @Test func zeroNewmsgidEdgeCases() {
        // 无 newmsgid 标签 → 0
        var xml = Array("<msg><content>x</content></msg>".utf8)
        let n1 = xml.withUnsafeMutableBufferPointer { b -> Int32 in
            wxkeep_runtime_test_zero(b.baseAddress, CUnsignedLong(b.count))
        }
        #expect(n1 == 0)
        // 已是 0 的数字不改（幂等）
        var zeroed = Array("<newmsgid>000</newmsgid>".utf8)
        let n2 = zeroed.withUnsafeMutableBufferPointer { b -> Int32 in
            wxkeep_runtime_test_zero(b.baseAddress, CUnsignedLong(b.count))
        }
        #expect(n2 == 0)
        #expect(zeroed == Array("<newmsgid>000</newmsgid>".utf8))
        // 数字后紧跟非数字字符即停
        var mixed = Array("<newmsgid>12x34</newmsgid>".utf8)
        let n3 = mixed.withUnsafeMutableBufferPointer { b -> Int32 in
            wxkeep_runtime_test_zero(b.baseAddress, CUnsignedLong(b.count))
        }
        #expect(n3 == 2)
        #expect(mixed == Array("<newmsgid>00x34</newmsgid>".utf8))
    }
}
