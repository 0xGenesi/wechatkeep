import Testing
import Foundation
@testable import wxkeep
@testable import WxkeepRuntime

/// RuntimeConfig.mergeKnownHooks：runtime.json 的 hooks 管理段合并语义。
/// 关键不变量：未知 uuid 的既有行保留（update-data 下发的新构建行不被旧
/// 工具回退）、已知 uuid 行被替换、用户键（tip_text 等）原样透传。
struct RuntimeConfigTests {

    private func tmpConfigPath() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-rtcfg-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("runtime.json")
    }

    @Test func mergeIntoMissingFileCreatesManagedSection() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let rows = try RuntimeConfig.mergeKnownHooks(into: [url])
        #expect(rows.count == RuntimeConfig.knownHooks.count)
        #expect(rows.contains { $0.build == "270099" && $0.hook_off == "0x537db40" })

        // 落盘形态：hooks 在场且可回读（含 270099 实流行）
        let dict = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), options: [], format: nil) as? [String: Any]
        let hooks = dict?["hooks"] as? [[String: Any]]
        #expect(hooks?.count == RuntimeConfig.knownHooks.count)
        #expect(hooks?.contains { ($0["uuid"] as? String) == "97e21436-abda-3b79-bec0-ef2653c6b423" } == true)
        #expect(hooks?.contains { ($0["hook_off"] as? String) == "0x537db40" } == true)
    }

    @Test func mergePreservesUserKeysAndUnknownRows() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        // 预置：用户文案 + 一行“未来构建”的 hooks 行（uuid 未知）+ 一行旧版 270099 行
        let future = RuntimeConfig.HookRow(
            build: "271000", uuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeffff0000",
            arch: "arm64", hook_off: "0x4000000", msg_arg: 1, xml_sso_off: 0x140,
            expected: "FD7BBFA9FD6F01A9F85FBCA9F44F02A9")
        let stale270099 = RuntimeConfig.HookRow(
            build: "270099", uuid: "97e21436-abda-3b79-bec0-ef2653c6b423",
            arch: "x86_64", hook_off: "0xDEADBEEF", msg_arg: 1, xml_sso_off: 0x130,
            expected: "AABBCCDDEEFF001122334455")
        var dict: [String: Any] = ["tip_text": "我的文案", "rewrite_self": true]
        let enc = JSONEncoder()
        dict["hooks"] = [try JSONSerialization.jsonObject(with: enc.encode(future)),
                         try JSONSerialization.jsonObject(with: enc.encode(stale270099))]
            as? [[String: Any]]
        try JSONSerialization.data(withJSONObject: dict).write(to: url)

        let rows = try RuntimeConfig.mergeKnownHooks(into: [url])
        // 旧 270099 行被替换为 knownHooks 版本（全表重写），future 行保留
        #expect(rows.count == RuntimeConfig.knownHooks.count + 1)
        #expect(rows.first { $0.build == "270099" }?.hook_off == "0x537db40")
        #expect(rows.contains { $0.uuid == future.uuid && $0.hook_off == future.hook_off })

        // 用户键透传
        let back = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), options: [], format: nil) as? [String: Any]
        #expect(back?["tip_text"] as? String == "我的文案")
        #expect(back?["rewrite_self"] as? Bool == true)
    }

    @Test func mergeIsIdempotent() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        _ = try RuntimeConfig.mergeKnownHooks(into: [url])
        let first = try Data(contentsOf: url)
        _ = try RuntimeConfig.mergeKnownHooks(into: [url])
        #expect(try Data(contentsOf: url) == first)
    }

    /// marker 候选序（77 续对偶修复）：序 = dylib 写序，第 2 位必须是微信
    /// 沙盒容器的 legacy Application Support（沙盒 Group 写被拒时的回落位），
    /// 第 3 位 = 真实 home 的 legacy 位（非沙盒宿主）。
    @Test func markerURLsOrderMatchesDylibWriteOrder() {
        let urls = RuntimeConfig.markerURLs
        #expect(urls.count == 3)
        #expect(urls[0].path.contains("Group Containers/\(RuntimeConfig.appGroupID)/wxkeep/runtime.marker"))
        #expect(urls[1].path.contains(
            "Containers/\(RuntimeConfig.wechatContainerBundleID)/Data/Library/Application Support/wxkeep/runtime.marker"))
        #expect(urls[2].path == FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/wxkeep/runtime.marker").path)
    }

    /// readMarkerText 按候选序探查：首位缺失时必须落到次位——沙盒微信场景
    /// （Group 无 marker、容器 legacy 位有）status/doctor 不再「无记录」。
    @Test func readMarkerTextFallsThroughCandidates() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-mk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let miss = dir.appendingPathComponent("missing.marker")
        let hit = dir.appendingPathComponent("hit.marker")
        try "loaded ts=1 mr2=hook-armed status=8 enc=2".write(to: hit, atomically: true, encoding: .utf8)
        #expect(RuntimeConfig.readMarkerText(at: [miss, hit]) == "loaded ts=1 mr2=hook-armed status=8 enc=2")
        #expect(RuntimeConfig.readMarkerText(at: [miss]) == nil)
        #expect(RuntimeConfig.readMarkerText(at: []) == nil)
    }

    /// HookRow wire format（77 续②补键名漂移修复锁）：mergeKnownHooks 经
    /// JSONEncoder 写 runtime.json，新字段的 wire 键必须是 snake_case
    /// （dylib hook_row_parse 读 func_size/anchor_va/anchor_bytes）——合成键
    /// 会写成 camelCase 而门静默失效（68 轮 verify_variants 同坑）。
    @Test func hookRowWireKeysAreSnakeCase() throws {
        let row = RuntimeConfig.HookRow(
            build: "270100", uuid: "0b9929bb-e55e-3513-b439-32375760bca2",
            arch: "arm64", hook_off: "0x4bc4d34", msg_arg: 1, xml_sso_off: 0,
            expected: "F85FBCA9F65701A9F44F02A9FD7B03A9",
            func_size: 4380, anchor_va: "0x4bc4e00", anchor_bytes: "AABB")
        let obj = try JSONSerialization.jsonObject(with: JSONEncoder().encode(row)) as! [String: Any]
        #expect(obj["func_size"] as? Int == 4380)
        #expect(obj["anchor_va"] as? String == "0x4bc4e00")
        #expect(obj["anchor_bytes"] as? String == "AABB")
        #expect(obj["funcSize"] == nil, "合成键 camelCase 混入 wire format = dylib 读不到")
        // 解码回读（update-data 旧数据含新键时的兼容面）
        let back = try JSONDecoder().decode(RuntimeConfig.HookRow.self, from: JSONEncoder().encode(row))
        #expect(back == row)
    }

    /// funcSize 数据契约（77 续②补 16 行；⑫zsbai 三构建回填至 22 行）：
    /// 带门行值域合法、家族值恒定（x64=5216/arm64=4380，11 构建 × 双架构
    /// pristine 切片三重校验派生——hook_off 必为 FUNCTION_STARTS 起点、
    /// 切片 UUID 与行一致、距离=到下一函数起点）。
    @Test func knownHooksFuncSizeContract() {
        let gated = RuntimeConfig.knownHooks.filter { $0.func_size != nil }
        #expect(gated.count == 22, "本地有 pristine 切片的 11 构建 × 双架构应全带门")
        let inRange = gated.allSatisfy { row in
            let v = row.func_size!
            return v > 0 && v <= 1 << 21
        }
        #expect(inRange, "C 侧 func_size 门值域（0, 2MB]")
        let x64 = gated.filter { $0.arch == "x86_64" }
        let arm64 = gated.filter { $0.arch == "arm64" }
        #expect(x64.allSatisfy { $0.func_size == 5216 })
        #expect(arm64.allSatisfy { $0.func_size == 4380 })
        let builds = Set(gated.map { $0.build })
        let want: Set<String> = ["270094", "270097", "270099",
                                 "270100", "270101", "270102",
                                 "270131", "270132", "270133", "270134", "270135"]
        #expect(builds == want)
    }

    /// knownHooks 表结构契约（77 续⑮）：编译期表是 runtime.json hooks 行的
    /// 唯一来源（install/hooks 全量写入），表自身的形态错误会让 dylib 侧
    /// hook_row_parse **静默丢行**（宁可不挂也不挂错）——丢行 = 该构建 hook
    /// 永不武装且无任何报错。把 dylib 侧接受域镜像成 Swift 侧断言，行加错
    /// 在编译期测试即红，而不是装机后「未武装」排障：
    /// - 44 行 = 22 构建 × {x86_64, arm64} 对称（每构建恰一行/架构）
    /// - UUID 全表唯一（身份门键）；hook_off 合法 hex 且 ∈ (0, 2^32)
    /// - msg_arg ≤ 5、xml_sso_off ≤ 0x1000（hook_row_parse 的行拒绝界）
    /// - expected 长度匹配架构（x64 12B / arm64 16B）
    /// - anchor 字段成对出现（半个锚点 = 行拒绝）
    @Test func knownHooksTableContract() {
        let rows = RuntimeConfig.knownHooks
        #expect(rows.count == 44, "4.1.15 全家族（除未发布 270087/092）+ 270131-135 × 双架构")
        // 每构建恰好双架构各一行
        var byBuild: [String: Set<String>] = [:]
        for row in rows { byBuild[row.build, default: []].insert(row.arch) }
        #expect(byBuild.count == 22)
        #expect(byBuild.values.allSatisfy { $0 == ["x86_64", "arm64"] })
        // UUID 唯一 + 形制（dylib uuid_str_valid：36 字符连字符小写 hex）
        let uuids = rows.map(\.uuid)
        #expect(Set(uuids).count == rows.count, "UUID 重复 = 身份门歧义")
        #expect(uuids.allSatisfy { $0.count == 36 && $0.allSatisfy { c in
            c == "-" || c.isHexDigit && !c.isUppercase } })
        // hook_row_parse 的行拒绝界（越界行被静默丢弃）
        #expect(rows.allSatisfy { row in
            guard row.hook_off.hasPrefix("0x"),
                  let va = UInt64(row.hook_off.dropFirst(2), radix: 16)
            else { return false }
            return va > 0 && va < (1 << 32)
        }, "hook_off 必须是 (0, 2^32) 内的 0x hex——strtoull 解析失败的行 dylib 侧整行丢弃")
        #expect(rows.allSatisfy { $0.msg_arg >= 1 && $0.msg_arg <= 5 && $0.xml_sso_off <= 0x1000 })
        #expect(rows.allSatisfy { row in
            let want = row.arch == "arm64" ? 32 : 24   // hex 字符数 = 16B / 12B
            return row.expected.count == want && row.expected.allSatisfy(\.isHexDigit)
        }, "expected 长度/字符必须匹配架构——parse_hex 产出长度不符即整行拒绝")
        #expect(rows.allSatisfy { ($0.anchor_va != nil) == ($0.anchor_bytes != nil) },
                "anchor_va/anchor_bytes 必须成对——半个锚点字段整行拒绝")
    }
}

/// 端到端格式回归：mergeKnownHooks 落盘的文件必须被 dylib 生产路径
/// （dictionaryWithContentsOfFile 的 plist 语义）解析——锁死
/// 「CLI 写 JSON / dylib 读 plist」的跨格式静默回落（2026-09-19 实测
/// 旧行为：runtime install 的 hooks 写入对 plist 存量文件直接失败，
/// dylib 连 tip_text 一起丢）。
extension RuntimeConfigTests {
    @Test func mergedFileIsReadableByDylibProductionPath() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        // 预置 plist 形态的存量文件（用户已配置的 tip_text）
        let existing: [String: Any] = ["tip_text": "⚠️ 已拦截撤回 · 原文已保留"]
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: existing, format: .xml, options: 0)
        try plistData.write(to: url)

        _ = try RuntimeConfig.mergeKnownHooks(into: [url])

        // 落盘仍是 plist（XML 头），且 dylib 生产路径能读到全部行 + tip
        let head = try String(contentsOf: url, encoding: .utf8)
        #expect(head.contains("<!DOCTYPE plist"))
        let path = url.path.withCString { p -> Int32 in
            wxkeep_runtime_test_load_config_file(p)
        }
        #expect(path == Int32(RuntimeConfig.knownHooks.count),
                "dylib 生产路径必须读到全部 knownHooks 行（got \(path)）")
        let tipLen = Int(wxkeep_runtime_test_tip_len())
        #expect(tipLen == "⚠️ 已拦截撤回 · 原文已保留".utf8.count)
    }
}

/// dylibSearchOrder：runtime dylib 解析序（显式 > env > brew lib > exe 同目录 > .build）。
/// brew 用户流程（Cellar lib 命中）是 0.2.0 分发的关键路径，锁死顺序防回归。
extension RuntimeConfigTests {
    @Test func dylibSearchOrderPrefersExplicitThenBrewLib() {
        let order = Wxkeep.RuntimeCommand.dylibSearchOrder(
            explicit: "/explicit/lib.dylib", env: "/env/lib.dylib",
            exePath: "/usr/local/Cellar/wxkeep/0.2.0/bin/wxkeep", cwd: "/tmp")
        #expect(order.count == 5)
        #expect(order[0] == "/explicit/lib.dylib")
        #expect(order[1] == "/env/lib.dylib")
        #expect(order[2] == "/usr/local/Cellar/wxkeep/0.2.0/lib/libwxkeep_runtime.dylib",
                "brew 布局：符号链接解析到 Cellar 后取 ../lib")
        #expect(order[3] == "/usr/local/Cellar/wxkeep/0.2.0/bin/libwxkeep_runtime.dylib")
        #expect(order[4] == "/tmp/.build/release/libwxkeep_runtime.dylib")
    }

    @Test func dylibSearchOrderSkipsEmptyExplicitAndEnv() {
        let order = Wxkeep.RuntimeCommand.dylibSearchOrder(
            explicit: nil, env: "",
            exePath: "/opt/cli/wxkeep", cwd: "/work")
        #expect(order.count == 3)
        #expect(order[0] == "/opt/lib/libwxkeep_runtime.dylib")
    }
}

/// `wxkeep runtime tip` 的校验与读写（0.2.0 实机验证的渲染契约，ROADMAP ㉒）：
/// 文案必须保持官方骨架 `"…" 撤回了一条消息`，总长 ≤ ~31B，`<>&` 剥除。
extension RuntimeConfigTests {

    @Test func tipValidationAcceptsVerifiedSkeleton() {
        let (n, v) = RuntimeConfig.validateTip("\"⚠️\" 撤回了一条消息")
        #expect(n == "\"⚠️\" 撤回了一条消息")
        if case .ok = v {} else { Issue.record("verified form must pass clean") }
    }

    @Test func tipValidationAcceptsFromPlaceholder() {
        // 纯 {from} 形态：展开后与原内文逐字节同构（昵称可解析时恒等长）
        let (_, v) = RuntimeConfig.validateTip("\"{from}\" 撤回了一条消息")
        if case .ok = v {} else { Issue.record("pure {from} form is the exact-fit form") }
    }

    @Test func tipValidationNotesMixedFromForm() {
        // ⚠️ + {from} 混合：骨架合法但展开长度随昵称增长——带告警接受
        let (_, v) = RuntimeConfig.validateTip("\"⚠️{from}\" 撤回了一条消息")
        guard case .acceptedWithNotes(let notes) = v else {
            Issue.record("mixed {from} form passes with note")
            return
        }
        #expect(notes.contains { $0.contains("{from}") })
    }

    @Test func tipValidationRejectsBrokenSkeleton() {
        // 空昵称 / 缺后缀 / 多尾巴 / 缺引号——渲染层会显示 Unsupported 占位
        for bad in ["\"\" 撤回了一条消息", "\"⚠️\" 撤回了", "\"⚠️\" 撤回了一条消息 啊",
                    "撤回了一条消息", "\"⚠️ 撤回了一条消息"] {
            if case .rejected = RuntimeConfig.validateTip(bad).1 {} else {
                Issue.record("must reject: \(bad)")
            }
        }
    }

    @Test func tipValidationRejectsOverlong() {
        // 34B 实机实证被拒（㉒ 第 2 条）——超 ~31B 的静态文案直接拒绝
        let long = "\"" + String(repeating: "警", count: 8) + "\" 撤回了一条消息"
        #expect(long.utf8.count > 31)
        if case .rejected = RuntimeConfig.validateTip(long).1 {} else {
            Issue.record("34B tip must be rejected")
        }
    }

    @Test func tipValidationStripsXmlBreakingChars() {
        let (n, v) = RuntimeConfig.validateTip("\"<a&b>\" 撤回了一条消息")
        #expect(!n.contains("<") && !n.contains(">") && !n.contains("&"))
        guard case .acceptedWithNotes(let notes) = v else {
            Issue.record("stripped skeleton still valid")
            return
        }
        #expect(notes.contains { $0.contains("剥除") })
    }

    @Test func tipWriteReadRoundTripPreservesHooks() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        // 目标文件必须预建：mergeKnownHooks 对缺失目标会以真 home 配置为
        // 迁移种子（by design），策略键（keep_message 等）会随之渗入——
        // 本用例断言的是缺省值语义，与环境配置解耦（2026-10-28 实弹暴露）。
        let seed = try PropertyListSerialization.data(fromPropertyList: ["hooks": []],
                                                      format: .xml, options: 0)
        try seed.write(to: url)
        _ = try RuntimeConfig.mergeKnownHooks(into: [url])   // 预置 hooks 管理段

        try RuntimeConfig.writeTip(text: "\"⚠️\" 撤回了一条消息", rewriteSelf: true, at: [url])
        let tip = RuntimeConfig.readTip(at: [url])
        #expect(tip.text == "\"⚠️\" 撤回了一条消息")
        #expect(tip.rewriteSelf == true)
        #expect(tip.keepMessage == true, "未触碰 keep_message（缺省开）")
        // hooks 不被 tip 写入清掉
        let dict = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: url), options: [], format: nil) as? [String: Any]
        #expect((dict?["hooks"] as? [[String: Any]])?.count == RuntimeConfig.knownHooks.count)

        try RuntimeConfig.removeTip(at: [url])
        #expect(RuntimeConfig.readTip(at: [url]).text == nil)
        #expect(RuntimeConfig.readTip(at: [url]).rewriteSelf == true, "removeTip 只动 tip_text")
    }

    /// CLI 写完的 tip 文件必须是 plist 格式（dylib dictionaryWithContentsOfFile
    /// 语义；跨端到端读取回归由 mergedFileIsReadableByDylibProductionPath 锁死）
    @Test func tipWriteProducesPlist() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try RuntimeConfig.writeTip(text: "\"⚠️\" 撤回了一条消息", rewriteSelf: nil, at: [url])
        let head = try String(contentsOf: url, encoding: .utf8)
        #expect(head.contains("<!DOCTYPE plist"))
        #expect(head.contains("tip_text"))
    }

    /// cfg_hash（V4 需求 3）：CLI 侧指纹算法与 runtime.m 的 FNV-1a 64 同构，
    /// 空文件有确定值、内容变化指纹变化（touch -r 还原 mtime 也还原不了内容）。
    @Test func configContentHashStableAndSensitive() throws {
        let url = tmpConfigPath()
        try Data().write(to: url)
        let empty = RuntimeConfig.currentConfigContentHash(at: [url])
        #expect(empty == 1_469_598_103_934_665_603)   // FNV offset basis（空输入）

        try Data("keep_message = true".utf8).write(to: url)
        let a = RuntimeConfig.currentConfigContentHash(at: [url])
        #expect(a != empty && a != nil)

        try Data("keep_message = false".utf8).write(to: url)
        let b = RuntimeConfig.currentConfigContentHash(at: [url])
        #expect(b != a)   // 一字节之差指纹必变
        try FileManager.default.removeItem(at: url)
        #expect(RuntimeConfig.currentConfigContentHash(at: [url]) == nil)   // 不可读 = nil
    }

    // MARK: - 98 轮：双路径面（Group + 微信沙盒容器 AS）回归

    /// 双写收敛：writeTip 双目标各落一份同内容；基座分歧键按「容器优先」
    /// 裁决——Group 陈旧 keep=false 不得覆盖容器在役 keep=true（灾难方向
    /// 防线，98 轮实弹前的手工镜像即为此）。
    @Test func dualWriteConvergesAndContainerWins() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-cfgtest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let group = dir.appendingPathComponent("group.json")
        let container = dir.appendingPathComponent("container.json")
        let enc = try PropertyListSerialization.data(fromPropertyList:
            ["keep_message": false, "tip_text": "旧"], format: .xml, options: 0)
        try enc.write(to: group)
        try PropertyListSerialization.data(fromPropertyList:
            ["keep_message": true, "hooks": [["build": "270135"]]],
            format: .xml, options: 0).write(to: container)

        let written = try RuntimeConfig.writeTip(
            text: "\"⚠️\" 撤回了一条消息", rewriteSelf: nil,
            at: [group, container])   // 基座缺省=targets（容器优先叠加）
        #expect(written.count == 2)

        for u in [group, container] {
            let d = try PropertyListSerialization.propertyList(
                from: Data(contentsOf: u), options: [], format: nil) as? [String: Any]
            #expect(d?["keep_message"] as? Bool == true,
                    "容器优先：Group 陈旧 keep=false 不得外溢")
            #expect(d?["tip_text"] as? String == "\"⚠️\" 撤回了一条消息")
            #expect((d?["hooks"] as? [[String: Any]])?.count == 1, "基座键透传")
        }
    }

    /// 读回落序：Group 缺失时读容器 AS（ad-hoc 装机的进程真读形态）。
    @Test func readTipFallsBackToContainer() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-cfgtest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let missing = dir.appendingPathComponent("absent.json")
        let container = dir.appendingPathComponent("container.json")
        try PropertyListSerialization.data(fromPropertyList:
            ["tip_text": "\"{from}\" 撤回了一条消息", "keep_message": true],
            format: .xml, options: 0).write(to: container)

        let tip = RuntimeConfig.readTip(at: [missing, container])
        #expect(tip.text == "\"{from}\" 撤回了一条消息")
        #expect(tip.keepMessage == true)
    }

    /// status 漂移面：marker 指纹对上任一候选即一致（进程读 Group 或容器
    /// AS 都算）；全部不匹配才算漂移。
    @Test func contentHashesCoverEveryCandidate() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-cfgtest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = dir.appendingPathComponent("a.json")
        let b = dir.appendingPathComponent("b.json")
        try Data("keep=true".utf8).write(to: a)
        try Data("keep=false".utf8).write(to: b)

        let hashes = RuntimeConfig.configContentHashes(at: [a, b])
        #expect(hashes.count == 2)
        #expect(hashes[0].url == a)   // 候选序保持
        #expect(hashes[0].hash != hashes[1].hash)
        #expect(RuntimeConfig.currentConfigContentHash(at: [a, b]) == hashes[0].hash)
        #expect(RuntimeConfig.configContentHashes(at: [dir.appendingPathComponent("x.json")]).isEmpty)
    }
}

/// 93 轮：能力探针纯函数——输出解析/判定/entitlements 过滤。
/// 背景：T4/T5 三轮机械工程的根因是「机制工程先于机制探针」——探针把
/// go/no-go 提前到 install 之前，这里锁死判定语义。
struct WxProbeTests {
    @Test func probeOutputParsing() {
        let out = "mprotect_direct=13\nremap_cow=4\njit_write=0\n"
        let p = Wxkeep.RuntimeCommand.parseProbeOutput(out)
        #expect(p.mprotect == 13)
        #expect(p.remap == 4)
        #expect(p.jit == 0)
        let empty = Wxkeep.RuntimeCommand.parseProbeOutput("garbage")
        #expect(empty.mprotect == nil && empty.remap == nil && empty.jit == nil)
    }

    @Test func probeVerdictSemantics() {
        // 可武装 = 既有签名代码页存在可写化路径（mprotect 或 remap 任一为 0）
        #expect(Wxkeep.RuntimeCommand.probeVerdict(mprotect: 0, remap: 4) == "writable")
        #expect(Wxkeep.RuntimeCommand.probeVerdict(mprotect: 13, remap: 0) == "writable")
        #expect(Wxkeep.RuntimeCommand.probeVerdict(mprotect: 13, remap: 4) == "blocked")
        // 缺项（探针运行异常）= 不可判定，不是 blocked（保守——让装后 marker 定案）
        #expect(Wxkeep.RuntimeCommand.probeVerdict(mprotect: nil, remap: 4) == "inconclusive")
        #expect(Wxkeep.RuntimeCommand.probeVerdict(mprotect: nil, remap: nil) == "inconclusive")
    }

    @Test func csOnlyEntitlementFilter() throws {
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>com.apple.application-identifier</key><string>5A4RE8SF68.com.tencent.xinWeChat</string>
        <key>com.apple.security.app-sandbox</key><true/>
        <key>com.apple.security.cs.allow-jit</key><true/>
        <key>com.apple.security.cs.disable-library-validation</key><true/>
        <key>com.apple.security.get-task-allow</key><true/>
        <key>com.apple.security.application-groups</key><array><string>5A4RE8SF68.x</string></array>
        </dict></plist>
        """
        let filtered = try #require(Wxkeep.RuntimeCommand.csOnlyEntitlements(xml))
        #expect(filtered.contains("allow-jit"))
        #expect(filtered.contains("disable-library-validation"))
        #expect(filtered.contains("get-task-allow"))
        #expect(!filtered.contains("app-sandbox"))
        #expect(!filtered.contains("application-identifier"))
        #expect(!filtered.contains("application-groups"))
        // 全被剥光的极端 = nil（调用方回落无 entitlements 重签）
        let bare = """
        <?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
        <key>com.apple.security.app-sandbox</key><true/></dict></plist>
        """
        #expect(Wxkeep.RuntimeCommand.csOnlyEntitlements(bare) == nil)
    }
}
