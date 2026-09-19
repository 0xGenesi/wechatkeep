import Foundation

/// runtime.json 的管理段：hooks 地址表（dylib 侧解析见 runtime.m 的
/// hook_row_parse——两侧行 schema 必须一致）。
///
/// 外部表是新构建 day-0 支持的数据通道：研究产出新构建的 hook 行后，
/// 更新 `knownHooks`（或经 update-data 分发的数据）重跑
/// `wxkeep runtime install` 即生效，dylib 不必重编。dylib 侧规则：
/// runtime.json 有合法 hooks 行则只用外部表，否则回落编译期内置表。
enum RuntimeConfig {
    struct HookRow: Codable, Equatable {
        /// 诊断标注（构建号）
        let build: String
        /// wechat.dylib 对应切片的 LC_UUID（身份门，标准连字符小写形）
        let uuid: String
        /// "x86_64" | "arm64"
        let arch: String
        /// hook 目标在切片内的 VM 偏移（0x 前缀 hex 字符串）
        let hook_off: String
        /// 消息结构在第几个整型参数（x64: 1=rsi / arm64: 1=x1）
        let msg_arg: Int
        /// 撤回 XML SSO 字段在消息结构内的偏移
        let xml_sso_off: Int
        /// 入口原像 hex（x64 12B / arm64 16B，防漂移门）
        let expected: String
    }

    /// 编译期已知行（与 runtime.m 内置表同源——改任一侧必须同步另一侧）。
    /// 4.1.15 全家族 x86_64：撤回解析汇点 wrapper（270099 行 = drive22 实弹
    /// 定案；其余行由 tools/derive_runtime_hooks.py 从官方 DMG 派生（守卫
    /// 位点→FUNCTION_STARTS→parse 入口；arm64 行 = catalog arm64 revoke 位点
    /// 所在函数起点），x64 序言门 554889E54157415641554154、arm64 序言门
    /// F85FBCA9F65701A9F44F02A9FD7B03A9 全过。270090/94/97 六行为 2026-09-19
    /// CDN 归档补齐（同款拓扑 + 序言门，与 ㉒ parse 直挂口径一致）；270084-89
    /// 十行为同日一致性轮发现的家族前段（4.1.15.4-.9，.7 从未发布）——地址表
    /// 达 30 行 = 4.1.15 全家族（除未发布的 270087/270092）× 双架构。
    static let knownHooks: [HookRow] = [
        HookRow(build: "270084", uuid: "94cd7862-7e56-3a22-a4b2-e75c45d2a9b4",
                arch: "x86_64", hook_off: "0x5368c60", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270085", uuid: "5d9c751b-5837-3de0-838b-0f930dbf96ff",
                arch: "x86_64", hook_off: "0x536efd0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270086", uuid: "85cef051-50e4-3811-a66c-1e0082b106e3",
                arch: "x86_64", hook_off: "0x5370000", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270088", uuid: "12960899-15f9-33e6-b425-e942dac51905",
                arch: "x86_64", hook_off: "0x53705f0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270089", uuid: "eb8ca404-c44e-3eff-9cc5-34c3a0fa762b",
                arch: "x86_64", hook_off: "0x5372080", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270090", uuid: "7cb8d056-ca85-3a26-9da5-0b3e45578559",
                arch: "x86_64", hook_off: "0x5374b80", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270091", uuid: "259ae4b6-eca0-3685-8542-6a33807e1d1f",
                arch: "x86_64", hook_off: "0x5376320", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270093", uuid: "2db576af-bb0e-3f47-a769-e522096ab8e3",
                arch: "x86_64", hook_off: "0x5378a10", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270094", uuid: "d245ce13-a7eb-3f6b-98d9-9f820ba32518",
                arch: "x86_64", hook_off: "0x5378bc0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270095", uuid: "4c586e00-1d9d-30dc-bd8f-5df4f1d8bebb",
                arch: "x86_64", hook_off: "0x537d2c0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270096", uuid: "46fe99c2-6fe3-34a5-a7de-6d3560d769e7",
                arch: "x86_64", hook_off: "0x537d2a0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270097", uuid: "c8c1dd52-27bb-39a3-912d-b0909ae3a198",
                arch: "x86_64", hook_off: "0x537d2b0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270098", uuid: "3e57bc84-fe65-31c3-9d4f-c25237932211",
                arch: "x86_64", hook_off: "0x537dad0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270099", uuid: "97e21436-abda-3b79-bec0-ef2653c6b423",
                arch: "x86_64", hook_off: "0x537db40", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270100", uuid: "23350838-734b-3df6-a4ff-93cf2dd8c704",
                arch: "x86_64", hook_off: "0x537dcd0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270084", uuid: "a08e3e78-cc29-3927-9375-883c644d8ff8",
                arch: "arm64", hook_off: "0x4bb380c", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270085", uuid: "f4572074-d11b-3316-969f-3804cfa55f7c",
                arch: "arm64", hook_off: "0x4bb74dc", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270086", uuid: "77c16863-ccaf-31da-af2a-9ed8514939ab",
                arch: "arm64", hook_off: "0x4bba488", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270088", uuid: "851a7d08-fed7-3cb8-86cb-a229d126a903",
                arch: "arm64", hook_off: "0x4bba8e8", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270089", uuid: "72f09a88-cafb-3142-88a6-6c4c88c72d97",
                arch: "arm64", hook_off: "0x4bbae80", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270090", uuid: "79b766ed-31d7-3bf9-a313-08b64d521c1d",
                arch: "arm64", hook_off: "0x4bbe5cc", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270091", uuid: "640c0f43-c42d-3ba4-bee5-e5602a30f699",
                arch: "arm64", hook_off: "0x4bbe7b8", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270093", uuid: "86525cee-eb28-3dd3-af6e-691ea9c62d76",
                arch: "arm64", hook_off: "0x4bc179c", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270094", uuid: "1d482dab-78a6-323e-bf7e-f14e0a0fcf3e",
                arch: "arm64", hook_off: "0x4bc1a18", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270095", uuid: "05646a53-6683-3fb3-acbc-c680e911bda8",
                arch: "arm64", hook_off: "0x4bc44a0", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270096", uuid: "60cd6a16-26f0-33d6-bb3e-41e28b7559fc",
                arch: "arm64", hook_off: "0x4bc4488", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270097", uuid: "ae733a46-fff4-3d0e-9fee-40a510c84197",
                arch: "arm64", hook_off: "0x4bc44b4", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270098", uuid: "6b9c4c1a-e03b-33f3-a1a9-b522bd8462f7",
                arch: "arm64", hook_off: "0x4bc4bac", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270099", uuid: "ed4dcbd2-4896-3a6d-8a70-7d8d88f74b0d",
                arch: "arm64", hook_off: "0x4bc4c20", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270100", uuid: "0b9929bb-e55e-3513-b439-32375760bca2",
                arch: "arm64", hook_off: "0x4bc4d34", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
    ]

    /// 微信的 App Group（与其 entitlements application-groups 同源）。
    /// Group Container 是 CLI（沙盒外）与 runtime dylib（沙盒内）唯一
    /// 双端可读写的数据通道——NSSearchPath 在沙盒内展开到微信容器，
    /// CLI 写的文件 dylib 读不到（2026-09-19 实证）。
    static let appGroupID = "5A4RE8SF68.com.tencent.xinWeChat"

    static func groupContainerURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Group Containers/\(appGroupID)/wxkeep",
                                    isDirectory: true)
    }

    /// runtime.json 现行位置（Group 容器）。
    static func url() -> URL {
        groupContainerURL().appendingPathComponent("runtime.json")
    }

    /// 旧位置（NSSearchPath 语义；dylib 在沙盒内读不到它，仅作迁移源）。
    static func legacyURL() -> URL {
        Config.userDataURL.appendingPathComponent("runtime.json")
    }

    /// plist 优先、JSON 兜底的读取（plist 是落盘格式；JSON 只为历史脏文件）。
    private static func readDict(at url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        if let loaded = (try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil)) as? [String: Any] {
            return loaded
        }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    // MARK: - tip 文案管理（`wxkeep runtime tip`）

    /// 文案配置的当前值（文件缺失 → 全部缺省）。
    static func readTip(at target: URL = url()) -> (text: String?, rewriteSelf: Bool, keepMessage: Bool) {
        guard let dict = readDict(at: target) else { return (nil, false, true) }
        let text = dict["tip_text"] as? String
        let rewriteSelf = dict["rewrite_self"] as? Bool ?? false
        let keepMessage = (dict["keep_message"] as? Bool) ?? true
        return (text?.isEmpty == true ? nil : text, rewriteSelf, keepMessage)
    }

    /// 校验结果：accepted / 带告警的接受 / 拒绝（原因人话化）。
    enum TipValidation {
        case ok
        case acceptedWithNotes([String])
        case rejected(String)
    }

    /// 0.2.0 实机验证的渲染契约（ROADMAP ㉒）：
    /// - 文案必须保持官方骨架 `"<X>" 撤回了一条消息`——渲染层按骨架匹配，
    ///   非规范形态显示为 Unsupported 占位；
    /// - 总长 ≤ 原提示内文（~31B）——超长 hook 逐次放弃保原文；
    /// - `<>&` 会被 dylib 剥除（XML 文本节点安全）——这里提前剥并告知；
    /// - `{from}` 占位符展开为撤回者昵称，实际长度随昵称变化，超长逐次放弃。
    static let skeletonSuffix = "\" 撤回了一条消息"

    static func validateTip(_ raw: String) -> (normalized: String, verdict: TipValidation) {
        var notes: [String] = []
        // 与 dylib apply_config_dict 同语义：剥除（非替换）会破坏 XML 的字符
        var stripped = ""
        for ch in raw {
            guard ch == "<" || ch == ">" || ch == "&" else { stripped.append(ch); continue }
            notes.append("已剥除会破坏 XML 的字符「\(ch)」（dylib 侧同规则）")
        }
        let data = stripped.data(using: .utf8) ?? Data()
        // 骨架 = `"` + 非空内文（不含引号）+ `" 撤回了一条消息`，到尾无多余字符
        guard stripped.hasPrefix("\""),
              let close = stripped.dropFirst().firstIndex(of: "\""),
              close > stripped.index(after: stripped.startIndex),
              String(stripped[close...]) == skeletonSuffix
        else {
            return (stripped, .rejected(
                "文案必须保持官方骨架 \"<X>\" 撤回了一条消息（渲染层按骨架匹配显示，"
                + "非规范形态会显示为 Unsupported 占位）。推荐：\"⚠️\" 撤回了一条消息"))
        }
        guard !data.isEmpty else {
            return (stripped, .rejected("文案为空"))
        }
        // 长度门按「展开后等效」评估：{from} 占位符 6B 会被昵称替换，模板
        // 原始字节数不能直接比对——静态等效部分超限才是真装不下。
        let phCount = stripped.components(separatedBy: "{from}").count - 1
        let staticEquivalent = data.count - phCount * 6
        if staticEquivalent > 31 || (phCount == 0 && data.count > 31) {
            return (stripped, .rejected(
                "文案展开后约 \(max(data.count, staticEquivalent))B，超过原提示内文长度（~31B）——"
                + "hook 会逐次放弃改写保原文。推荐 30B 实证形态：\"⚠️\" 撤回了一条消息，"
                + "或恒等长的 \"{from}\" 撤回了一条消息"))
        }
        // 纯 {from} 形态在数学上恒等长：骨架 = `"`+昵称+`"`+空格+7 字短语，
        // 展开后与原内文逐字节同构（昵称可解析时）——最稳形态。
        if stripped == "\"{from}\" 撤回了一条消息" {
            return (stripped, .ok)
        }
        if phCount > 0 {
            notes.append("{from} 展开为撤回者昵称：展开后长度 = 静态部分 + 昵称长度，"
                + "超过原内文时该次放弃保原文（安全方向）")
        } else if data.count > 30 {
            notes.append("31B 比实证形态（30B）长：撤回者昵称较短时原内文可能更短，该次放弃保原文")
        }
        return (stripped, notes.isEmpty ? .ok : .acceptedWithNotes(notes))
    }

    /// 写 tip_text / rewrite_self（保留 hooks 与其余键，原子写，plist 格式——
    /// 与 mergeKnownHooks 同一格式契约）。text 为 nil = 不动文案；微信运行中
    /// 也可写：dylib 仅启动时读，下次启动生效。
    static func writeTip(text: String?, rewriteSelf: Bool?, at target: URL = url()) throws {
        var dict: [String: Any] = readDict(at: target) ?? [:]
        if let text { dict["tip_text"] = text }
        if let rewriteSelf { dict["rewrite_self"] = rewriteSelf }
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let out = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try out.write(to: target, options: .atomic)
    }

    /// 移除 tip_text（hook 仍武装：keep_message 通用 keeptip 不受影响）。
    static func removeTip(at target: URL = url()) throws {
        var dict: [String: Any] = readDict(at: target) ?? [:]
        dict.removeValue(forKey: "tip_text")
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let out = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try out.write(to: target, options: .atomic)
    }

    /// 把 knownHooks 合并进 runtime.json 的 "hooks" 数组：按 uuid 去重替换，
    /// 未知 uuid 的既有行保留（update-data 下发的新构建行不会被旧工具回退），
    /// 其余键（tip_text / rewrite_self / 用户自己的行）原样保留。
    /// 文件不存在则创建（目录一并建）；Group 容器无文件而旧位置有时，
    /// 旧文件内容作为迁移种子并入。
    ///
    /// 格式契约：**XML property list**，不是 JSON——dylib 侧用
    /// `NSDictionary dictionaryWithContentsOfFile`（plist 语义）读取，
    /// JSON 文件会整体解析失败并静默回落内置表（tip_text 一起丢）。
    /// 本函数读写都走 PropertyListSerialization；JSON 仅作为历史脏文件的
    /// 只读迁移入口。
    @discardableResult
    static func mergeKnownHooks(into target: URL) throws -> [HookRow] {
        var dict: [String: Any] = [:]
        if FileManager.default.fileExists(atPath: target.path) {
            dict = Self.readDict(at: target) ?? [:]
        } else if target != legacyURL(),
                  FileManager.default.fileExists(atPath: legacyURL().path),
                  let legacy = Self.readDict(at: legacyURL()) {
            dict = legacy   // 迁移种子：旧位置的 tip/rewrite_self/自定义行并入新文件
        }

        var rows: [[String: Any]] = (dict["hooks"] as? [[String: Any]]) ?? []
        let knownUUIDs = Set(knownHooks.map(\.uuid))
        rows.removeAll { ($0["uuid"] as? String).map(knownUUIDs.contains) ?? false }
        let encoder = JSONEncoder()
        for hook in knownHooks {
            let data = try encoder.encode(hook)
            rows.append(try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:])
        }
        dict["hooks"] = rows

        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let out = try PropertyListSerialization.data(
            fromPropertyList: dict, format: .xml, options: 0)
        // 原子写：微信启动瞬间撞上写入会读到半文件并静默回落内置表
        try out.write(to: target, options: .atomic)
        return rows.map { row in
            // 合并产物回读为 HookRow 只为计数/展示；不合法的自定义行会被
            // dylib 丢弃（宁可不挂也不挂错），这里不因此失败。
            (try? JSONDecoder().decode(HookRow.self, from: JSONSerialization.data(withJSONObject: row)))
                ?? HookRow(build: (row["build"] as? String) ?? "?",
                           uuid: (row["uuid"] as? String) ?? "?",
                           arch: (row["arch"] as? String) ?? "x86_64",
                           hook_off: (row["hook_off"] as? String) ?? "0",
                           msg_arg: (row["msg_arg"] as? Int) ?? 1,
                           xml_sso_off: (row["xml_sso_off"] as? Int) ?? 0,
                           expected: (row["expected"] as? String) ?? "")
        }
    }
}
