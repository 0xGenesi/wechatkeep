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
    /// 定案；其余行由 tools/derive_runtime_hooks.py 从官方 DMG 派生——
    /// 守卫位点→FUNCTION_STARTS→parse 唯一调用者→wrapper，序言门
    /// 554889E54157415641554154 全过，270099 行与实弹结果互证）。
    /// ⚠️ wrapper+0x130 偏移为家族同构推定（270099 实测），实机 hook 未生效
    /// 时按 RUNTIME-DESIGN 切 parse 入口方案（rsi 直挂）。
    static let knownHooks: [HookRow] = [
        HookRow(build: "270091", uuid: "259ae4b6-eca0-3685-8542-6a33807e1d1f",
                arch: "x86_64", hook_off: "0x53760f0", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270093", uuid: "2db576af-bb0e-3f47-a769-e522096ab8e3",
                arch: "x86_64", hook_off: "0x53787e0", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270095", uuid: "4c586e00-1d9d-30dc-bd8f-5df4f1d8bebb",
                arch: "x86_64", hook_off: "0x537d090", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270096", uuid: "46fe99c2-6fe3-34a5-a7de-6d3560d769e7",
                arch: "x86_64", hook_off: "0x537d070", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270098", uuid: "3e57bc84-fe65-31c3-9d4f-c25237932211",
                arch: "x86_64", hook_off: "0x537d8a0", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270099", uuid: "97e21436-abda-3b79-bec0-ef2653c6b423",
                arch: "x86_64", hook_off: "0x537d910", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        HookRow(build: "270100", uuid: "23350838-734b-3df6-a4ff-93cf2dd8c704",
                arch: "x86_64", hook_off: "0x537daa0", msg_arg: 1, xml_sso_off: 0x130,
                expected: "554889E54157415641554154"),
        // arm64 行：同款拓扑派生（gen3 cbz 位点→FUNCTION_STARTS→唯一 BL 调用者），
        // 序言 = sub sp,#0x80 + stp×3（无 PC 相对，全部构建逐字节相同——
        // 家族信号）。msg_arg=1（x1）/+0x130 偏移为跨架构同构推定，同受
        // expected 门与运行时 needle/tag 门保护。
        HookRow(build: "270091", uuid: "640c0f43-c42d-3ba4-bee5-e5602a30f699",
                arch: "arm64", hook_off: "0x4bbe5a4", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270093", uuid: "86525cee-eb28-3dd3-af6e-691ea9c62d76",
                arch: "arm64", hook_off: "0x4bc1588", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270095", uuid: "05646a53-6683-3fb3-acbc-c680e911bda8",
                arch: "arm64", hook_off: "0x4bc428c", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270096", uuid: "60cd6a16-26f0-33d6-bb3e-41e28b7559fc",
                arch: "arm64", hook_off: "0x4bc4274", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270098", uuid: "6b9c4c1a-e03b-33f3-a1a9-b522bd8462f7",
                arch: "arm64", hook_off: "0x4bc4998", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270099", uuid: "ed4dcbd2-4896-3a6d-8a70-7d8d88f74b0d",
                arch: "arm64", hook_off: "0x4bc4a0c", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
        HookRow(build: "270100", uuid: "0b9929bb-e55e-3513-b439-32375760bca2",
                arch: "arm64", hook_off: "0x4bc4b20", msg_arg: 1, xml_sso_off: 0x130,
                expected: "FF0302D1FC6F02A9FA6703A9F85F04A9"),
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
