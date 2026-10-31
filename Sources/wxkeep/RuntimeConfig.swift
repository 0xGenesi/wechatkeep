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
        /// 函数级身份门①（可选，77 续）：目标函数起点到 LC_FUNCTION_STARTS
        /// 下一函数起点的距离（派生期布局指纹）。旧行不带 → 门不启用
        /// （向后兼容）；带则 dylib 安装期与镜像元数据比对，不符拒装——
        /// 序言门对「同序言不同函数」无分辨力（10-03 自更新实证）。
        var func_size: Int? = nil
        /// 函数级身份门②（可选）：锚点在切片内的 VM 偏移（与 hook_off 同基准，
        /// 0x 前缀 hex）。与 anchor_bytes 成对出现，缺一整行拒绝。
        var anchor_va: String? = nil
        /// 锚点期望字节 hex（≤64B；建议取目标函数体内 distinctive 指令序列
        /// 或其引用的常量——重编译几乎必动的位置）。
        var anchor_bytes: String? = nil

        /// 显式 CodingKeys：case 名与属性一致（本结构属性已是 snake_case，
        /// 恰为 dylib 侧 wire 键），列出即把 wire 键名钉死——未来新增字段
        /// 若忘登记，Decodable 合成直接编译失败（防御位而非装饰；68 轮
        /// verify_variants「合成键漂移静默失效」同坑的编译期解）。
        private enum CodingKeys: String, CodingKey {
            case build, uuid, arch, hook_off, msg_arg, xml_sso_off, expected
            case func_size, anchor_va, anchor_bytes
        }
    }

    /// 编译期已知行（与 runtime.m 内置表同源——改任一侧必须同步另一侧）。
    /// 4.1.15 全家族 x86_64：hook 点 = **parse 入口直挂**（㉒ 实弹定案：
    /// rsi = sysmsg XML 裸 SSO；wrapper+0x130 静态推定已被真实撤回证伪）。
    /// 行由 tools/derive_runtime_hooks.py 从官方 DMG 派生（守卫
    /// 位点→FUNCTION_STARTS→parse 入口；arm64 行 = catalog arm64 revoke 位点
    /// 所在函数起点），x64 序言门 554889E54157415641554154、arm64 序言门
    /// F85FBCA9F65701A9F44F02A9FD7B03A9 全过。270090/94/97 六行为 2026-09-19
    /// CDN 归档补齐（同款拓扑 + 序言门，与 ㉒ parse 直挂口径一致）；270084-89
    /// 十行为同日一致性轮发现的家族前段（4.1.15.4-.9，.7 从未发布）；270101/
    /// 102 于 2026-10-20 补齐、270131-135 于 10-14/10-17 派生——地址表达
    /// 44 行 = 4.1.15 全家族（除从未发布的 270087/270092）+ 270131-135
    /// × 双架构（22 构建 × 2）。
    ///
    /// funcSize 覆盖率（77 续②补 16 行、⑫ zsbai 回填 6 行，2026-10-26/27）：
    /// 11 构建 × 双架构 = 22 行已带函数级身份门字段（270094/097/099——
    /// zsbai 三件 dmg 切片；270100/101/102/131-135——本地 pristine 切片在
    /// var/ab + var/wxarm）。派生经三重校验（hook_off 必为
    /// LC_FUNCTION_STARTS 起点、切片 LC_UUID 与行全同、距离 = 到下一函数
    /// 起点），家族值恒定 x64=5216 / arm64=4380（parse 家族函数跨构建尺寸
    /// 稳定的旁证）。余 11 构建（270084-093/095-096/098）为**永久缺口**：
    /// 官方 CDN 直链全量 404（77 续⑫ probe 定案）、zsbai 仅 .14/.17/.19/.20
    /// 在档——不带 funcSize = 门未启用，行为同 77 轮前（向后兼容设计）。
    /// 已知实害案例：270100 arm64 行对 10-03 自更新世代
    /// 失效且有害（同 UUID 新字节「同序言不同函数」）——funcSize 门使该
    /// 场景从「破坏消息渲染」降级为「拒装 + kStFuncMismatch 可诊断」。
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
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270095", uuid: "4c586e00-1d9d-30dc-bd8f-5df4f1d8bebb",
                arch: "x86_64", hook_off: "0x537d2c0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270096", uuid: "46fe99c2-6fe3-34a5-a7de-6d3560d769e7",
                arch: "x86_64", hook_off: "0x537d2a0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270097", uuid: "c8c1dd52-27bb-39a3-912d-b0909ae3a198",
                arch: "x86_64", hook_off: "0x537d2b0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270098", uuid: "3e57bc84-fe65-31c3-9d4f-c25237932211",
                arch: "x86_64", hook_off: "0x537dad0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154"),
        HookRow(build: "270099", uuid: "97e21436-abda-3b79-bec0-ef2653c6b423",
                arch: "x86_64", hook_off: "0x537db40", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270100", uuid: "23350838-734b-3df6-a4ff-93cf2dd8c704",
                arch: "x86_64", hook_off: "0x537dcd0", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        // 270101/270102（4.1.15.21/.22，2026-10-20 补齐轮）：此前「无 dmg
        // 工件可派生」是 stale 结论——当日定点复核 CDN 两构建均在档（206；
        // 9-21 的「.21-.25 全 404」探测记录有误或其后上档）。x64 行照常
        // guard→parse 派生，序言门全过。
        HookRow(build: "270101", uuid: "b66498da-99d2-35de-b32a-3c757c7e1abd",
                arch: "x86_64", hook_off: "0x537de80", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270102", uuid: "0d57fc3a-ed9c-3266-a1a8-cdf77b732c0f",
                arch: "x86_64", hook_off: "0x537e070", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        // 270131/270132（4.1.15.51/.52，2026-10-17 CDN 缺口补齐轮）：zsbai 漏
        // 归档、watch CI 因此从未发现的构建——官方 CDN 构建归档直链按线性
        // 探测（4.1.15.23-.50 全 404，.51/.52 在档）补入。派生与序言门同
        // 270133-135 口径：x64 = parse-guard → FUNCTION_STARTS parse 入口；
        // arm64 = revoke 位点所在函数起点 + 切片 LC_UUID。
        HookRow(build: "270131", uuid: "255452e3-73fa-3682-8d06-6be7fe42352b",
                arch: "x86_64", hook_off: "0x54f7160", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270132", uuid: "281a9644-2629-34cb-82ee-8e58dc5eb5e7",
                arch: "x86_64", hook_off: "0x54f9340", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        // 270133-270135（4.1.15.53-.55，2026-10-14 派生轮）：x64 行 =
        // locate_x64_parse_guard → derive_runtime_hooks（序言门全过）；
        // arm64 行 = revoke 位点所在函数起点（LC_FUNCTION_STARTS）+ 切片
        // LC_UUID + 家族序言门。
        HookRow(build: "270133", uuid: "9a1ef201-c390-3412-a286-e629482602b2",
                arch: "x86_64", hook_off: "0x54f9c10", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270134", uuid: "c32fa6ee-bc41-399d-ae83-ee81512d7b57",
                arch: "x86_64", hook_off: "0x5502500", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
        HookRow(build: "270135", uuid: "661e436d-ae61-3413-a867-841f042ddc12",
                arch: "x86_64", hook_off: "0x5503730", msg_arg: 1, xml_sso_off: 0,
                expected: "554889E54157415641554154", func_size: 5216),
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
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270095", uuid: "05646a53-6683-3fb3-acbc-c680e911bda8",
                arch: "arm64", hook_off: "0x4bc44a0", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270096", uuid: "60cd6a16-26f0-33d6-bb3e-41e28b7559fc",
                arch: "arm64", hook_off: "0x4bc4488", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270097", uuid: "ae733a46-fff4-3d0e-9fee-40a510c84197",
                arch: "arm64", hook_off: "0x4bc44b4", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270098", uuid: "6b9c4c1a-e03b-33f3-a1a9-b522bd8462f7",
                arch: "arm64", hook_off: "0x4bc4bac", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9"),
        HookRow(build: "270099", uuid: "ed4dcbd2-4896-3a6d-8a70-7d8d88f74b0d",
                arch: "arm64", hook_off: "0x4bc4c20", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270100", uuid: "0b9929bb-e55e-3513-b439-32375760bca2",
                arch: "arm64", hook_off: "0x4bc4d34", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        // 270101/270102 arm64：函数起点 16B 序言门全过。270102 起点
        // 0x4bc5168 与 fzlzjerry 09-30 公布的 runtime-tip 解析器入口逐位
        // 一致（独立逆向互证；其 270100 入口 0x4bc4d34 亦与我们旧行同值）。
        HookRow(build: "270101", uuid: "d0729a8f-19af-3b62-b1c2-dd99ba580b83",
                arch: "arm64", hook_off: "0x4bc4f68", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270102", uuid: "3b7b6abb-2c36-3e58-a384-cdef05a57aa5",
                arch: "arm64", hook_off: "0x4bc5168", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270131", uuid: "825a26b5-c211-31d6-9e6f-9295865ae5c9",
                arch: "arm64", hook_off: "0x4d12b50", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270132", uuid: "15884091-e6a6-34a4-afe0-36c207a1a58b",
                arch: "arm64", hook_off: "0x4d16ce8", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270133", uuid: "ea1a57e3-4599-3365-9dc3-c69375798d73",
                arch: "arm64", hook_off: "0x4d15438", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270134", uuid: "8acf7a2f-517c-32b4-9dfb-47e8849cd444",
                arch: "arm64", hook_off: "0x4d1c880", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
        HookRow(build: "270135", uuid: "0c2f01c0-c197-3286-901d-70e1d007a1c0",
                arch: "arm64", hook_off: "0x4d1f8d8", msg_arg: 1, xml_sso_off: 0,
                expected: "F85FBCA9F65701A9F44F02A9FD7B03A9", func_size: 4380),
    ]

    /// 微信的 App Group（与其 entitlements application-groups 同源）。
    /// Group Container 是 CLI（沙盒外）与 runtime dylib（沙盒内）唯一
    /// 双端可读写的数据通道——NSSearchPath 在沙盒内展开到微信容器，
    /// CLI 写的文件 dylib 读不到（2026-09-19 实证）。
    static let appGroupID = "5A4RE8SF68.com.tencent.xinWeChat"

    /// 微信沙盒容器的 bundle id（appGroupID 去团队前缀；与 appGroupID 同为
    /// 稳定常量的既有先例）。marker 读/清侧用它推容器 legacy 路径。
    static let wechatContainerBundleID = "com.tencent.xinWeChat"

    static func groupContainerURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Group Containers/\(appGroupID)/wxkeep",
                                    isDirectory: true)
    }

    /// runtime marker 的候选路径（读/写/清三侧共用，77 续对偶修复）。
    /// 序 = dylib write_marker_ex 的写序（首个可写者胜）：
    /// 1. Group 容器（正常装机双端可达的正位）
    /// 2. 微信沙盒容器的 legacy Application Support——沙盒微信 Group 写
    ///    被拒（containermanagerd 拒 ad-hoc 无 team）时 dylib 的回落位；
    ///    容器路径对同用户 CLI 可读，不是盲区
    /// 3. 真实 home 的 Application Support（非沙盒宿主的 legacy 位）
    static var markerURLs: [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            groupContainerURL().appendingPathComponent("runtime.marker"),
            home.appendingPathComponent(
                "Library/Containers/\(wechatContainerBundleID)/Data/Library/Application Support/wxkeep/runtime.marker"),
            home.appendingPathComponent(
                "Library/Application Support/wxkeep/runtime.marker"),
        ]
    }

    /// 首个存在的 marker 文本（候选序探查；全都缺失返回 nil）。
    static func readMarkerText(at candidates: [URL] = markerURLs) -> String? {
        for url in candidates {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                return text
            }
        }
        return nil
    }

    /// 清掉全部候选位的 marker（install/remove 的「新装周期从无记录起算」
    /// 用——只清 Group 会漏掉沙盒回落位的过期证据）。
    static func removeAllMarkers(at candidates: [URL] = markerURLs) {
        for url in candidates {
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// runtime.json 现行位置（Group 容器）。
    static func url() -> URL {
        groupContainerURL().appendingPathComponent("runtime.json")
    }

    /// 微信沙盒容器内的 runtime.json——**ad-hoc 重签宿主进程内 Group 读写
    /// 被 containermanagerd 拒（无 team）时 dylib 的真读位**（98 轮实弹
    /// cfgdiag 实证；与 markerURLs 的沙盒回落位同机理同路径）。
    static func wechatContainerConfigURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(
                "Library/Containers/\(wechatContainerBundleID)/Data/Library/Application Support/wxkeep/runtime.json")
    }

    /// 配置写目标（双份）：Group（CLI 正位）+ 微信沙盒容器（进程真读位，
    /// 同内容双写保证「进程读哪份哪份就对」——dylib 读首个可读者，两份
    /// 内容一致后选径不再影响语义）。
    static var configWriteTargets: [URL] {
        [url(), wechatContainerConfigURL()]
    }

    /// 配置读候选序 = dylib read_runtime_config 的回落序（Group → 容器 AS
    /// → 真 home legacy）；首个存在者 = 进程有效配置。
    static var configReadCandidates: [URL] {
        [url(), wechatContainerConfigURL(), legacyURL()]
    }

    /// 进程有效配置字典（叠加视图：legacy < Group < 容器 AS 逐键覆盖；
    /// 全缺失返回 nil）。首个存在者选法在 ad-hoc 装机会选中陈旧 Group
    /// （98 轮实测：显示 keep=off 而进程真跑容器的 keep=on——误报防护
    /// 状态）；叠加方向与 mergedWriteBase 同原则：容器=在役真值。
    static func effectiveConfigDict() -> [String: Any]? {
        let merged = mergedWriteBase(from: [legacyURL(), url(), wechatContainerConfigURL()])
        return merged.isEmpty ? nil : merged
    }

    /// 旧位置（NSSearchPath 语义；dylib 在沙盒内读不到它，仅作迁移源）。
    static func legacyURL() -> URL {
        Config.userDataURL.appendingPathComponent("runtime.json")
    }

    /// 当前生效配置文件的内容指纹（FNV-1a 64，与 runtime.m 的
    /// config_content_hash 同算法同选径：group → 容器 AS → legacy 回落）。
    /// `runtime status` 用它与 marker 的 cfgh= 对比做漂移告警（V4 需求 3）。
    /// 文件不可读返回 nil。at 参数供测试注入（缺省走真实选径）。
    static func currentConfigContentHash(at candidates: [URL]? = nil) -> UInt64? {
        configContentHashes(at: candidates).first?.hash
    }

    /// 逐候选实算指纹（98 轮：双文件语境下 marker 指纹可能对上任何一份——
    /// 进程 group 读被拒时读的是容器 AS，与 CLI 优先的 Group 不是同一份；
    /// status 的漂移告警按「任一候选匹配」判，不再拿首份单挑）。
    static func configContentHashes(at candidates: [URL]? = nil)
        -> [(url: URL, hash: UInt64)] {
        var out: [(URL, UInt64)] = []
        for u in candidates ?? configReadCandidates {
            guard let data = try? Data(contentsOf: u) else { continue }
            var h: UInt64 = 1_469_598_103_934_665_603
            for b in data {
                h ^= UInt64(b)
                h = h &* 1_099_511_628_211
            }
            out.append((u, h))
        }
        return out
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

    /// 文案配置的当前值（候选序首个存在者；全缺失 → 全部缺省）。
    /// candidates 供测试注入（缺省 = 真实选径）。
    static func readTip(at candidates: [URL]? = nil) -> (text: String?, rewriteSelf: Bool, keepMessage: Bool) {
        let dict: [String: Any]? = candidates.map { cs in
            cs.lazy.compactMap { readDict(at: $0) }.first
        } ?? effectiveConfigDict()
        guard let dict else { return (nil, false, true) }
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

    /// 双写基座：Group 与容器 AS 都在时按「容器 AS 优先」逐键叠加（分歧键
    /// 以容器值为准）。方向性理由：ad-hoc 装机（主流形态）进程内只读得到
    /// 容器，容器键=在役真值；反向叠加会让陈旧 Group 键（如 keep=false）
    /// 静默覆盖在役防护——灾难方向。容器缺失的机器（Group 可读的 team 签
    /// 装机）退化为纯 Group 基座，语义同旧版。from 供测试注入（[] = 全隔离）。
    static func mergedWriteBase(from candidates: [URL]? = nil) -> [String: Any] {
        var dict: [String: Any] = [:]
        for u in candidates ?? [url(), wechatContainerConfigURL()] {
            if let d = readDict(at: u) { for (k, v) in d { dict[k] = v } }
        }
        return dict
    }

    /// 写 tip_text / rewrite_self（双目标写，见 configWriteTargets；基座=
    /// mergedWriteBase——进程有效真源向两份副本收敛）。保留 hooks 与其余
    /// 键，原子写，plist 格式——与 mergeKnownHooks 同一格式契约。text 为
    /// nil = 不动文案；微信运行中也可写：30s 热重载生效。返回实写成功的
    /// 目标；全部失败抛末次错误。
    @discardableResult
    static func writeTip(text: String?, rewriteSelf: Bool?,
                         at targets: [URL] = configWriteTargets,
                         base candidates: [URL]? = nil) throws -> [URL] {
        var dict = mergedWriteBase(from: candidates ?? targets)
        if let text { dict["tip_text"] = text }
        if let rewriteSelf { dict["rewrite_self"] = rewriteSelf }
        return try writePlist(dict, to: targets)
    }

    /// 移除 tip_text（hook 仍武装：keep_message 通用 keeptip 不受影响）。
    /// 双目标写同 writeTip。
    @discardableResult
    static func removeTip(at targets: [URL] = configWriteTargets,
                          base candidates: [URL]? = nil) throws -> [URL] {
        var dict = mergedWriteBase(from: candidates ?? targets)
        dict.removeValue(forKey: "tip_text")
        return try writePlist(dict, to: targets)
    }

    /// plist 原子写多目标；至少一份成功即返回成功清单，全败抛末次错误。
    private static func writePlist(_ dict: [String: Any], to targets: [URL]) throws -> [URL] {
        let out = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        var written: [URL] = []
        var lastError: Error?
        for target in targets {
            do {
                try FileManager.default.createDirectory(
                    at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
                try out.write(to: target, options: .atomic)
                written.append(target)
            } catch { lastError = error }
        }
        if written.isEmpty, let lastError { throw lastError }
        return written
    }

    /// 把 knownHooks 合并进 runtime.json 的 "hooks" 数组：按 uuid 去重替换，
    /// 未知 uuid 的既有行保留（update-data 下发的新构建行不会被旧工具回退），
    /// 其余键（tip_text / rewrite_self / 用户自己的行）原样保留。
    /// 双目标写（configWriteTargets：Group + 微信沙盒容器——98 轮：ad-hoc
    /// 装机进程内只读得到容器份，hooks 地址表的 day-0 数据通道必须达它）；
    /// 基座 = mergedWriteBase（容器优先逐键叠加）；两目标全无文件而旧位置
    /// 有时，旧文件内容作为迁移种子并入。
    ///
    /// 格式契约：**XML property list**，不是 JSON——dylib 侧用
    /// `NSDictionary dictionaryWithContentsOfFile`（plist 语义）读取，
    /// JSON 文件会整体解析失败并静默回落内置表（tip_text 一起丢）。
    /// 本函数读写都走 PropertyListSerialization；JSON 仅作为历史脏文件的
    /// 只读迁移入口。
    @discardableResult
    static func mergeKnownHooks(into targets: [URL] = configWriteTargets,
                                base candidates: [URL]? = nil) throws -> [HookRow] {
        // 基座缺省 = 写目标自身（容器优先叠加）——保留目标文件里的用户键
        // （旧语义）；显式 base（含 []）供测试注入/隔离。
        var dict = mergedWriteBase(from: candidates ?? targets)
        if dict.isEmpty,
           candidates == nil,
           !targets.contains(legacyURL()),
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

        _ = try writePlist(dict, to: targets)
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
                           expected: (row["expected"] as? String) ?? "",
                           func_size: row["func_size"] as? Int,
                           anchor_va: row["anchor_va"] as? String,
                           anchor_bytes: row["anchor_bytes"] as? String)
        }
    }
}
