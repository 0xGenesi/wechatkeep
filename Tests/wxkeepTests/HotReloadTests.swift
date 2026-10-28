import Testing
import Foundation
@testable import wxkeep
@testable import WxkeepRuntime

/// 77 续㉘：配置热重载（策略键 ≤30s 生效、hooks 表绝不动）与自发撤回
/// 判别门（T5 F1 修复）的契约测试。
struct HotReloadTests {

    private func tmpPlist() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-hotreload-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("runtime.json")
    }

    private func hookRowDict() -> [String: Any] {
        ["build": "270099", "uuid": "97e21436-abda-3b79-bec0-ef2653c6b423",
         "arch": "x86_64", "hook_off": "0x537db40", "msg_arg": 1,
         "xml_sso_off": 0, "expected": "554889E54157415641554154"]
    }

    private func writePlist(_ url: URL, _ dict: [String: Any]) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: url)
    }

    /// 热重载契约：策略键换新、hooks 表行数不动（换表仍需重启进程）。
    @Test func hotReloadSwapsTipWithoutTouchingHooks() throws {
        let url = tmpPlist()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try writePlist(url, ["tip_text": "AAAA", "hooks": [hookRowDict()], "keep_message": true])
        let loaded = url.path.withCString { wxkeep_runtime_test_load_config_file($0) }
        #expect(loaded == 1, "初始装载应接受 1 行 hooks")
        #expect(wxkeep_runtime_test_tip_len() == 4)

        try writePlist(url, ["tip_text": "BBBBBBBBBBBB", "hooks": [hookRowDict(), hookRowDict()],
                            "keep_message": false])
        let r = url.path.withCString { wxkeep_runtime_test_reload_config($0) }
        #expect(r == 0, "热重载成功且 hooks 未被触碰（got \(r)）")
        #expect(wxkeep_runtime_test_tip_len() == 12, "tip 热生效")
        #expect(wxkeep_runtime_test_ext_hooks_count() == 1, "hooks 表不受热重载影响")
    }

    /// 热重载对坏文件的契约：不可解析返回 -1（先立戳语义由生产路径承担）。
    @Test func hotReloadRejectsUnparseableFile() throws {
        let url = tmpPlist()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        try Data("not a plist".utf8).write(to: url)
        let r = url.path.withCString { wxkeep_runtime_test_reload_config($0) }
        #expect(r == -1)
    }

    /// 自发撤回判别门（T5 F1）：自发 XML（内文「你撤回…」）→ 0（放行原生）；
    /// 他人 XML（实弹捕获形态，含群/私）→ 1（走 keep/zero 门）。
    @Test func keepGateSkipsSelfRevokeOnly() {
        let others = ["\"Jennifer\" 撤回了一条消息",          // 群聊 replacemsg 内文（d34 捕获）
                      "张三 撤回了一条消息"]                    // 无引号变体
        for text in others {
            let bytes = Array(text.utf8)
            let gate = bytes.withUnsafeBufferPointer {
                wxkeep_runtime_test_keep_gate($0.baseAddress, UInt(bytes.count))
            }
            #expect(gate == 1, "他人撤回应过门: \(text)")
        }
        for text in ["你撤回了一条消息", "你撤回了一条群公告"] {
            let bytes = Array(text.utf8)
            let gate = bytes.withUnsafeBufferPointer {
                wxkeep_runtime_test_keep_gate($0.baseAddress, UInt(bytes.count))
            }
            #expect(gate == 0, "自发撤回应放行原生行为: \(text)")
        }
    }

    /// 16 条实弹捕获全量回归：他人捕获全过门（判别器对真实负载零误伤）。
    @Test func keepGateAgainstAllLiveCaptures() throws {
        let urls = try FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: "var/wxarm"), includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("d") && $0.pathExtension == "xml" }
        if urls.isEmpty {
            print("ℹ︎ 实弹捕获不在场（CI 环境）——本用例空过")
            return
        }
        for url in urls {
            let data = try Data(contentsOf: url)
            let raw = String(data: data, encoding: .utf8) ?? ""
            let isSelf = raw.contains("你撤回")   // d29/d32 部分捕获=自发撤回采样
            let gate = data.withUnsafeBytes {
                wxkeep_runtime_test_keep_gate($0.baseAddress, UInt(data.count))
            }
            #expect(gate == (isSelf ? 0 : 1),
                    "判别器应与捕获形态一致: \(url.lastPathComponent) self=\(isSelf)")
        }
    }
}
