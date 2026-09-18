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
        let rows = try RuntimeConfig.mergeKnownHooks(into: url)
        #expect(rows.count == RuntimeConfig.knownHooks.count)
        #expect(rows.contains { $0.build == "270099" && $0.hook_off == "0x537d910" })

        // 落盘形态：hooks 在场且可回读（含 270099 实流行）
        let dict = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), options: [], format: nil) as? [String: Any]
        let hooks = dict?["hooks"] as? [[String: Any]]
        #expect(hooks?.count == RuntimeConfig.knownHooks.count)
        #expect(hooks?.contains { ($0["uuid"] as? String) == "97e21436-abda-3b79-bec0-ef2653c6b423" } == true)
        #expect(hooks?.contains { ($0["hook_off"] as? String) == "0x537d910" } == true)
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

        let rows = try RuntimeConfig.mergeKnownHooks(into: url)
        // 旧 270099 行被替换为 knownHooks 版本（全表重写），future 行保留
        #expect(rows.count == RuntimeConfig.knownHooks.count + 1)
        #expect(rows.first { $0.build == "270099" }?.hook_off == "0x537d910")
        #expect(rows.contains { $0.uuid == future.uuid && $0.hook_off == future.hook_off })

        // 用户键透传
        let back = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), options: [], format: nil) as? [String: Any]
        #expect(back?["tip_text"] as? String == "我的文案")
        #expect(back?["rewrite_self"] as? Bool == true)
    }

    @Test func mergeIsIdempotent() throws {
        let url = tmpConfigPath()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        _ = try RuntimeConfig.mergeKnownHooks(into: url)
        let first = try Data(contentsOf: url)
        _ = try RuntimeConfig.mergeKnownHooks(into: url)
        #expect(try Data(contentsOf: url) == first)
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

        _ = try RuntimeConfig.mergeKnownHooks(into: url)

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
