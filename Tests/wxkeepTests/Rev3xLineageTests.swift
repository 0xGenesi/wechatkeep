import Testing
import Foundation
@testable import wxkeep

/// 3.x（主程序/ObjC 时代）谱系契约（83 轮派生，2026-10-30）：
/// 16 构建 × revoke/revoke-keeptip × 双架构，binary=Contents/MacOS/WeChat。
/// 入口选择子四代改名谱系钉死在 source 字段里——目录若被误删/误改（merge
/// 事故、上游覆盖）在此翻红。3.8.3 无 tag = 线内天然缺口，不在表内。
struct Rev3xLineageTests {
    /// 构建 → 入口选择子（世代表与 tools/derive_revoke_3x.py BUILDS 同源）
    static let lineage: [String: String] = [
        "23440": "FFToNameFavChatZZ:sessionMsgList:",   // 3.5.5
        "24160": "FFToNameFavChatZZ:sessionMsgList:",   // 3.6.0
        "24205": "FFToNameFavChatZZ:sessionMsgList:",   // 3.6.1
        "24456": "FFToNameFavChatZZ:sessionMsgList:",   // 3.6.2
        "25067": "FFToNameFavChatZZ:sessionMsgList:",   // 3.7.0
        "25668": "FFToNameFavChatZZ:sessionMsgList:",   // 3.7.1
        "26239": "processNewXMLMsg:sessionMsgList:",    // 3.8.0
        "26638": "onRevokeRoomHistory:",                // 3.8.1（撤回+房间历史合并体）
        "27289": "onRevokeRoomHistory:",                // 3.8.2
        "27725": "onSecMsg:syncMsgList:",               // 3.8.4
        "27885": "onSecMsg:syncMsgList:",               // 3.8.5
        "28076": "onSecMsg:syncMsgList:",               // 3.8.6
        "28245": "onSecMsg:syncMsgList:",               // 3.8.7
        "28486": "onSecMsg:syncMsgList:",               // 3.8.8.18
        "28564": "onSecMsg:syncMsgList:",               // 3.8.9.17
        "28632": "onSecMsg:syncMsgList:",               // 3.8.10.17
    ]
    static let executorSelector = "DelRevokedMsg:msgData:"
    static let hostClass = "FFProcessReqsvrZZ"

    private func loadConfig() throws -> Config {
        let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try Config.load(explicit: here.appendingPathComponent("config.json").path)
    }

    @Test func threeXLineageContract() throws {
        let config = try loadConfig()
        for (build, entrySel) in Self.lineage {
            let entry = try #require(config.entry(build: build), "3.x 构建 \(build) 不在目录")
            let ids = Set(entry.targets.map(\.identifier))
            #expect(ids == ["revoke", "revoke-keeptip"],
                    "\(build): 目标集 \(ids) 应恰为双变体")
            for target in entry.targets {
                #expect(target.binary == "Contents/MacOS/WeChat",
                        "\(build)/\(target.identifier): 3.x 必须打主程序")
                #expect(target.entries.count == 2,
                        "\(build)/\(target.identifier): 应双架构各 1 条")
                let archs = Set(target.entries.map(\.arch))
                #expect(archs == [.x86_64, .arm64],
                        "\(build)/\(target.identifier): 架构集 \(archs)")
                for e in target.entries {
                    // 溯源必须指向宿主类上的方法级点位；revoke=入口世代名，
                    // revoke-keeptip=执行体（全程稳定选择子）
                    let expectedSel = target.identifier == "revoke"
                        ? entrySel : Self.executorSelector
                    #expect(e.source?.contains(
                        "wxkeep:objc3x:\(Self.hostClass)::\(expectedSel)@\(build)") == true,
                        "\(build)/\(target.identifier)/\(e.arch): source 溯源反常: \(e.source ?? "nil")")
                    // 形态：裸 ret（void 方法），expected = 8 字节序言
                    #expect(e.asm == (e.arch == .x86_64 ? "C3" : "C0035FD6"),
                        "\(build)/\(target.identifier)/\(e.arch): asm=\(e.asm ?? "nil") 非裸 ret")
                    #expect(e.expected?.values.allSatisfy { $0.count == 16 } == true,
                        "\(build)/\(target.identifier)/\(e.arch): expected 非 8 字节序言")
                    #expect(Int(e.addr ?? "", radix: 16) != nil,
                        "\(build)/\(target.identifier)/\(e.arch): addr 非十六进制")
                }
            }
        }
    }

    /// 执行体与入口不得同址（不同位点才构成两变体；同址=派生事故）
    @Test func variantSitesAreDistinct() throws {
        let config = try loadConfig()
        for build in Self.lineage.keys {
            guard let entry = config.entry(build: build) else { continue }
            let sites: [String: Set<String>] = Dictionary(uniqueKeysWithValues:
                entry.targets.map { ($0.identifier,
                    Set(targetSites($0, build: build))) })
            for (id, set) in sites where set.isEmpty {
                Issue.record("\(build)/\(id): 无位点")
            }
            #expect(sites["revoke"]?.isDisjoint(with: sites["revoke-keeptip"] ?? []) == true,
                    "\(build): 两变体位点重叠")
        }
    }

    private func targetSites(_ target: Config.Target, build: String) -> [String] {
        target.entries.map { "\($0.arch.rawValue):\($0.addr ?? "")" }
    }
}
