import Foundation
import Testing
@testable import wxkeep

/// L12 负空间完备性（混淆矩阵）（V6-DEPTH D16/R15，133 轮）。
///
/// 判别器的价值在拒绝：expected 门对「他构建条目 × 本构建二进制」的
/// 全矩阵必须零假接受——此前只有单字节篡改负控，「错版目录数据」这一
/// A5 级威胁的判别力从未被系统测量。
///
/// 合成全矩阵（本文件，CI 常跑）：4 构建 × 4 二进制 = 16 格——
///   · 对角 4 格：written（正常路径）；
///   · 共享序言对 (V1,V4)/(V4,V1)：**接受 = 设计边界如实入测**——两构建
///     在同 VA 的 expected 字节相同（4.x 家族 stp 序言大量复用的真实构型），
///     字节门按定义无法判别。这不是缺陷而是字节门的定义域：判别力 = 字节
///     精确匹配。共享构型的上层防线是 L9 目标恒等门 + 行为 verify +
///     build 号选表（config.entry(build:)）——边界写成契约而非假设；
///   · 其余 10 格：patch 精确抛 expectedMismatch / inspect 报 .unknown
///     （零假接受）。
///
/// 真切片腿（ConfusionMatrixRealTests，env-gated）：WXKEEP_CONFUSION_PLAN
/// 计划（python 从 config.json 抽取 revoke 条目 + var/wxarm 切片），全对角
/// + 非对角抽样，inspect 只读；接受/拒绝逐格输出 JSON 行，独立 python
/// 复核（verify_confusion_matrix.py 双向灵敏度：接受格 ⇔ 独立实现确认
/// 字节相等；不一致 = 假接受/假拒绝红灯）。
struct ConfusionMatrixTests {
    /// V1..V3 位点字节互异；V4 与 V1 共享 expected（stp 序言构型）。
    /// 每个 binary 的 pristine @100 = 自家 expected 字节。
    private static let builds: [(id: String, expected: String, asm: String)] = [
        ("V1", "F44FBEA9FD7B01A9", "00008052C0035FD6"),
        ("V2", "AABBCCDDEEFF0011", "1122334455667788"),
        ("V3", "9988776655443322", "AA88CCDD66EE5544"),
        ("V4", "F44FBEA9FD7B01A9", "4444444452008052"),   // 共享序言对成员
    ]

    private static func entries(_ id: String) -> [Config.PatchEntry] {
        let spec = builds.first { $0.id == id }!
        return [Config.PatchEntry(
            arch: .arm64, addr: "100", recipe: nil,
            expected: Config.ExpectedVariants([spec.expected]),
            asm: spec.asm, source: "confusion-matrix")]
    }

    /// thin arm64 binary，@100 处载入 pristine 字节。
    private static func makeBinary(_ id: String, work: URL) throws -> URL {
        let spec = builds.first { $0.id == id }!
        let pristine = Array(Data(hex: spec.expected)!)
        let image = MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400,
                                      code: [(0x100, pristine)])
        let url = work.appendingPathComponent("\(id).dylib")
        try image.write(to: url)
        return url
    }

    @Test func diagonalAcceptedCrossVariateRejected() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-confusion-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        var binaries: [String: URL] = [:]
        for spec in Self.builds {
            binaries[spec.id] = try Self.makeBinary(spec.id, work: work)
        }

        var accepted = 0, rejected = 0
        for entrySpec in Self.builds {
            for binSpec in Self.builds {
                // 每格独立副本——patch 层格子会写，防交叉污染。
                let cellURL = work.appendingPathComponent("cell-\(entrySpec.id)-\(binSpec.id).dylib")
                try FileManager.default.copyItem(at: binaries[binSpec.id]!, to: cellURL)
                let entries = Self.entries(entrySpec.id)

                // inspect 层
                let inspections = try Patcher.inspect(binary: cellURL, entries: entries,
                                                      identifier: "confusion")
                let isDiagonal = entrySpec.id == binSpec.id
                let sharesPrologue = entrySpec.expected == binSpec.expected

                if isDiagonal || sharesPrologue {
                    // 接受格：对角 = 正常路径；共享序言 = 设计边界契约
                    //（字节门判别力的显式记录——见文件头注释）。
                    let isPristine = inspections.first?.state == .pristine
                    #expect(isPristine,
                            "\(entrySpec.id)→\(binSpec.id): 接受格 inspect 态异常")
                    let outcomes = try Patcher.patch(binary: cellURL, entries: entries,
                                                     identifier: "confusion")
                    let writtenAll = outcomes.count == 1 && outcomes[0] == .written
                    #expect(writtenAll,
                            "\(entrySpec.id)→\(binSpec.id): 接受格 patch 未写入")
                    accepted += 1
                } else {
                    // 拒绝格：零假接受——inspect 报 unknown，patch 精确抛
                    // expectedMismatch（错版目录数据事故的干净拒绝路径）。
                    let isUnknown = inspections.first?.state == .unknown
                    // Inspection.State 无 rawValue——显式字符串化供诊断消息。
                    let inspectState: String = {
                        switch inspections.first?.state {
                        case .patched: return "patched"
                        case .pristine: return "pristine"
                        case .ambiguous: return "ambiguous"
                        case .unknown: return "unknown"
                        case nil: return "empty"
                        }
                    }()
                    #expect(isUnknown,
                            "\(entrySpec.id)→\(binSpec.id): 拒绝格假接受（inspect 报 \(inspectState)）")
                    let error = expectThrows(
                        try Patcher.patch(binary: cellURL, entries: entries,
                                          identifier: "confusion"))
                    // 精确 case（133 轮双评审 P3：is PatchError 弱于表述——
                    // 错版拒绝必须是 expectedMismatch 这一个 case）。
                    let isExpectedMismatch = "\(error)".contains("expected one of")
                    #expect(isExpectedMismatch,
                            "\(entrySpec.id)→\(binSpec.id): 拒绝错误 ≠ expectedMismatch（得 \(error)）")
                    rejected += 1
                }
            }
        }

        // 矩阵形状自证：16 格 = 4 接受对角 + 2 共享序言接受 + 10 拒绝。
        #expect(accepted == 6, "接受格数 \(accepted) ≠ 6（4 对角 + 2 共享序言）")
        #expect(rejected == 10, "拒绝格数 \(rejected) ≠ 10")
    }

    /// patch 层第二道门：接受格写入后，其他构建条目对**已打补丁**的副本
    /// 仍必拒（expected 多变体门覆盖 pristine 与 patched 两种盘面态）。
    @Test func patchedStateStillRejectsForeignEntries() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-confusion-p-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        // V1 打满 → 盘上 @100 = V1 asm；V3 条目（expected=V3 pristine 字节）
        // 对该盘面必须拒绝（盘面既非 V3 pristine 也非 V3 asm）。
        let v1 = try Self.makeBinary("V1", work: work)
        let outcomes = try Patcher.patch(binary: v1, entries: Self.entries("V1"),
                                         identifier: "confusion")
        let writtenAll = outcomes.count == 1 && outcomes[0] == .written
        #expect(writtenAll)
        let error = expectThrows(try Patcher.patch(binary: v1, entries: Self.entries("V3"),
                                                   identifier: "confusion"))
        let isExpectedMismatch = "\(error)".contains("expected one of")
        #expect(isExpectedMismatch,
                "patched 态对外条目的拒绝应报 expectedMismatch（得 \(error)）")
    }
}

/// L12 真切片腿（env-gated）：计划由 tools/verify_confusion_matrix.py 生成
/// （config.json revoke 条目 × var/wxarm 切片），inspect 只读零写入；逐格
/// 输出 JSON 行供 python 独立复核（双向灵敏度判据见文件头）。
struct ConfusionMatrixRealTests {
    private static func plan() -> [[String: Any]]? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_CONFUSION_PLAN"],
              FileManager.default.fileExists(atPath: path),
              let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
              !json.isEmpty else { return nil }
        return json
    }

    @Test(.disabled(if: plan() == nil,
                    "WXKEEP_CONFUSION_PLAN not set — confusion oracle skipped"))
    func confusionOracleOnRealSlices() throws {
        let items = try #require(Self.plan())
        for item in items {
            // 一行一格："CONF {from}->{to} arch={arch} accept={state}|reject"
            guard let from = item["from"] as? String,
                  let to = item["to"] as? String,
                  let dylibPath = item["dylib"] as? String,
                  let entriesRaw = item["entries"] as? [[String: Any]],
                  FileManager.default.fileExists(atPath: dylibPath) else { continue }
            let entries = try entriesRaw.map { raw -> Config.PatchEntry in
                guard let arch = raw["arch"] as? String,
                      let addr = raw["addr"] as? String,
                      let asm = raw["asm"] as? String else {
                    throw DummyError()
                }
                let expected = (raw["expected"] as? [String]) ?? []
                guard let archEnum = Config.Arch(rawValue: arch) else {
                    throw DummyError()   // 133 轮双评审 P3：错 arch 显式失败，
                                         // 不静默纠偏 arm64（溯源困难）
                }
                return Config.PatchEntry(
                    arch: archEnum,
                    addr: addr, recipe: nil,
                    expected: Config.ExpectedVariants(expected),
                    asm: asm, source: "confusion-real")
            }
            let dylib = URL(fileURLWithPath: dylibPath)
            let inspections = (try? Patcher.inspect(binary: dylib, entries: entries,
                                                    identifier: "confusion-real")) ?? []
            // Inspection.State 无 rawValue——显式字符串化（accept = 接受格，
            // 供 python 独立复核字节；reject = 拒绝格）。cell 格式
            // "verdict:state:addr:current-hex"（python 端按 addr 对齐条目）。
            let states = inspections.map { inspection -> String in
                let stateName: String
                switch inspection.state {
                case .patched: stateName = "patched"
                case .pristine: stateName = "pristine"
                case .ambiguous: stateName = "ambiguous"
                case .unknown: stateName = "unknown"
                }
                let addr = String(inspection.va, radix: 16)
                let verdict = inspection.state == .unknown ? "reject" : "accept"
                return "\(verdict):\(stateName):\(addr):\(inspection.current)"
            }
            let payload: [String: Any] = [
                "from": from, "to": to, "cells": states,
            ]
            if let lineData = try? JSONSerialization.data(withJSONObject: payload),
               let line = String(data: lineData, encoding: .utf8) {
                print("CONF \(line)")
            }
        }
    }
}
