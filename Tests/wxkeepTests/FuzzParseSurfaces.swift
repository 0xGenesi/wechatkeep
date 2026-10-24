import Foundation
import Testing
@testable import wxkeep

/// L3⑤ Swift 侧解析面模糊测试：确定性 PRNG（SplitMix64，种子固定 →
/// 失败可复现）随机畸形输入驱动四个解析面：
/// - `Data(hex:)` / `ExpectedPattern`（catalog expected/asm 文本面）
/// - `MachOInjector`（fat/thin 头、load command 遍历、插入/移除）
/// - `MachImage`（段表/节表解析）
/// 预言：零崩溃 + 若干恒成立的不变量（全具体 pattern 自匹配、
/// Data(hex:) 长度契约、注入-移除往返保持文件长度）。
/// C 侧（runtime.m 测试缝）的 coverage-guided 模糊见 tools/fuzz/run_fuzz.sh。
struct FuzzParseSurfaces {
    /// SplitMix64：小、快、跨平台确定的 PRNG。
    private struct Rng {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
        mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
        mutating func bool() -> Bool { next() & 1 == 0 }
        mutating func below(_ n: Int) -> Int { Int(next() % UInt64(n)) }
    }

    private static let charset = Array("0123456789abcdefABCDEF? :maskxZ\"'\\\n\t".unicodeScalars)

    private static func randomHexishString(_ rng: inout Rng) -> String {
        let n = rng.below(40)
        var out = ""
        for _ in 0..<n { out.unicodeScalars.append(charset[rng.below(charset.count)]) }
        return out
    }

    /// 随机 Mach-O 形态字节：大头是零/随机，头部按概率植入四种 magic 之一
    /// （让 sliceInfo/slices 真的走进解析路径而不是永远在入口被拒）。
    private static func randomMachOBlob(_ rng: inout Rng) -> Data {
        let n = 1 + rng.below(8192)
        var data = Data(count: n)
        // 显式标注闭包参数类型：CI 的旧 SDK 上 Data 同时存在 RawBufferPointer
        // 与 legacy Pointer<UInt8> 两条 withUnsafeMutableBytes 重载，`raw[i]`
        // 对两者皆合法 → 裸 `{ raw in` 类型推断二义（新 SDK 已删旧重载故
        // 本机可编译）。显式类型让重载唯一，全工具链一致。
        data.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            for i in 0..<n { raw[i] = rng.byte() }
        }
        switch rng.below(5) {
        case 0: data.replaceSubrange(0..<min(4, n), with: [0xCF, 0xFA, 0xED, 0xFE])
        case 1: data.replaceSubrange(0..<min(4, n), with: [0xBE, 0xBA, 0xFE, 0xCA])
        case 2: data.replaceSubrange(0..<min(4, n), with: [0xCA, 0xFE, 0xBA, 0xBE])
        case 3:  // FAT + 疯狂 nfat（越界由守卫拒绝）
            data.replaceSubrange(0..<min(8, n), with: [0xCA, 0xFE, 0xBA, 0xBE, 0x7F, 0xFF, 0xFF, 0xFF])
        default: break
        }
        return data
    }

    @Test
    func hexPatternInjectorAndImageParsingTakeGarbageWithoutCrashing() {
        var rng = Rng(state: 0x776B_6565_7032_3036)   // "wkeep2026"
        let iterations = 20_000
        var concreteSelfMatchChecks = 0
        for it in 0..<iterations {
            // 面 1：hex / ExpectedPattern 文本（每 100 迭代注入一条纯 hex
            // 确定性样本，保证「全具体 pattern 自匹配」不变量有足量采样）
            let spec = it % 20 == 0
                ? String(repeating: "0123456789ABCDEF".map { $0 }[it % 16], count: 2 * (1 + it % 8))
                : Self.randomHexishString(&rng)
            if let data = Data(hex: spec) {
                #expect(data.count * 2 <= spec.unicodeScalars.count)   // 奇/坏字符 → nil
            }
            if let pattern = ExpectedPattern(spec: spec) {
                #expect(pattern.byteCount >= 0)
                let probe = Data((0..<pattern.byteCount + 4).map { _ in rng.byte() })
                _ = pattern.matches(probe)
                for n in 0...pattern.byteCount + 1 {
                    _ = pattern.concretePrefix(n)
                }
                // 不变量：全具体 pattern 的物化字节必匹配自身
                if let full = pattern.concretePrefix(pattern.byteCount) {
                    #expect(pattern.matches(full))
                    concreteSelfMatchChecks += 1
                }
            }

            // 面 2：MachOInjector
            var blob = Self.randomMachOBlob(&rng)
            _ = (try? MachOInjector.slices(in: blob)) ?? nil
            if let bases = try? MachOInjector.slices(in: blob) {
                for b in bases { _ = try? MachOInjector.sliceInfo(in: blob, base: b) }
            }
            _ = MachOInjector.isInjectedAnySlice(data: blob, path: "@executable_path/x.dylib")
            let cmd = MachOInjector.buildLoadDylibCommand(path: String(
                (0..<rng.below(120)).map { _ in Character(UnicodeScalar(rng.byte() % 95 + 32)) }))
            #expect(cmd.count % 8 == 0 && cmd.count >= 24)
            let before = blob.count
            if (try? MachOInjector.insertLoadDylib(data: &blob, dylibInstallPath: "/x.dylib")) != nil {
                _ = MachOInjector.isInjectedAnySlice(data: blob, path: "/x.dylib")
                if (try? MachOInjector.removeLoadDylib(data: &blob, dylibInstallPath: "/x.dylib")) != nil {
                    // 移除以尾部补零保持长度——插入-移除往返不得改变文件长度
                    #expect(blob.count == before)
                }
            }

            // 面 3：MachImage（临时文件——init 走文件路径）
            if rng.bool() {
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent("wxkeep-fuzz-\(UUID().uuidString).bin")
                try? blob.write(to: tmp)
                defer { try? FileManager.default.removeItem(at: tmp) }
                _ = try? MachImage(file: tmp, arch: rng.bool() ? .arm64 : .x86_64)
            }
        }
        // 采样计数落在合理区间（防「分支从未到达」的假覆盖）
        #expect(concreteSelfMatchChecks > iterations / 100)
    }

    @Test
    func patternMaskSemanticsSurviveTargetedMalformedSpecs() {
        // 定向语料：掩码后缀的各种坏形态（mask 空 / 非 hex / 冒号悬挂）
        let bad = ["1:", "1:mask", "1:maskZZ", "1:mask0", ":maskFF", "?? :maskFF",
                   "12:maskf", "12:maskFF:extra", "1 2", "0x12", "-", "\u{301}1"]
        for spec in bad {
            if let p = ExpectedPattern(spec: spec) {
                // 被接受的必须能安全使用（不放任何断言失败——只证明不崩 + 自洽）
                _ = p.matches(Data([0x12, 0x34]))
            }
        }
        // 合法形态的语义锚：掩码位与通配位都放行不匹配字节
        // "12:mask0F"：高半字节被掩掉，只比对低半字节 ==2
        let pat = ExpectedPattern(spec: "12:mask0F")
        #expect(pat?.matches(Data([0xA2])) == true)    // 低半字节 2 ✓ 高位任意
        #expect(pat?.matches(Data([0xA1])) == false)   // 低半字节 1 ✗
        #expect(ExpectedPattern(spec: "?2")?.matches(Data([0xF2])) == true)
        #expect(ExpectedPattern(spec: "?2")?.concretePrefix(1) == nil)
        // 短数据必须整体不匹配（72·L4 变异测试揭出的缺口：guard 曾可被
        // 「+8 放行」变异存活——短读越界 Data 下标即崩溃）
        #expect(ExpectedPattern(spec: "1234")?.matches(Data([0x12])) == false)
        #expect(ExpectedPattern(spec: "1234")?.matches(Data([])) == false)
    }
}
