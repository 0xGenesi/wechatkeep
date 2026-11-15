import Foundation
import Testing
@testable import wxkeep

/// 137 轮方案 v2：计数签名校准（`runtime calibrate`）纯逻辑回归。
/// 判读分支按面别语义钉死——产品面（zero/fires）是合成事件唯一替代
/// 不了的证明；仪器面（克隆证据链）随同一事件落账；selfskip 单独成
/// 面（边界确认非产品证明）；marker 重置（微信重启）= 增量不可比。
struct RuntimeCalibrateTests {

    /// runtime.m marker_content 同构合成行（键序与格式一致）
    private func marker(_ counters: [String: Int]) -> String {
        var parts = ["loaded ts=1.0 mr2=hook-armed status=8 enc=2 istep=0 ierr=0"]
        for (k, v) in counters { parts.append("\(k)=\(v)") }
        parts.append("cfg=1 cfgh=0000000000000001 last=<none> inner=<none> probe=<none>")
        return parts.joined(separator: " ") + "\n"
    }

    @Test func parseCountersReadsNumericKeysOnly() {
        let text = marker(["fires": 22, "zero": 3, "selfskip": 6])
        let c = Wxkeep.RuntimeCommand.parseCounters(text)
        #expect(c["fires"] == 22)
        #expect(c["zero"] == 3)
        #expect(c["selfskip"] == 6)
        #expect(c["clpub"] == nil)   // 缺席键 = 无此计数（非 0 语义由 verdict 的 ?? 0 统一）
        #expect(c["mr2"] == nil)     // 字符串键天然落选
        #expect(Wxkeep.RuntimeCommand.parseCounters(nil).isEmpty)
        // ts=1.0 含小数点：数字前缀截取只吃 "1"——ts 不是计数键，无干扰
        #expect(c["loaded"] == nil)
    }

    @Test func verdictNoEventWindow() {
        let c = Wxkeep.RuntimeCommand.parseCounters(marker(["fires": 22, "selfskip": 6]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: c, after: c)
        #expect(v.summary == "no-event")
        #expect(!v.productProven && !v.instrumentSampled && !v.reset)
        #expect(v.lines.contains { $0.contains("无他撤事件") })
    }

    @Test func verdictProductProofViaZero() {
        let before = Wxkeep.RuntimeCommand.parseCounters(marker(["zero": 0, "fires": 22]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker(["zero": 1, "fires": 22]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        #expect(v.productProven)
        #expect(!v.instrumentSampled)
        #expect(v.summary == "product-only")
        #expect(v.lines.contains { $0.contains("保留动作 +1") && $0.contains("产品面") })
    }

    @Test func verdictSelfskipOnlyIsBoundaryNotProduct() {
        let before = Wxkeep.RuntimeCommand.parseCounters(marker(["selfskip": 5]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker(["selfskip": 6]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        // 自撤走 selfskip 门——不构成产品证明（他撤链未经过），单独成面
        #expect(!v.productProven && !v.instrumentSampled)
        #expect(v.summary == "selfskip-only")
        #expect(v.lines.contains { $0.contains("边界确认") })
    }

    @Test func verdictInstrumentSamplingAndClpubGuidance() {
        let before = Wxkeep.RuntimeCommand.parseCounters(marker(["clone": 13, "clmissq": 13, "clpub": 0]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker(["clone": 14, "clmissq": 14, "clpub": 1]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        #expect(v.instrumentSampled && !v.productProven)
        #expect(v.summary == "instrument-only")
        #expect(v.lines.contains { $0.contains("clpub=+1") })
        #expect(v.lines.contains { $0.contains("M4 认证采样可行") && $0.contains("r8pub") })
    }

    @Test func verdictFullChainProductPlusInstrument() {
        let before = Wxkeep.RuntimeCommand.parseCounters(marker([:]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker([
            "zero": 2, "fires": 1, "clone": 1, "clsvc": 1, "clkey": 1, "clhit": 1, "clpub": 2]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        #expect(v.productProven && v.instrumentSampled)
        #expect(v.summary == "product+instrument")
        #expect(v.lines.contains { $0.contains("克隆证据链：") })
    }

    @Test func verdictDetectsMarkerReset() {
        // after < before = 微信重启（计数归零）——增量不可比必须显式红
        let before = Wxkeep.RuntimeCommand.parseCounters(marker(["fires": 22, "clone": 13]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker(["fires": 2, "clone": 1]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        #expect(v.reset)
        #expect(v.lines.contains { $0.contains("marker 重置") })
    }

    @Test func verdictClinsActivationLine() {
        let before = Wxkeep.RuntimeCommand.parseCounters(marker([:]))
        let after = Wxkeep.RuntimeCommand.parseCounters(marker(["clins": 1, "clpubm": 1]))
        let v = Wxkeep.RuntimeCommand.calibrationVerdict(before: before, after: after)
        #expect(v.lines.contains { $0.contains("插入调用已激活") && $0.contains("pub_vt") })
        #expect(v.lines.contains { $0.contains("clpubm=+1") })
    }
}
