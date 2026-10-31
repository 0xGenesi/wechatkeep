import Testing
import Foundation
@testable import wxkeep

/// T6（94 轮）：安装期入口补丁——编码 golden、编解码往返、真切片计划。
/// 机制背景：macOS 27 进程内代码页写化被策略封死（T4/T5 机械定案），
/// 入口补丁在磁盘预置「adrp x16,SLOT; ldr; br」跳板，dylib 启动时数据写
/// SLOT（唯一合法写路径）。判定语义探针（wxprobe）已另测。
struct EntrySlotTests {
    @Test func adrpLdrRoundTrip() throws {
        // 同页/跨页/负偏移/页界四种形态全部往返一致
        let cases: [(pc: UInt64, slot: UInt64)] = [
            (0x4d1f8d8, 0xa24dfc8),          // 270135 实际几何（正向 ~0x55 页）
            (0x1000, 0x2000),                // 相邻页
            (0x2FFF, 0x1000),                // 负向、PC 页内偏移跨页
            (0x8000_0000, 0x7FFF_F000),      // 负向大偏移
        ]
        for c in cases {
            let w0 = try EntrySlot.encodeAdrp(rd: 16, pc: c.pc, target: c.slot)
            let w1 = try EntrySlot.encodeLdr64(rt: 16, rn: 16, byteOffset: c.slot & 0xFFF)
            let back = EntrySlot.decodeSlotVA(pc: c.pc, w0: w0, w1: w1, w2: EntrySlot.brX16)
            #expect(back == c.slot, "round-trip \(c)")
        }
    }

    @Test func adrpEncodingKnownVector() throws {
        // ADRP x16, target：手算向量（immlo/immhi 拆分 + 0x90000000 基）
        // pc=0x4d1f8d8（页 0x4d1f000）→ slot 页 0xa24d000：pages=0x552E
        let w = try EntrySlot.encodeAdrp(rd: 16, pc: 0x4d1f8d8, target: 0xa24d000)
        // imm=0x552E → immlo=0b10(0x552E&3=2)、immhi=0x154B<<5
        #expect(w == 0x9000_0000 | ((0x552E & 3) << 29) | ((0x552E >> 2) << 5) | 16)
        // ldr x16,[x16,#0xfc8]：0xF9400000 | (0x1F9<<10) | (16<<5) | 16
        let l = try EntrySlot.encodeLdr64(rt: 16, rn: 16, byteOffset: 0xfc8)
        #expect(l == 0xF940_0000 | (0x1F9 << 10) | (16 << 5) | 16)
        #expect(EntrySlot.brX16 == 0xD61F_0200)
    }

    @Test func decodeRejectsNonPatchShapes() {
        // 非 adrp/非 ldr x16/非 br 形态一律 nil（dylib 侧识别补丁态的门）
        #expect(EntrySlot.decodeSlotVA(pc: 0x1000, w0: 0x1400_0001, w1: 0xF940_0000 | (16 << 5) | 16, w2: EntrySlot.brX16) == nil)   // b 非 adrp
        #expect(EntrySlot.decodeSlotVA(pc: 0x1000, w0: 0x9000_0000 | 16, w1: 0xF940_0000 | (17 << 5) | 16, w2: EntrySlot.brX16) == nil)   // Rn≠16
        #expect(EntrySlot.decodeSlotVA(pc: 0x1000, w0: 0x9000_0000 | 16, w1: 0xF940_0000 | (16 << 5) | 16, w2: 0xD65F_03C0) == nil)   // ret 非 br x16
    }

    /// 真切片计划（270135 arm64，开发机 var/ 在库时）：SLOT 应落在手算的
    /// __DATA 段尾填充 0xa24dfc8；入口=parse 0x4d1f8d8。
    @Test(.enabled(if: FileManager.default.fileExists(atPath: "var/wxarm/270135_arm64.dylib")),
          .disabled(if: ProcessInfo.processInfo.environment["CI"] != nil))
    func realSlicePlan270135() throws {
        let url = URL(fileURLWithPath: "var/wxarm/270135_arm64.dylib")
        let plan = try EntrySlot.planArm64(
            file: url, hookOff: 0x4d1f8d8,
            expectedHex: "F85FBCA9F65701A9F44F02A9FD7B03A9")
        #expect(plan.entryVA == 0x4d1f8d8)
        #expect(plan.slotVA == 0xa24dfc8, "SLOT 应为 __DATA 段尾填充 8 对齐位（手算 94 轮）")
        #expect(plan.original12.count == 12)
        // 补丁自解码回 SLOT
        let w: [UInt32] = (0..<3).map { i in
            plan.patch12.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i * 4, as: UInt32.self) }
        }
        #expect(EntrySlot.decodeSlotVA(pc: plan.entryVA, w0: w[0], w1: w[1], w2: w[2]) == plan.slotVA)
        // 已补丁态识别
        #expect(EntrySlot.detectPatched(file: url, hookOff: 0x4d1f8d8) == nil)   // 原始态无补丁
    }

    /// detectPatched 落区门（P2 修复回归）：真补丁态识别 ✓；SLOT 区字节
    /// 非零（非 planArm64 选址不变量）→ 判非补丁。只有指令形态门时，
    /// __objc_stubs 原生三连会被误判成已补丁（install 跳武装/remove 误还原）。
    @Test(.enabled(if: FileManager.default.fileExists(atPath: "var/wxarm/270135_arm64.dylib")),
          .disabled(if: ProcessInfo.processInfo.environment["CI"] != nil))
    func detectPatchedRegionGateOnRealSlice() throws {
        let src = URL(fileURLWithPath: "var/wxarm/270135_arm64.dylib")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-eslot-\(UUID().uuidString).dylib")
        try FileManager.default.copyItem(at: src, to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let plan = try EntrySlot.planArm64(
            file: tmp, hookOff: 0x4d1f8d8,
            expectedHex: "F85FBCA9F65701A9F44F02A9FD7B03A9")
        var data = try Data(contentsOf: tmp)
        data.replaceSubrange(plan.entryFileOffset..<plan.entryFileOffset + 12, with: plan.patch12)
        try data.write(to: tmp)
        #expect(EntrySlot.detectPatched(file: tmp, hookOff: 0x4d1f8d8) == plan.slotVA,
                "真补丁态必须识别（SLOT 在段尾填充且内容为零）")

        // SLOT 区被写入非零值（非 planArm64 不变量）→ 指令形态再像也不是补丁
        var corrupted = try Data(contentsOf: tmp)
        corrupted.replaceSubrange(plan.slotFileOffset..<plan.slotFileOffset + 8,
                                  with: Data(repeating: 0xAA, count: 8))
        try corrupted.write(to: tmp)
        #expect(EntrySlot.detectPatched(file: tmp, hookOff: 0x4d1f8d8) == nil,
                "SLOT 内容非零 = 非 planArm64 选址（objc_stubs 的 ldr 目标不满足零内容）")
    }
}
