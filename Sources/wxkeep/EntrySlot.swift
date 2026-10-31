import Foundation

/// T6（94 轮立项）：安装期入口补丁——macOS 27 封死进程内签名页写化
/// （T4/T5 机械定案：mprotect errno 13 / COW 写副本被 CS 击杀）后，
/// runtime hook 的唯一复活路径 = 装机时在磁盘上把 hook 目标函数入口前
/// 12 字节改写为「adrp x16, SLOT; ldr x16, [x16]; br x16」（x16 = linker
/// 惯例 intra-procedure scratch，__objc_stubs 同款），SLOT 落 `__DATA`
/// 段尾文件填充（装机件上可审计的真零区）；runtime dylib 启动时自解码
/// SLOT 地址并把蹦床地址写进去（数据写，合法）。
///
/// 自描述性：入口 12B 即为补丁形态本身——dylib 无需 config 扩展即可识别
/// 补丁态并解码 SLOT；恢复 = 写回 hooks 行 expected 前 12 字节。
enum EntrySlot {
    struct Plan: Equatable {
        let entryVA: UInt64
        let entryFileOffset: Int        // fat 文件绝对偏移（应用补丁处）
        let slotVA: UInt64
        let slotFileOffset: Int         // fat 文件绝对偏移（SLOT 预检/清零处）
        let original12: Data
        let patch12: Data
    }

    enum EntrySlotError: Error, CustomStringConvertible {
        case prologueMismatch(expected: String, actual: String)
        case noTailPadding(need: Int, have: Int)
        case slotUnaligned
        case outOfAdrpRange
        case dataSegmentNotFound

        var description: String {
            switch self {
            case .prologueMismatch(let e, let a):
                return "入口字节与 hooks 行 expected 前 12B 不符（expected \(e.prefix(24)) actual \(a.prefix(24))）——位点漂移或入口补丁已在"
            case .noTailPadding(let need, let have):
                return "__DATA 段尾文件填充不足（需 \(need)B 实得 \(have)B）"
            case .slotUnaligned:
                return "SLOT 未 8 对齐（ldr X 寄存器要求）"
            case .outOfAdrpRange:
                return "SLOT 超出 adrp ±4GB 可达范围"
            case .dataSegmentNotFound:
                return "切片内无 __DATA 段"
            }
        }
    }

    // MARK: - 指令编码（纯函数，golden 向量锁定在测试里）

    /// ADRP Xd, #imm（PC 相对页寻址，±4GB）
    static func encodeAdrp(rd: UInt32, pc: UInt64, target: UInt64) throws -> UInt32 {
        let pcPage = pc & ~UInt64(0xFFF)
        let tPage = target & ~UInt64(0xFFF)
        let diff = Int64(bitPattern: tPage) - Int64(bitPattern: pcPage)
        guard diff % 0x1000 == 0 else { throw EntrySlotError.outOfAdrpRange }
        let pages = diff / 0x1000
        guard pages >= -(1 << 20), pages < (1 << 20) else { throw EntrySlotError.outOfAdrpRange }
        let imm = UInt32(bitPattern: Int32(truncatingIfNeeded: pages)) & 0x1F_FFFF
        let immlo = (imm & 0b11) << 29
        let immhi = (imm >> 2) << 5
        return 0x9000_0000 | immlo | immhi | (rd & 0x1F)
    }

    /// LDR Xt, [Xn, #imm12]（64 位无偏移缩放形式，imm12 按 8 缩放）
    static func encodeLdr64(rt: UInt32, rn: UInt32, byteOffset: UInt64) throws -> UInt32 {
        guard byteOffset % 8 == 0, byteOffset / 8 < 0x1000 else {
            throw EntrySlotError.slotUnaligned
        }
        return 0xF940_0000 | (UInt32(byteOffset / 8) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    static let brX16: UInt32 = 0xD61F_0200

    /// 从指令流解码 adrp x16 + ldr x16,[x16,#imm] + br x16 → SLOT VA。
    /// runtime dylib 侧同构解码（C 实现）；Swift 版供测试与 CLI 校验。
    static func decodeSlotVA(pc: UInt64, w0: UInt32, w1: UInt32, w2: UInt32) -> UInt64? {
        // adrp x16: bit31=1, bits28-24=10000, Rd=16
        guard (w0 >> 31) == 1, ((w0 >> 24) & 0x1F) == 0x10, (w0 & 0x1F) == 16 else { return nil }
        // ldr x16,[x16,#imm]: 0xF9400000 族, Rn=16, Rt=16
        guard (w1 & 0xFFC0_0000) == 0xF940_0000,
              ((w1 >> 5) & 0x1F) == 16, (w1 & 0x1F) == 16 else { return nil }
        guard w2 == brX16 else { return nil }
        let immlo = (w0 >> 29) & 0x3
        let immhi = (w0 >> 5) & 0x7_FFFF
        var imm = (Int64(immhi) << 2) | Int64(immlo)
        if imm & (1 << 20) != 0 { imm -= (1 << 21) }
        let page = (pc & ~UInt64(0xFFF)) &+ (UInt64(bitPattern: Int64(imm)) << 12)
        let off = UInt64((w1 >> 10) & 0xFFF) << 3
        return page &+ off
    }

    // MARK: - 计划（读取切片，产出补丁字节与文件偏移）

    /// 完整计划：arm64 切片 + hooks 行（hook_off/expected）→ Plan。
    /// 应用：`plan.patch12` 写入 `plan.entryFileOffset`；
    /// 恢复：`plan.original12` 写回同位（或已知补丁态时按行 expected 恢复）。
    static func planArm64(file url: URL, hookOff: UInt64,
                          expectedHex: String) throws -> Plan {
        let image = try MachImage(file: url, arch: .arm64)
        let entry = hookOff
        // 1) 现场字节 == expected 前 12B（原始态门）
        guard let cur = image.bytes(va: entry, count: 12) else {
            throw EntrySlotError.prologueMismatch(expected: expectedHex, actual: "<unreadable>")
        }
        guard let expected = Data(hex: String(expectedHex.prefix(24))) else {
            throw EntrySlotError.prologueMismatch(expected: expectedHex, actual: "expected 非 hex")
        }
        guard cur == expected else {
            throw EntrySlotError.prologueMismatch(
                expected: expected.map { String(format: "%02X", $0) }.joined(),
                actual: cur.map { String(format: "%02X", $0) }.joined())
        }
        // 2) __DATA 段：由任一 segment=="__DATA" 的 section 反查其所属段
        guard let dataSection = image.sections.first(where: { $0.segment == "__DATA" }) else {
            throw EntrySlotError.dataSegmentNotFound
        }
        guard let seg = image.segments.first(where: {
            dataSection.addr >= $0.vmaddr && dataSection.addr < $0.vmaddr + $0.vmsize
        }) else {
            throw EntrySlotError.dataSegmentNotFound
        }
        // 3) 段内最后 file-backed section 的结尾 → 段文件尾之间的真填充
        let lastEnd = image.sections
            .filter { $0.segment == "__DATA" && $0.offset > 0 }
            .map { $0.offset + Int($0.size) }
            .max() ?? 0
        guard lastEnd > 0 else { throw EntrySlotError.noTailPadding(need: 16, have: 0) }
        // 段文件尾 = 切片内下一个 file-backed 段的 fileoff（与切片尾取小）
        let nextFileOff = image.segments
            .map(\.fileoff)
            .filter { $0 > seg.fileoff }
            .min() ?? UInt64(image.data.count)
        let segFileEnd = min(nextFileOff, UInt64(image.data.count))
        let padStart = max(lastEnd, Int(seg.fileoff))
        let pad = Int(segFileEnd) - padStart
        guard pad >= 16 else {
            throw EntrySlotError.noTailPadding(need: 16, have: max(pad, 0))
        }
        // 8 对齐向上的 SLOT + 真零验证（不覆盖任何有值数据）
        var slotOff = (padStart + 7) & ~7
        if slotOff < padStart { slotOff = padStart }
        guard slotOff + 8 <= segFileEnd else {
            throw EntrySlotError.noTailPadding(need: 8, have: Int(segFileEnd) - slotOff)
        }
        let slotVA = seg.vmaddr + UInt64(slotOff - Int(seg.fileoff))
        guard slotVA % 8 == 0 else { throw EntrySlotError.slotUnaligned }
        guard image.bytes(va: slotVA, count: 8) == Data(repeating: 0, count: 8) else {
            throw EntrySlotError.noTailPadding(need: 8, have: 0)
        }
        // 4) adrp 可达 + 组装 12B 补丁
        _ = try encodeAdrp(rd: 16, pc: entry, target: slotVA)
        var words: [UInt32] = [
            try encodeAdrp(rd: 16, pc: entry, target: slotVA),
            try encodeLdr64(rt: 16, rn: 16, byteOffset: slotVA & 0xFFF),
            brX16,
        ]
        var patch = Data()
        for x in words {
            var le = x.littleEndian
            withUnsafeBytes(of: &le) { patch.append(contentsOf: $0) }
        }
        // 5) 切片相对偏移 → fat 文件绝对偏移（VA==fileoff 的 dylib 上两者同值，
        //    仍走 sliceRelativeOffset 保守换算）
        guard let entryOff = image.sliceRelativeOffset(va: entry),
              let slotOffInSlice = image.sliceRelativeOffset(va: slotVA) else {
            throw EntrySlotError.prologueMismatch(expected: expectedHex, actual: "VA→off 失败")
        }
        let fatEntryOff = image.sliceOffset + entryOff
        let fatSlotOff = image.sliceOffset + slotOffInSlice
        return Plan(entryVA: entry, entryFileOffset: fatEntryOff,
                    slotVA: slotVA, slotFileOffset: fatSlotOff,
                    original12: expected.prefix(12), patch12: patch)
    }

    /// 已补丁态识别：入口 12B 自解码出 SLOT 且 SLOT 在 __DATA 段尾填充区。
    static func detectPatched(file url: URL, hookOff: UInt64) -> UInt64? {
        guard let image = try? MachImage(file: url, arch: .arm64),
              let raw = image.bytes(va: hookOff, count: 12) else { return nil }
        var w: [UInt32] = []
        for i in 0..<3 {
            let b0 = UInt32(raw[i * 4])
            let b1 = UInt32(raw[i * 4 + 1]) << 8
            let b2 = UInt32(raw[i * 4 + 2]) << 16
            let b3 = UInt32(raw[i * 4 + 3]) << 24
            w.append(b0 | b1 | b2 | b3)
        }
        return decodeSlotVA(pc: hookOff, w0: w[0], w1: w[1], w2: w[2])
    }
}
