import Foundation
import Testing
@testable import wxkeep

/// 深度不变量（V3-DEPTH）：把「引擎是纯函数」「检测器能检出篡改」「注入
/// round-trip 是性质而非单点」从隐含假设升格为机器预言。
///
/// - 确定性：patch(pristine) 必须是数学函数——两份独立副本各跑一次，
///   输出逐字节恒等。任何未来的时间戳/随机性/迭代序引入都会在这里翻红。
/// - 负控：检测器自身必须被证明「能检测」——翻转一个已打补丁字节后，
///   inspect/aggregate 必须报 unknown/mixed，绝不能误报 patched。
/// - 性质：注入器往返在随机化变体（路径长度/镜像尺寸/头填充）上恒成立。
final class DepthInvariantsTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-depth-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    private func pristineThin() -> Data {
        MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
            (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            (0x120, [0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54]),
            (0x140, [0xF8, 0x5F, 0xBC, 0xA9, 0xF6, 0x57, 0x01, 0xA9]),
        ])
    }

    private var entries: [Config.PatchEntry] {
        [
            MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E553504889FB"]),
            MachOFixture.entry(.x86_64, addr: "120", asm: "90909090", expected: ["4157415641554154"]),
            MachOFixture.entry(.x86_64, addr: "140", asm: "1F2003D5", expected: ["F85FBCA9F65701A9"]),
        ]
    }

    // MARK: L6 确定性

    @Test func patchIsDeterministicAcrossIndependentRuns() throws {
        let a = workDir.appendingPathComponent("copy-a.dylib")
        let b = workDir.appendingPathComponent("copy-b.dylib")
        try pristineThin().write(to: a)
        try pristineThin().write(to: b)

        _ = try Patcher.patch(binary: a, entries: entries, identifier: "revoke")
        _ = try Patcher.patch(binary: b, entries: entries, identifier: "revoke")

        let patchedA = try Data(contentsOf: a)
        let patchedB = try Data(contentsOf: b)
        #expect(patchedA == patchedB, "两份独立副本的补丁输出必须逐字节恒等")
        #expect(patchedA != pristineThin(), "fixture 必须真的被改写（防恒真）")

        // restore 同理是纯函数：两条独立还原路径回到同一 pristine
        let inverted = entries.map { e -> Config.PatchEntry in
            var copy = e
            copy.asm = e.expected!.values[0]
            copy.expected = Config.ExpectedVariants([e.asm] + e.expected!.values)
            return copy
        }
        _ = try Patcher.patch(binary: a, entries: inverted, identifier: "revoke")
        _ = try Patcher.patch(binary: b, entries: inverted, identifier: "revoke")
        let restoredA = try Data(contentsOf: a)
        let restoredB = try Data(contentsOf: b)
        #expect(restoredA == pristineThin())
        #expect(restoredA == restoredB)
    }

    // MARK: 负控（检测器的检测）

    @Test func tamperedPatchPointIsDetectedNotReportedClean() throws {
        let binary = workDir.appendingPathComponent("tampered.dylib")
        try pristineThin().write(to: binary)
        _ = try Patcher.patch(binary: binary, entries: entries, identifier: "revoke")
        var blob = try Data(contentsOf: binary)
        // 篡改第 2 个补丁点的首字节（90 → 91）：仍在 asm 长度内、非 asm、
        // 非 expected —— 必须落 .unknown
        blob[0x120] = 0x91
        try blob.write(to: binary)

        let inspections = try Patcher.inspect(binary: binary, entries: entries, identifier: "revoke")
        #expect(inspections.count == 3)
        #expect(inspections[0].state == .patched)
        #expect(inspections[1].state == .unknown, "被篡改的补丁点必须报 unknown（负控核心断言）")
        #expect(inspections[2].state == .patched)
        // doctor 聚合层同样不得洗白：unknown 传播为 unknown（→ overall mixed）
        #expect(Doctor.aggregate(inspections.map(\.state)) == "unknown")
    }

    // MARK: 注入往返性质（随机化变体）

    /// 复用 MachOInjectorTests 的头空间布局，但路径长度、镜像尺寸与头填充
    /// 随机化。往返的**精确契约**（removeLoadDylib「尾部补零」语义）：
    /// 唯一允许的字节差异 = 原命令区末尾被临时命令占用的 [cmdsEnd,
    /// cmdsEnd+cmdsize) 窗口归零（真实二进制此处本就是链接器零填充，
    /// 此时契约退化为完全恒等——既有单点 fixture 测的就是该形态）；
    /// 窗口之外的一切字节（含其后填充与全部内容）必须原样保留。
    @Test func injectorRoundTripHoldsAcrossRandomizedVariants() throws {
        var seed: UInt64 = 0x9E3779B97F4A7C15   // SplitMix64，与 fuzz 驱动同族
        func next() -> UInt64 {
            seed &+= 0x9E3779B97F4A7C15
            var z = seed
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }

        for _ in 0..<500 {
            let pathLen = 8 + Int(next() % 90)          // 路径长度 8..97
            let path = "@executable_path/../Frameworks/"
                + String((0..<pathLen).map { _ in Character(UnicodeScalar(UInt8(next() % 26) + UInt8(ascii: "a"))) })
                + ".dylib"
            let size = 0x1000 + Int(next() % 0x8000)    // 镜像 4K..36K
            let floor: Int = 0x400
            let cmdsEnd = 32 + 152                      // 原始命令区末尾（0xB8）

            var data = Data(count: size)
            func put32(_ o: Int, _ v: UInt32) {
                data[o] = UInt8(v & 0xFF); data[o+1] = UInt8((v >> 8) & 0xFF)
                data[o+2] = UInt8((v >> 16) & 0xFF); data[o+3] = UInt8((v >> 24) & 0xFF)
            }
            func put64(_ o: Int, _ v: UInt64) {
                for k in 0..<8 { data[o+k] = UInt8((v >> (8*k)) & 0xFF) }
            }
            func putStr(_ o: Int, _ s: String) {
                data.replaceSubrange(o..<(o+16), with: Data(repeating: 0, count: 16))
                data.replaceSubrange(o..<o+min(16, s.utf8.count), with: s.utf8.prefix(16))
            }
            put32(0, 0xFEEDFACF); put32(4, 0x0100000C); put32(8, 0); put32(12, 2)
            put32(16, 1); put32(20, 152); put32(24, 0); put32(28, 0)
            put32(32, 0x19); put32(36, 152)
            putStr(40, "__TEXT")
            put64(56, 0); put64(64, UInt64(size))
            put64(72, UInt64(floor)); put64(80, UInt64(size - floor))
            put32(88, 7); put32(92, 5); put32(96, 1); put32(100, 0)
            putStr(104, "__text"); putStr(120, "__TEXT")
            put64(136, UInt64(floor)); put64(144, UInt64(size - floor))
            put32(152, UInt32(floor))
            // 头部空闲区随机填充（含非零——比真实链接器零填充更强的扰动）
            for o in cmdsEnd..<floor { data[o] = UInt8(next() & 0xFF) }
            let original = data

            try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: path)
            #expect(MachOInjector.isInjected(data: data, base: 0, path: path))
            let cmdSize = MachOInjector.buildLoadDylibCommand(path: path).count
            try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: path)

            // 契约预言：original 中把 [cmdsEnd, cmdsEnd+cmdSize) 置零后的像
            var expected = original
            for o in cmdsEnd..<min(cmdsEnd + cmdSize, expected.count) { expected[o] = 0 }
            #expect(data == expected,
                    "往返后唯一允许差异 = 临时命令窗口归零（pathLen=\(pathLen), size=\(size), cmdSize=\(cmdSize)）")
            // 命令区本身（含 ncmds/sizeofcmds 头字段）必须完全复原
            #expect(data.prefix(cmdsEnd) == original.prefix(cmdsEnd))
            // 窗口之后的全部字节（填充与内容）必须原样
            #expect(data.suffix(data.count - cmdsEnd - cmdSize)
                    == original.suffix(original.count - cmdsEnd - cmdSize))
        }
    }
}
