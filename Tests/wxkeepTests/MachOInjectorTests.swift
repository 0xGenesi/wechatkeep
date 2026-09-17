import Foundation
import Testing
@testable import wxkeep

/// LC_LOAD_DYLIB 注入器：插入/移除往返、头空间检查、重复注入拒绝。
struct MachOInjectorTests {
    /// 构造带头空间的可执行 fixture：header(32) + LC_SEGMENT_64(152，含 1 节)
    /// 节 offset = 0x400（content floor），头部可用空间 = 0x400 - 184。
    private func makeExecutable(size: Int = 0x1000) -> Data {
        var d = Data(count: size)
        func put32(_ o: Int, _ v: UInt32) {
            d[o] = UInt8(v & 0xFF); d[o+1] = UInt8((v >> 8) & 0xFF)
            d[o+2] = UInt8((v >> 16) & 0xFF); d[o+3] = UInt8((v >> 24) & 0xFF)
        }
        func put64(_ o: Int, _ v: UInt64) {
            for k in 0..<8 { d[o+k] = UInt8((v >> (8*k)) & 0xFF) }
        }
        func putStr(_ o: Int, _ s: String) {
            d.replaceSubrange(o..<(o+16), with: Data(repeating: 0, count: 16))
            d.replaceSubrange(o..<o+min(16, s.utf8.count), with: s.utf8.prefix(16))
        }
        // mach_header_64
        put32(0, 0xFEEDFACF); put32(4, 0x01000007); put32(8, 0); put32(12, 2)
        put32(16, 1); put32(20, 152); put32(24, 0); put32(28, 0)
        // LC_SEGMENT_64 @32（cmdsize 152 = 段头 72 + 1 节 80）
        put32(32, 0x19); put32(36, 152)
        putStr(40, "__TEXT")
        put64(56, 0); put64(64, UInt64(size))      // vmaddr / vmsize
        put64(72, 0x400); put64(80, UInt64(size - 0x400))  // fileoff / filesize
        put32(88, 7); put32(92, 5); put32(96, 1); put32(100, 0)
        // section_64 @104
        putStr(104, "__text"); putStr(120, "__TEXT")
        put64(136, 0x400); put64(144, UInt64(size - 0x400))  // addr / size
        put32(152, 0x400)                          // 节 offset = content floor
        // 0x184..0x400 头部空闲填充；0x400 起内容
        d[0x400] = 0xC3
        return d
    }

    @Test func insertRemoveRoundTrip() throws {
        var data = makeExecutable()
        let original = data
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: "@executable_path/../Frameworks/wxkeep_runtime.dylib")
        #expect(MachOInjector.isInjected(data: data, base: 0, path: "@executable_path/../Frameworks/wxkeep_runtime.dylib"))
        try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: "@executable_path/../Frameworks/wxkeep_runtime.dylib")
        #expect(data == original, "移除后应与原始字节一致")
    }

    @Test func doubleInsertRefused() throws {
        var data = makeExecutable()
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: "@executable_path/../Frameworks/wxkeep_runtime.dylib")
        #expect(throws: MachOInjector.InjectorError.self) {
            try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: "@executable_path/../Frameworks/wxkeep_runtime.dylib")
        }
    }

    @Test func isInjectedFalseOnCleanBinary() throws {
        #expect(!MachOInjector.isInjected(data: makeExecutable(), base: 0, path: "@x/y.dylib"))
    }

    @Test func noHeaderSpaceRefused() throws {
        // 节 offset=0 → content floor=0 → 头部无空间 → 拒绝而非破坏
        var d = Data(count: 0x1000)
        func put32(_ o: Int, _ v: UInt32) {
            d[o] = UInt8(v & 0xFF); d[o+1] = UInt8((v >> 8) & 0xFF)
            d[o+2] = UInt8((v >> 16) & 0xFF); d[o+3] = UInt8((v >> 24) & 0xFF)
        }
        func put64(_ o: Int, _ v: UInt64) {
            for k in 0..<8 { d[o+k] = UInt8((v >> (8*k)) & 0xFF) }
        }
        put32(0, 0xFEEDFACF); put32(4, 0x01000007); put32(12, 2)
        put32(16, 1); put32(20, 152)
        put32(32, 0x19); put32(36, 152)
        put64(56, 0); put64(64, 0x1000)
        put64(72, 0); put64(80, 0x1000)
        put32(96, 1)                                // 1 节，节 offset=0 → floor=0
        put32(152, 0)
        #expect(throws: MachOInjector.InjectorError.self) {
            try MachOInjector.insertLoadDylib(data: &d, dylibInstallPath: "@x/y.dylib")
        }
    }
}
