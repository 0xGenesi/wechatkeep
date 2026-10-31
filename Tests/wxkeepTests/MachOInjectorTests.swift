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

    @Test func doubleInsertIsIdempotent() throws {
        var data = makeExecutable()
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        let once = data
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        #expect(data == once, "重复 install 应为 no-op")
        #expect(MachOInjector.isInjected(data: data, base: 0, path: cmd))
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

    // MARK: - 2026-09-18 事故回归：小命令必须不阻断遍历

    /// 真实主程序在注入 LC 之前有 LC_SOURCE_VERSION（16B）——旧 remove 的
    /// `cmdsize >= 24 else break` 让遍历提前中断 → remove 假成功 → 删 dylib
    /// 文件后启动必崩。本测试用带 SOURCE_VERSION 的夹具锁死该场景。
    private func makeExecutableWithSourceVersion() -> Data {
        var d = makeExecutable()
        func put32(_ o: Int, _ v: UInt32) {
            d[o] = UInt8(v & 0xFF); d[o+1] = UInt8((v >> 8) & 0xFF)
            d[o+2] = UInt8((v >> 16) & 0xFF); d[o+3] = UInt8((v >> 24) & 0xFF)
        }
        // LC_SOURCE_VERSION @184（cmd=0x32, cmdsize=16），追加在 SEG 之后
        put32(184, 0x32); put32(188, 16)
        put32(16, 2)                       // ncmds: 1 → 2
        put32(20, 152 + 16)                // sizeofcmds: 152 → 168
        return d
    }

    @Test func removeWithSourceVersionBeforeInjectRoundTrip() throws {
        var data = makeExecutableWithSourceVersion()
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        #expect(MachOInjector.isInjected(data: data, base: 0, path: cmd))
        try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: cmd)
        #expect(!MachOInjector.isInjected(data: data, base: 0, path: cmd),
                "SOURCE_VERSION 不得阻断 remove 遍历（2026-09-18 事故回归）")
    }

    /// remove 在没有任何匹配 LC 时必须抛错（CLI 依赖此信号中止删 dylib 文件）
    @Test func removeWithoutInjectThrows() {
        #expect(throws: MachOInjector.InjectorError.self) {
            var data = makeExecutableWithSourceVersion()
            try MachOInjector.removeLoadDylib(data: &data,
                                              dylibInstallPath: "@x/y.dylib")
        }
    }

    /// 同切片两条同路径 LC_LOAD_DYLIB（历史事故态）：remove 全清且
    /// ncmds/sizeofcmds 保持自洽——多删一报 = dyld 解析补零区 = 启动炸。
    @Test func removeDoubleLoadCommandsKeepsHeaderConsistent() throws {
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        var data = makeExecutable()
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        // 手工复制第二条（真实事故 = 历史版本重复注入残留）
        let cmdsize = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 188, as: UInt32.self) })
        let first = Data(data[184..<(184 + cmdsize)])
        data.replaceSubrange((184 + cmdsize)..<(184 + cmdsize + cmdsize), with: first)
        data.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32(3), toByteOffset: 16, as: UInt32.self)            // ncmds 2→3
            raw.storeBytes(of: UInt32(152 + 2 * cmdsize), toByteOffset: 20, as: UInt32.self)
        }
        #expect(MachOInjector.isInjected(data: data, base: 0, path: cmd))
        try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: cmd)
        #expect(!MachOInjector.isInjected(data: data, base: 0, path: cmd),
                "两条都要清掉")
        // 头自洽：按 ncmds 遍历应精确走完 sizeofcmds（多删少报 = 遍历踩进
        // 补零区，dyld 同款语义）
        let ncmds = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) }
        let sizeofcmds = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self) })
        var cursor = 32
        var walked = 0
        for _ in 0..<ncmds {
            let size = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self) })
            #expect(size >= 8)
            cursor += size
            walked += size
        }
        #expect(walked == sizeofcmds, "命令区走完应恰为 sizeofcmds（ncmds 与实删数自洽）")
    }

    /// 巨型命令区（>0x10000）：注入命令落在尾部时 isInjectedAnySlice 仍必须
    /// 可见——固定 0x10000 窗会让 install 后置守卫假回滚、doctor 误报未注入。
    @Test func isInjectedAnySliceSeesPast64KWindow() throws {
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        var big = makeExecutable(size: 0x21000)
        // 节 offset 抬到 0x20000 → 头部合法空间 >128KB
        big.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32(0x20000), toByteOffset: 152, as: UInt32.self)
        }
        // 4096 条 LC_SOURCE_VERSION（16B）把命令区撑过 0x10000
        var off = 184
        for _ in 0..<4096 {
            big.withUnsafeMutableBytes { raw in
                raw.storeBytes(of: UInt32(0x32), toByteOffset: off, as: UInt32.self)
                raw.storeBytes(of: UInt32(16), toByteOffset: off + 4, as: UInt32.self)
            }
            off += 16
        }
        big.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32(1 + 4096), toByteOffset: 16, as: UInt32.self)
            raw.storeBytes(of: UInt32(152 + 4096 * 16), toByteOffset: 20, as: UInt32.self)
        }
        try MachOInjector.insertLoadDylib(data: &big, dylibInstallPath: cmd)
        // 注入位 = 32 + sizeofcmds ≈ 0x100B8 > 0x10000
        #expect(MachOInjector.isInjectedAnySlice(data: big, path: cmd),
                "命令区 >0x10000 时注入命令在尾部仍必须可见")
    }
}

// MARK: - 102 轮：病态头的写侧干净拒绝（读侧钳位的写侧对偶）

struct MachOInjectorHardeningTests {
    /// 复用 MachOInjectorTests 的 fixture 构造（同文件包内可见——独立
    /// struct 需要 @testable 访问；直接复制保持两套件独立）。
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
        put32(0, 0xFEEDFACF); put32(4, 0x01000007); put32(8, 0); put32(12, 2)
        put32(16, 1); put32(20, 152); put32(24, 0); put32(28, 0)
        put32(32, 0x19); put32(36, 152)
        putStr(40, "__TEXT")
        put64(56, 0); put64(64, UInt64(size))
        put64(72, 0x400); put64(80, UInt64(size - 0x400))
        put32(88, 7); put32(92, 5); put32(96, 1); put32(100, 0)
        putStr(104, "__text"); putStr(120, "__TEXT")
        put64(136, 0x400); put64(144, UInt64(size - 0x400))
        put32(152, 0x400)
        d[0x400] = 0xC3
        return d
    }

    /// ncmds=0 + 匹配 LC 在场：removals(1) > ncmds(0) 的减法此前是
    /// UInt32 下溢 trap；现在必须是干净拒绝。
    @Test func removeWithZeroNcmdsThrowsInsteadOfTrapping() throws {
        var data = makeExecutable()
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        data.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32(0), toByteOffset: 16, as: UInt32.self)   // ncmds=0
        }
        var caught: MachOInjector.InjectorError?
        do { try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: cmd) }
        catch let e as MachOInjector.InjectorError { caught = e }
        var malformed = false
        if case .malformedHeader? = caught { malformed = true }
        #expect(malformed, "expected malformedHeader, got \(String(describing: caught))")
    }

    /// sizeofcmds 越过文件尾 + 匹配 LC 在场：写回按文件尾钳位——不再
    /// replaceSubrange 越界 precondition 崩溃；文件长度恒不变。
    @Test func removeWithOversizedSizeofcmdsDoesNotCrash() throws {
        var data = makeExecutable()
        let cmd = "@executable_path/../Frameworks/wxkeep_runtime.dylib"
        try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: cmd)
        let before = data.count
        data.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32(0x00FFFFFF), toByteOffset: 20, as: UInt32.self)
        }
        // 不崩溃即通过（成功或干净拒绝均可）；长度不变是硬断言。
        do { try MachOInjector.removeLoadDylib(data: &data, dylibInstallPath: cmd) } catch {}
        #expect(data.count == before, "移除路径永不改变文件长度")
    }

    /// insert 侧：ncmds=0xFFFFFFFF 病态值 +1 此前上溢 trap；先校验后写。
    @Test func insertWithSaturatedNcmdsThrowsInsteadOfTrapping() throws {
        var data = makeExecutable()
        data.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt32.max, toByteOffset: 16, as: UInt32.self)
        }
        var caught: MachOInjector.InjectorError?
        do { try MachOInjector.insertLoadDylib(data: &data, dylibInstallPath: "@x/y.dylib") }
        catch let e as MachOInjector.InjectorError { caught = e }
        var malformed = false
        if case .malformedHeader? = caught { malformed = true }
        #expect(malformed, "expected malformedHeader, got \(String(describing: caught))")
    }
}
