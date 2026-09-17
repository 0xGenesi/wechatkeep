import Foundation

/// LC_LOAD_DYLIB injector for the WeChat main executable (runtime feature).
///
/// Safety contract mirrors Patcher: fat-aware (every 64-bit slice), header-space
/// check BEFORE any write (refuses rather than corrupting), backup by caller,
/// remove is the exact inverse of insert.
///
/// Why the main executable and not wechat.dylib: the runtime dylib must load
/// BEFORE the app initializes; injecting into the main binary achieves that,
/// and the main binary is small (fast re-sign) and rarely rebuilt by Tencent
/// compared to the dylib.
enum MachOInjector {
    enum InjectorError: Error, CustomStringConvertible {
        case not64BitMachO
        case no64BitSlice
        case noHeaderSpace(slice: Int, needed: Int, available: Int)
        case loadCommandNotFound(String)
        case alreadyInjected(String)

        var description: String {
            switch self {
            case .not64BitMachO: "not a 64-bit Mach-O"
            case .no64BitSlice: "no 64-bit slice found"
            case .noHeaderSpace(let slice, let needed, let available):
                "slice #\(slice): load command needs \(needed) bytes, only \(available) available"
            case .loadCommandNotFound(let name):
                "LC_LOAD_DYLIB for \(name) not found"
            case .alreadyInjected(let name):
                "\(name) is already injected"
            }
        }
    }

    static let loadDylibCmd: UInt32 = 0xC

    struct SliceInfo {
        let offset: Int          // slice start in file
        let ncmdsOff: Int        // file offset of ncmds field
        let sizeofcmdsOff: Int
        let commandsOff: Int     // file offset of first load command
        var ncmds: UInt32
        var sizeofcmds: UInt32
        let contentFloor: Int    // first byte after the load commands that is real content
    }

    /// Parses one 64-bit slice's header info. `base` = slice start in file.
    static func sliceInfo(in data: Data, base: Int) throws -> SliceInfo {
        guard data.count >= base + 32,
              data.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: base, as: UInt32.self) }) == 0xFEEDFACF
        else { throw InjectorError.not64BitMachO }
        let ncmdsOff = base + 16
        let sizeofcmdsOff = base + 20
        let ncmds = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: ncmdsOff, as: UInt32.self) }
        let sizeofcmds = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sizeofcmdsOff, as: UInt32.self) }
        let commandsOff = base + 32

        // content floor: 段的 fileoff 会覆盖头部自身（__TEXT fileoff=0），
        // 必须取第一个**节**的文件偏移（节头 80B，offset 字段在节内 +40）
        var floor = Int.max
        var cursor = commandsOff
        for _ in 0..<ncmds {
            let cmd = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: UInt32.self) }
            let cmdsize = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self) }
            guard cmdsize >= 8, cursor + Int(cmdsize) <= data.count else { break }
            if cmd == 0x19 {   // LC_SEGMENT_64
                let nsects = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 64, as: UInt32.self) }
                for si in 0..<nsects {
                    let sec = cursor + 72 + Int(si) * 80
                    let size = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sec + 32, as: UInt64.self) }
                    let offset = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sec + 40, as: UInt32.self) }
                    if size > 0, offset > 0 { floor = min(floor, base + Int(offset)) }
                }
            }
            cursor += Int(cmdsize)
        }
        if floor == Int.max { floor = commandsOff + Int(sizeofcmds) }
        return SliceInfo(offset: base, ncmdsOff: ncmdsOff, sizeofcmdsOff: sizeofcmdsOff,
                         commandsOff: commandsOff, ncmds: ncmds, sizeofcmds: sizeofcmds,
                         contentFloor: floor)
    }

    /// 64-bit slices (file offsets) in a thin or fat Mach-O.
    static func slices(in data: Data) throws -> [Int] {
        let magic = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) }
        if magic == 0xBEBAFECA {   // FAT big-endian magic (little-endian read)
            let nfat = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self).byteSwapped }
            var out = [Int]()
            for i in 0..<nfat {
                let e = 8 + Int(i) * 20
                let cputype = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: e, as: UInt32.self).byteSwapped }
                let off = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: e + 8, as: UInt32.self).byteSwapped }
                if cputype & 0x0100_0000 != 0 { out.append(Int(off)) }   // 64-bit arch
            }
            guard !out.isEmpty else { throw InjectorError.no64BitSlice }
            return out
        }
        let is64 = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) } == 0xFEEDFACF
        guard is64 else { throw InjectorError.not64BitMachO }
        return [0]
    }

    static func buildLoadDylibCommand(path: String) -> Data {
        let nameBytes = Array(path.utf8)
        var cmdsize = 24 + nameBytes.count + 1
        cmdsize = (cmdsize + 7) & ~7
        var d = Data()
        var le32: [UInt8] = []
        func put32(_ v: UInt32) { le32 = [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)]; d.append(contentsOf: le32) }
        put32(loadDylibCmd)          // cmd
        put32(UInt32(cmdsize))       // cmdsize
        put32(24)                    // name.offset
        put32(0)                     // timestamp
        put32(0)                     // current_version
        put32(0)                     // compatibility_version
        d.append(contentsOf: nameBytes)
        d.append(contentsOf: [UInt8](repeating: 0, count: cmdsize - d.count))
        return d
    }

    /// True if any LC_LOAD_DYLIB in the slice carries `path`.
    static func isInjected(data: Data, base: Int, path: String) -> Bool {
        let info = try? sliceInfo(in: data, base: base)
        guard let info else { return false }
        var cursor = info.commandsOff
        for _ in 0..<info.ncmds {
            guard cursor + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: UInt32.self) }
            let cmdsize = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self) })
            guard cmdsize >= 24, cursor + cmdsize <= data.count else { break }
            if cmd == loadDylibCmd {
                let nameOff = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 8, as: UInt32.self) })
                let end = cursor + cmdsize
                var nstart = cursor + nameOff
                while nstart < end && data[nstart] == 0 { nstart += 1 }   // 跳过填充零
                let nend = nstart + path.utf8.count
                if nend <= end,
                   Data(data[nstart..<nstart + path.utf8.count]) == Data(path.utf8) {
                    return true
                }
            }
            cursor += cmdsize
        }
        return false
    }

    /// Inserts an LC_LOAD_DYLIB for `dylibInstallPath` into every 64-bit slice.
    static func insertLoadDylib(data: inout Data, dylibInstallPath: String) throws {
        let cmd = buildLoadDylibCommand(path: dylibInstallPath)
        for base in try slices(in: data) {
            let info = try sliceInfo(in: data, base: base)
            if isInjected(data: data.subdata(in: base..<(base + 32 + Int(info.sizeofcmds))),
                          base: 0, path: dylibInstallPath) {
                throw InjectorError.alreadyInjected(dylibInstallPath)
            }
            let available = info.contentFloor - (info.commandsOff + Int(info.sizeofcmds))
            guard available >= cmd.count else {
                throw InjectorError.noHeaderSpace(slice: base, needed: cmd.count, available: available)
            }
            // 新命令追加到加载命令区末尾；ncmds/sizeofcmds 各 +1/+=size
            data.replaceSubrange(info.commandsOff + Int(info.sizeofcmds)..<(info.commandsOff + Int(info.sizeofcmds) + cmd.count), with: cmd)
            let ncmdsOff = info.ncmdsOff
            let ncmds = data.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: ncmdsOff, as: UInt32.self) }) + 1
            data.withUnsafeMutableBytes { $0.storeBytes(of: ncmds, toByteOffset: ncmdsOff, as: UInt32.self) }
            let scOff = info.sizeofcmdsOff
            let sc = data.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: scOff, as: UInt32.self) }) + UInt32(cmd.count)
            data.withUnsafeMutableBytes { $0.storeBytes(of: sc, toByteOffset: scOff, as: UInt32.self) }
        }
    }

    /// Removes the LC_LOAD_DYLIB carrying `dylibInstallPath` from every slice.
    static func removeLoadDylib(data: inout Data, dylibInstallPath: String) throws {
        for base in try slices(in: data) {
            var info = try sliceInfo(in: data, base: base)
            var commands = Data(data[info.commandsOff..<(info.commandsOff + Int(info.sizeofcmds))])
            var found = false
            var cursor = 0
            while cursor + 8 <= commands.count {
                let cmd = commands.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: UInt32.self) }
                let cmdsize = Int(commands.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 4, as: UInt32.self) })
                guard cmdsize >= 24, cursor + cmdsize <= commands.count else { break }
                if cmd == loadDylibCmd {
                    let nameOff = Int(commands.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor + 8, as: UInt32.self) })
                    let nstart = cursor + nameOff
                    let nend = nstart + dylibInstallPath.utf8.count
                    if nend <= cursor + cmdsize,
                       Data(commands[nstart..<nstart + dylibInstallPath.utf8.count]) == Data(dylibInstallPath.utf8) {
                        commands.removeSubrange(cursor..<cursor + cmdsize)
                        found = true
                        continue   // 不前进：后续命令前移补位
                    }
                }
                cursor += cmdsize
            }
            guard found else { continue }
            // 写回：命令区总长不变——移除后尾部补零（保持文件长度与内容偏移不变）
            let freed = Int(info.sizeofcmds) - commands.count
            var padded = commands
            padded.append(contentsOf: Data(repeating: 0, count: freed))
            data.replaceSubrange(info.commandsOff..<(info.commandsOff + Int(info.sizeofcmds)), with: padded)
            data.withUnsafeMutableBytes { raw in
                raw.storeBytes(of: info.ncmds - 1, toByteOffset: info.ncmdsOff, as: UInt32.self)
                raw.storeBytes(of: UInt32(commands.count), toByteOffset: info.sizeofcmdsOff, as: UInt32.self)
            }
        }
    }
}
