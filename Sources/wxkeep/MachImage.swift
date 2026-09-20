import Foundation

/// Read-only Mach-O image access for locator recipes: slice extraction,
/// section lookup, byte search. VA == slice-relative file offset is NOT
/// assumed here; all VA↔offset math goes through segments.
struct MachImage {
    struct Section {
        let name: String
        let segment: String
        let addr: UInt64
        let size: UInt64
        let offset: Int
    }

    enum ImageError: Error, CustomStringConvertible {
        case notMachO
        case noSlice(arch: String)
        case noSection(String)

        var description: String {
            switch self {
            case .notMachO: return "not a 64-bit Mach-O"
            case .noSlice(let arch): return "no \(arch) slice in this fat file"
            case .noSection(let name): return "section __TEXT,\(name) not found"
            }
        }
    }

    let data: Data
    let sliceOffset: Int
    let cputype: Int32
    let segments: [(vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64)]
    let sections: [Section]

    /// Extracts the slice for `arch` from a fat file (or uses the whole thin file).
    init(file url: URL, arch: Config.Arch) throws {
        let raw = try Data(contentsOf: url)
        guard raw.count >= 8 else { throw ImageError.notMachO }
        let magicBE = raw.prefix(4).reduce(0) { ($0 << 8) | UInt32($1) }
        if magicBE == 0xCAFEBABE {
            let nfat = raw.subdata(in: 4..<8).reduce(0) { ($0 << 8) | UInt32($1) }
            var chosen: (offset: Int, cputype: Int32)?
            var cursor = 8
            for _ in 0..<nfat {
                guard cursor + 20 <= raw.count else { throw ImageError.notMachO }
                let archBytes = raw.subdata(in: cursor..<cursor + 20)
                let cputype = Int32(bitPattern:
                    (0..<4).reduce(UInt32(0)) { ($0 << 8) | UInt32(archBytes[$1]) })
                // fat_arch: cputype@0 cpusubtype@4 offset@8 size@12 align@16
                let sliceOff = (8..<12).reduce(UInt32(0)) { ($0 << 8) | UInt32(archBytes[$1]) }
                if cputype == arch.cpuType {
                    chosen = (Int(sliceOff), cputype)
                    break
                }
                cursor += 20
            }
            guard let pick = chosen else { throw ImageError.noSlice(arch: arch.rawValue) }
            let end = raw.count
            self.init(slice: raw.subdata(in: pick.offset..<end), sliceOffset: pick.offset,
                      cputype: pick.cputype)
        } else {
            guard raw.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) }) == 0xFEEDFACF
            else { throw ImageError.notMachO }
            let cputype = raw.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: Int32.self) }
            self.init(slice: raw, sliceOffset: 0, cputype: cputype)
        }
    }

    private init(slice: Data, sliceOffset: Int, cputype: Int32) {
        self.data = slice
        self.sliceOffset = sliceOffset
        self.cputype = cputype
        var segs: [(UInt64, UInt64, UInt64)] = []
        var secs: [Section] = []
        let ncmds = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) }
        var p = 32
        for _ in 0..<ncmds {
            guard p + 8 <= data.count else { break }
            let cmd = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p, as: UInt32.self) }
            let cmdsize = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self) })
            guard cmdsize > 0, p + cmdsize <= data.count else { break }
            if cmd == 0x19 {
                guard p + 72 <= data.count else { break }
                let segname = String(bytes: data.subdata(in: (p+8)..<(p+24)).prefix(while: { $0 != 0 }), encoding: .ascii) ?? ""
                let vmaddr = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p + 24, as: UInt64.self) }
                let vmsize = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p + 32, as: UInt64.self) }
                let fileoff = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p + 40, as: UInt64.self) }
                segs.append((vmaddr, vmsize, fileoff))
                let nsects = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: p + 64, as: UInt32.self) })
                var sp = p + 72
                for _ in 0..<nsects {
                    guard sp + 80 <= data.count else { break }
                    let sname = String(bytes: data.subdata(in: sp..<(sp+16)).prefix(while: { $0 != 0 }), encoding: .ascii) ?? ""
                    let saddr = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sp + 32, as: UInt64.self) }
                    let ssize = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sp + 40, as: UInt64.self) }
                    let soff = Int(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: sp + 48, as: UInt32.self) })
                    secs.append(Section(name: sname, segment: segname, addr: saddr, size: ssize, offset: soff))
                    sp += 80
                }
            }
            p += cmdsize
        }
        self.segments = segs
        self.sections = secs
    }

    func section(_ name: String) throws -> Section {
        guard let s = sections.first(where: { $0.name == name && $0.segment == "__TEXT" })
            ?? sections.first(where: { $0.name == name }) else {
            throw ImageError.noSection(name)
        }
        return s
    }

    /// VA → offset relative to the START of the slice (not the fat file).
    func sliceRelativeOffset(va: UInt64) -> Int? {
        for seg in segments where va >= seg.vmaddr && va < seg.vmaddr + seg.vmsize {
            return Int(seg.fileoff) + Int(va - seg.vmaddr)
        }
        return nil
    }

    func bytes(va: UInt64, count: Int) -> Data? {
        guard let o = sliceRelativeOffset(va: va), o + count <= data.count else { return nil }
        return data.subdata(in: o..<o + count)
    }

    /// VA 处 4 字节按小端组装（段表换算；越界返回 nil）。arm64 指令反解用。
    func word32(va: UInt64) -> UInt32? {
        guard let b = bytes(va: va, count: 4) else { return nil }
        var v: UInt32 = 0
        for (i, byte) in b.enumerated() { v |= UInt32(byte) << (8 * i) }
        return v
    }

    /// All offsets (slice-relative) where `pattern` occurs inside `section`.
    func offsets(of pattern: Data, in sectionName: String) throws -> [Int] {
        let s = try section(sectionName)
        let start = s.offset
        let end = min(start + Int(s.size), data.count)
        var out: [Int] = []
        var searchStart = start
        while searchStart + pattern.count <= end {
            guard let r = data.range(of: pattern, options: [], in: searchStart..<end) else { break }
            out.append(r.lowerBound)
            searchStart = r.lowerBound + 1
        }
        return out
    }
}
