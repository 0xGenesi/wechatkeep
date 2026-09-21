import Foundation

/// Applies byte patches to a (possibly fat) Mach-O with a hard safety contract:
///
/// 1. Every entry is planned (arch → slice) and its **current bytes are read**
///    before anything is written.
/// 2. If any entry is not "already patched" and not acceptable, **nothing is
///    written at all** — no half-applied targets (the failure mode observed in
///    predecessor projects).
/// 3. Entries without `expected` are quarantined: refused unless the caller
///    explicitly opts in, and never restorable.
struct Patcher {
    // MARK: - Errors

    enum PatchError: Error, CustomStringConvertible {
        case not64BitMachO
        case noArchMatched
        case recipeResolutionFailed(identifier: String, cause: String)
        case vaNotFound(va: UInt64, arch: String)
        case missingExpected(index: Int, identifier: String)
        case expectedMismatch(index: Int, identifier: String, va: UInt64, expected: [String], current: String)

        var description: String {
            switch self {
            case .not64BitMachO:
                "not a 64-bit Mach-O file"
            case .noArchMatched:
                "no patch entry matched an architecture slice in this binary"
            case .recipeResolutionFailed(let identifier, let cause):
                "recipe for \(identifier) failed to resolve a site: \(cause). "
                + "A new signature generation needs human analysis (docs/MAINTAINING.md)."
            case .vaNotFound(let va, let arch):
                String(format: "VA 0x%X (%@) does not fall inside any segment of its slice", va, arch)
            case .missingExpected(let i, let id):
                "entry #\(i) (target \(id)) has no `expected` bytes — quarantined. "
                + "It cannot be safety-checked nor restored; refusing to write. "
                + "Override with --allow-unverified only if you know why it lacks provenance."
            case .expectedMismatch(let i, let id, let va, let expected, let current):
                "entry #\(i) (target \(id)) at VA 0x\(String(format: "%X", va)): bytes on disk are "
                + "\(current), expected one of \(expected.joined(separator: " / ")) — "
                + "wrong WeChat build or unknown prior modification. Nothing was written."
            }
        }
    }

    // MARK: - Results

    enum EntryOutcome: Equatable {
        case written
        case alreadyPatched
    }

    struct Inspection: Equatable {
        let arch: Config.Arch
        let va: UInt64
        /// patched (bytes == asm) / pristine (matches an expected variant) /
        /// ambiguous (normalized entry: bytes match BOTH — patched and pristine
        /// are byte-identical, so the state must be resolved by the target's
        /// other entries) / unknown
        let state: State
        let current: String

        enum State: Equatable { case patched, pristine, ambiguous, unknown }
    }

    // MARK: - Entry points

    /// Patch `entries` into `binary`. See the type doc for the safety contract.
    /// Returns one outcome per entry, in input order.
    static func patch(
        binary: URL,
        entries: [Config.PatchEntry],
        identifier: String,
        dryRun: Bool = false,
        allowUnverified: Bool = false
    ) throws -> [EntryOutcome] {
        guard !entries.isEmpty else { throw PatchError.noArchMatched }
        // Dry runs must not require write access (root-owned bundles).
        let handle = dryRun ? try FileHandle(forReadingFrom: binary) : try FileHandle(forUpdating: binary)
        defer { try? handle.close() }

        let plans = try buildPlans(handle: handle, entries: resolveRecipes(entries, binary: binary),
                                   identifier: identifier)

        // Phase 1 — read & verify everything before the first write.
        // Site length = max(asm, expected variants): asm and the accepted
        // original bytes may differ in length (restore inversion, upstream
        // entries), so comparisons are prefix-based at the longer length.
        var outcomes = [EntryOutcome]()
        var writes = [(offset: UInt64, data: Data)]()
        for (index, plan) in plans.enumerated() {
            let siteLen = max(plan.asm.count, plan.expected?.map(\.byteCount).max() ?? 0)
            let current = try readBytes(handle: handle, offset: plan.fileOffset, count: siteLen)
            if current.prefix(plan.asm.count) == plan.asm {
                outcomes.append(.alreadyPatched)
                continue
            }
            guard let variants = plan.expected, !variants.isEmpty else {
                if allowUnverified {
                    outcomes.append(.written)
                    writes.append((plan.fileOffset, plan.asm))
                    continue
                }
                throw PatchError.missingExpected(index: index, identifier: identifier)
            }
            guard variants.contains(where: { $0.matches(current) }) else {
                throw PatchError.expectedMismatch(
                    index: index, identifier: identifier, va: plan.va,
                    expected: variants.map(\.spec), current: current.hexUppercase)
            }
            outcomes.append(.written)
            writes.append((plan.fileOffset, plan.asm))
        }
        guard !dryRun else { return outcomes }

        // Phase 2 — every entry verified; write them all.
        for write in writes {
            try handle.seek(toOffset: write.offset)
            try handle.write(contentsOf: write.data)
        }
        return outcomes
    }

    /// Read-only twin of `patch`: reports the current state at every entry.
    static func inspect(binary: URL, entries: [Config.PatchEntry], identifier: String) throws -> [Inspection] {
        guard !entries.isEmpty else { throw PatchError.noArchMatched }
        let handle = try FileHandle(forReadingFrom: binary)
        defer { try? handle.close() }

        let plans = try buildPlans(handle: handle, entries: try resolveRecipes(entries, binary: binary),
                                   identifier: identifier)
        return try plans.map { plan in
            let siteLen = max(plan.asm.count, plan.expected?.map(\.byteCount).max() ?? 0)
            let current = try readBytes(handle: handle, offset: plan.fileOffset, count: siteLen)
            let asmMatch = current.prefix(plan.asm.count) == plan.asm
            let expectedMatch = plan.expected?.contains(where: { $0.matches(current) }) == true
            let state: Inspection.State
            // Checking asm first used to misread normalized entries (asm ∈
            // expected, e.g. keeptip's prologue-restore at the isRevokemsg
            // entry) as patched even on a pristine binary — reporting the
            // ambiguity lets callers resolve it from sibling entries.
            if asmMatch && expectedMatch { state = .ambiguous }
            else if asmMatch { state = .patched }
            else if expectedMatch { state = .pristine }
            else { state = .unknown }
            return Inspection(arch: plan.entry.arch, va: plan.va, state: state, current: current.hexUppercase)
        }
    }

    // MARK: - Recipe resolution

    /// Recipe entries carry a locator instead of an addr; resolve them to a
    /// concrete VA now. The expected-byte gate downstream is unchanged — a
    /// recipe only decides WHERE, never whether it is safe to write.
    static func resolveRecipes(_ entries: [Config.PatchEntry], binary: URL, identifier: String = "<target>") throws -> [Config.PatchEntry] {
        try entries.map { entry in
            guard entry.addr == nil, let dict = entry.recipe else { return entry }
            do {
                let recipe = try RecipeEngine.Recipe(dict: dict)
                let image = try MachImage(file: binary, arch: entry.arch)
                let va = try RecipeEngine.resolve(recipe: recipe, image: image, arch: entry.arch)
                var copy = entry
                copy.addr = String(va, radix: 16)
                return copy
            } catch {
                // Surface the real cause (ambiguous anchors / new signature
                // generation / missing slice) — degrading to noArchMatched
                // would send the user hunting the wrong problem.
                throw PatchError.recipeResolutionFailed(identifier: identifier, cause: String(describing: error))
            }
        }
    }

    // MARK: - Internals

    private struct Plan {
        let entry: Config.PatchEntry
        let va: UInt64
        let asm: Data
        let expected: [ExpectedPattern]?
        let fileOffset: UInt64
    }

    private static func buildPlans(
        handle: FileHandle, entries: [Config.PatchEntry], identifier: String
    ) throws -> [Plan] {
        let slices = try slices(of: handle)
        var plans = [Plan]()
        for entry in entries {
            guard let slice = slices.first(where: { $0.cputype == entry.arch.cpuType }) else { continue }
            guard let addrHex = entry.addr, let va = UInt64(addrHex, radix: 16) else { continue } // recipe entries: M2
            let fileOffset = try resolveVA(va: va, handle: handle, sliceOffset: slice.offset, arch: entry.arch)
            let asm = Data(hex: entry.asm)!
            let expected = entry.expected?.values.compactMap { ExpectedPattern(spec: $0) }
            plans.append(Plan(entry: entry, va: va, asm: asm, expected: expected, fileOffset: fileOffset))
        }
        guard !plans.isEmpty else { throw PatchError.noArchMatched }
        return plans
    }

    /// (cputype, slice file offset) for every slice: fat → each fat_arch (big-endian),
    /// thin → the whole file. Fat headers are always big-endian on disk.
    private static func slices(of handle: FileHandle) throws -> [(cputype: Int32, offset: UInt64)] {
        try handle.seek(toOffset: 0)
        guard let header = try handle.read(upToCount: 8), header.count == 8 else {
            throw PatchError.not64BitMachO
        }
        let magicBE = header.prefix(4).reduce(0) { ($0 << 8) | UInt32($1) }
        if magicBE == 0xCAFEBABE {
            let nfat = header.suffix(4).reduce(0) { ($0 << 8) | UInt32($1) }
            var out: [(Int32, UInt64)] = []
            var offset: UInt64 = 8
            for _ in 0..<nfat {
                try handle.seek(toOffset: offset)
                guard let arch = try handle.read(upToCount: 20), arch.count == 20 else {
                    throw PatchError.not64BitMachO
                }
                let fields = stride(from: 0, to: 20, by: 4).map { i in
                    arch.subdata(in: i..<i+4).reduce(0) { ($0 << 8) | UInt32($1) }
                }
                let cputype = Int32(bitPattern: fields[0])
                let sliceOffset = UInt64(fields[2])
                out.append((cputype, sliceOffset))
                offset += 20
            }
            return out
        }
        // Thin: mach_header_64 magic (little-endian) + cputype at offset 4.
        guard header.withUnsafeBytes({ $0.loadUnaligned(fromByteOffset: 0, as: UInt32.self) }) == 0xFEEDFACF
        else { throw PatchError.not64BitMachO }
        let cputype = header.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: Int32.self) }
        return [(cputype, 0)]
    }

    /// VA → absolute file offset by walking LC_SEGMENT_64 inside the slice.
    private static func resolveVA(
        va: UInt64, handle: FileHandle, sliceOffset: UInt64, arch: Config.Arch
    ) throws -> UInt64 {
        try handle.seek(toOffset: sliceOffset)
        guard let header = try handle.read(upToCount: 32), header.count == 32 else {
            throw PatchError.not64BitMachO
        }
        let ncmds = header.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) }
        var cursor = sliceOffset + 32
        for _ in 0..<ncmds {
            try handle.seek(toOffset: cursor)
            guard let cmdHeader = try handle.read(upToCount: 8), cmdHeader.count == 8 else {
                throw PatchError.not64BitMachO
            }
            let (cmd, cmdsize) = cmdHeader.withUnsafeBytes {
                ($0.loadUnaligned(fromByteOffset: 0, as: UInt32.self),
                 $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
            }
            if cmd == 0x19 { // LC_SEGMENT_64
                try handle.seek(toOffset: cursor + 24)
                guard let seg = try handle.read(upToCount: 40), seg.count == 40 else {
                    throw PatchError.not64BitMachO
                }
                let fields = seg.withUnsafeBytes { raw -> (UInt64, UInt64, UInt64) in
                    (raw.loadUnaligned(fromByteOffset: 0, as: UInt64.self),   // vmaddr
                     raw.loadUnaligned(fromByteOffset: 8, as: UInt64.self),   // vmsize
                     raw.loadUnaligned(fromByteOffset: 16, as: UInt64.self))  // fileoff
                }
                if va >= fields.0 && va < fields.0 + fields.1 {
                    return sliceOffset + fields.2 + (va - fields.0)
                }
            }
            cursor += UInt64(cmdsize)
        }
        throw PatchError.vaNotFound(va: va, arch: arch.rawValue)
    }

    private static func readBytes(handle: FileHandle, offset: UInt64, count: Int) throws -> Data {
        try handle.seek(toOffset: offset)
        guard let data = try handle.read(upToCount: count), data.count == count else {
            throw PatchError.not64BitMachO
        }
        return data
    }
}
