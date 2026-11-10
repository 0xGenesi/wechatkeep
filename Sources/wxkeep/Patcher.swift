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
        case fat64Unsupported
        case noArchMatched
        case recipeResolutionFailed(identifier: String, cause: String)
        case vaNotFound(va: UInt64, arch: String)
        case missingExpected(index: Int, identifier: String)
        case expectedMismatch(index: Int, identifier: String, va: UInt64, expected: [String], current: String)
        case malformedAsm(index: Int, identifier: String, asm: String)
        case malformedExpected(index: Int, identifier: String, spec: String)
        case overlappingEntries(first: Int, second: Int, va: UInt64, identifier: String)

        var description: String {
            switch self {
            case .not64BitMachO:
                "not a 64-bit Mach-O file"
            case .fat64Unsupported:
                "FAT_MAGIC_64 (0xCAFEBABF) fat header is not supported — "
                + "current WeChat binaries are FAT32 or thin; refusing to guess layout"
            case .noArchMatched:
                "no patch entry matched an architecture slice in this binary"
            case .recipeResolutionFailed(let identifier, let cause):
                "recipe for \(identifier) failed to resolve a site: \(cause). "
                + "A new signature generation needs human analysis (docs/MAINTAINING.md)."
            case .vaNotFound(let va, let arch):
                String(format: "VA 0x%X (%@) does not fall inside any segment of its slice", va, arch)
            case .overlappingEntries(let first, let second, let va, let id):
                String(format: "entries #%d and #%d (target %@) map to the same file offset (VA 0x%X) — overlapping patch data is refused", first, second, id, va)
            case .missingExpected(let i, let id):
                "entry #\(i) (target \(id)) has no `expected` bytes — quarantined. "
                + "It cannot be safety-checked nor restored; refusing to write. "
                + "Override with --allow-unverified only if you know why it lacks provenance."
            case .expectedMismatch(let i, let id, let va, let expected, let current):
                "entry #\(i) (target \(id)) at VA 0x\(String(format: "%X", va)): bytes on disk are "
                + "\(current), expected one of \(expected.joined(separator: " / ")) — "
                + "wrong WeChat build or unknown prior modification. Nothing was written."
            case .malformedAsm(let i, let id, let asm):
                "entry #\(i) (target \(id)) has bad hex asm \"\(asm)\" — refusing. "
                + "Catalog/recipe data failed load-time validation? Please report this."
            case .malformedExpected(let i, let id, let spec):
                "entry #\(i) (target \(id)) has unparseable expected spec \"\(spec)\" — refusing. "
                + "Bad specs previously fell out of the variant set silently (compactMap), "
                + "narrowing the write gate with no diagnostic pointer; now a clean rejection."
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

#if DEBUG
    /// 写故障注入缝（126 轮遗留⑦）：Phase-2 写循环第 index 条写入**前**注入
    /// 错误——fail-at(k) 语义 = 前 k 条已落盘（EIO/ENOSPC 形中途写失败的
    /// 可控复现）。M08 十四轮不可测的根因就是无此缝（恢复重签决策链的
    /// 行为面在测试进程内不可达）。**URL 限定**：swift-testing 并行跑套件，
    /// 进程全局缝会误伤并发用例——注入器只对目标二进制路径生效。DEBUG-only
    ///（生产零缝）；用例 defer 复位。
    static nonisolated(unsafe) var debugWriteFailureAt: ((URL, Int) -> Error?)?

    /// 非合作崩溃缝（V7-DEPTH D20/R20，134 轮）：与 fail-at(k) 同位点、
    /// **同位点自毙**——`kill(getpid(), SIGKILL)`，零栈展开（throw 式注入会
    /// 走 unwind，defer/清理路径照常执行——那是「引擎优雅处理错误」，不是
    /// 「断电后盘面合法」；两个故障模型，SQLite 崩溃测试机械的分工）。测试
    /// 以子进程真跑 CLI 时经环境变量武装：**双钥匙**（WXKEEP_KILL_AT=位点序
    /// 号 + WXKEEP_KILL_BIN=目标二进制绝对路径），任一不匹配不触发——防误
    /// 武装真实补丁。
    /// 位点序号语义与 L10 fail-at(k) 对齐 = **跨 Patcher.patch 调用的写序号**
    /// （引擎按 target 分多次调用，每调内 index 从 0 起——按闭包调用次数计
    /// 数，CrashMatrixTests 同款）。kill 在单写 syscall 边界生效（内核完成
    /// 当前小写入），单写内部撕裂不在此模型（归 APFS/硬件层，V6 §6 已登记
    /// 同类边界）。DEBUG-only，未设环境变量时零行为差。
    nonisolated(unsafe) static var debugKillWriteCounters: [String: Int] = [:]
    static func debugKillAtWriteSite(_ binary: URL, _ index: Int) {
        _ = index   // 单调词内序号不作门（跨调用计数才与 L10 的 k 同义）
        guard ProcessInfo.processInfo.environment["WXKEEP_KILL_AT"] != nil,
              let bin = ProcessInfo.processInfo.environment["WXKEEP_KILL_BIN"],
              bin == binary.standardizedFileURL.path
        else { return }
        let path = binary.standardizedFileURL.path
        debugKillWriteCounters[path, default: 0] += 1
        if let want = ProcessInfo.processInfo.environment["WXKEEP_KILL_AT"],
           String(debugKillWriteCounters[path]!) == want {
            kill(getpid(), SIGKILL)
        }
    }
#endif

    /// per-site 审计数据（125 轮 V5 深度轮）：被覆写的字节与出处。Phase-1
    /// 规划期收集，Phase-2 写入全部成功后才经 auditSink 交付——账目只反映
    /// 已落盘的写入（dry-run / 写前失败不产生账目）。
    struct SiteAudit {
        let arch: Config.Arch
        let va: UInt64
        let before: Data   // 被替换的实读字节（asm 跨度）
        let after: Data    // 写入的 asm 字节
        let identifier: String
        let source: String?
    }

    /// Patch `entries` into `binary`. See the type doc for the safety contract.
    /// Returns one outcome per entry, in input order.
    static func patch(
        binary: URL,
        entries: [Config.PatchEntry],
        identifier: String,
        dryRun: Bool = false,
        allowUnverified: Bool = false,
        auditSink: ((SiteAudit) -> Void)? = nil
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
        var audits = [SiteAudit]()
        for (index, plan) in plans.enumerated() {
            let siteLen = max(plan.asm.count, plan.expected?.map(\.byteCount).max() ?? 0)
            let current = try readBytes(handle: handle, offset: plan.fileOffset, count: siteLen)
            if current.prefix(plan.asm.count) == plan.asm {
                outcomes.append(.alreadyPatched)
                continue
            }
            if auditSink != nil {
                // 账目先行收集；交付推迟到 Phase-2 全部成功后（见下）。
                audits.append(SiteAudit(
                    arch: plan.entry.arch, va: plan.va,
                    before: current.prefix(plan.asm.count), after: plan.asm,
                    identifier: identifier, source: plan.entry.source))
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
        // 审计逐条交付（125 续双评审 P1 修）：写入循环不与 audits 耦合
        //（sink==nil 时 audits 恒空，zip 会把写入一并清零——全量测试当场
        // 抓获的耦合事故）；sink 在场时两者同序 1:1，写一条、交付一条——
        // 中途写失败（EIO/ENOSPC）时已写成的位点账目已交付（字节在盘 =
        // 账目在场），CLI 失败路径把它落为「已写位点」的账（journal 记
        // 中断、audit 记已写——各司其职）。
        for (index, write) in writes.enumerated() {
#if DEBUG
            if let injected = Patcher.debugWriteFailureAt?(binary, index) { throw injected }
            Patcher.debugKillAtWriteSite(binary, index)
#endif
            try handle.seek(toOffset: write.offset)
            try handle.write(contentsOf: write.data)
            if index < audits.count { auditSink?(audits[index]) }
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
        for (index, entry) in entries.enumerated() {
            guard let slice = slices.first(where: { $0.cputype == entry.arch.cpuType }) else { continue }
            guard let addrHex = entry.addr, let va = UInt64(addrHex, radix: 16) else { continue } // recipe entries: M2
            let fileOffset = try resolveVA(va: va, handle: handle, sliceOffset: slice.offset, arch: entry.arch)
            // 装载期校验覆盖 catalog/signatures 两条主路，但 restore 的反转条目、
            // 测试合成条目与未来数据源仍可能带坏 hex 到这里——强解包 trap 会
            // 把数据错误变成进程崩溃，换成带上下文的干净拒绝。
            // 空 asm 同拒（124 轮体检 P2 兜底层）：装载门覆盖 catalog/signatures
            // 主路，但 restore 反演/测试合成条目直落此处——空 Data 过 hex 门后
            // prefix(0)==空 恒真 = 永远假 alreadyPatched。
            guard let asm = Data(hex: entry.asm), !asm.isEmpty else {
                throw PatchError.malformedAsm(index: index, identifier: identifier, asm: entry.asm)
            }
            // expected 坏 spec 干净拒绝（136 轮评审 P3，与上方 malformedAsm
            // 同款纪律）：compactMap 静默滤除会把 3 变体门收窄成 2——方向
            // fail-closed（坏形态只会 expectedMismatch 拒写，不会误写），
            // 但失败时无线索指向坏 spec 本身。装载期校验覆盖 catalog/
            // signatures 主路；restore 反演与测试合成条目仍可能带坏 spec
            // 直落此处。
            var expected: [ExpectedPattern]?
            if let values = entry.expected?.values {
                var parsed: [ExpectedPattern] = []
                parsed.reserveCapacity(values.count)
                for spec in values {
                    guard let pattern = ExpectedPattern(spec: spec) else {
                        throw PatchError.malformedExpected(index: index, identifier: identifier, spec: spec)
                    }
                    parsed.append(pattern)
                }
                expected = parsed
            }
            plans.append(Plan(entry: entry, va: va, asm: asm, expected: expected, fileOffset: fileOffset))
        }
        guard !plans.isEmpty else { throw PatchError.noArchMatched }
        // 同 binary 内写入区间重叠检测（102 轮数据完整性门；108 轮从
        // 「fileOffset 全等」收紧为区间交叠）：Phase 1 的全量预读会让重叠
        // 位点的两条 entry 都以「原始字节」过门，Phase 2 顺序写则后者静默
        // 覆盖前者（双 written 假账）——部分交叠（off=X len16 vs off=X+8
        // len4）与全等同属这一事故形态。现役数据不可达（variant 互斥、域
        // 不交），但数据演进/合并事故必须在这里变成干净拒绝而不是静默错写。
        var spans: [(start: UInt64, end: UInt64, index: Int)] =
            plans.enumerated().map {
                ($0.element.fileOffset,
                 $0.element.fileOffset + UInt64($0.element.asm.count), $0.offset)
            }
        spans.sort { $0.start < $1.start }
        for i in 1..<max(1, spans.count) {
            if spans[i].start < spans[i - 1].end {
                throw PatchError.overlappingEntries(
                    first: spans[i - 1].index, second: spans[i].index,
                    va: plans[spans[i].index].va, identifier: identifier)
            }
        }
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
        if magicBE == 0xCAFEBABF {
            throw PatchError.fat64Unsupported
        }
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
            if cmd == 0x19, cmdsize >= 72 { // LC_SEGMENT_64（cmdsize 门：段命令头 72B，短命令读段字段=读进下一条命令）
                // 溢出防 trap（124 轮体检 P3，MachImage 读路径同款）：损坏
                // cmdsize 近 2^64 时 cursor 推进加法溢出 = 进程崩溃。
                let seekOff = cursor.addingReportingOverflow(24)
                guard !seekOff.overflow else { throw PatchError.not64BitMachO }
                try handle.seek(toOffset: seekOff.partialValue)
                guard let seg = try handle.read(upToCount: 40), seg.count == 40 else {
                    throw PatchError.not64BitMachO
                }
                let fields = seg.withUnsafeBytes { raw -> (UInt64, UInt64, UInt64, UInt64) in
                    (raw.loadUnaligned(fromByteOffset: 0, as: UInt64.self),   // vmaddr
                     raw.loadUnaligned(fromByteOffset: 8, as: UInt64.self),   // vmsize
                     raw.loadUnaligned(fromByteOffset: 16, as: UInt64.self),  // fileoff
                     raw.loadUnaligned(fromByteOffset: 24, as: UInt64.self))  // filesize
                }
                // 写路径的换算必须落在 file-backed 区间内：vmsize 覆盖 __bss
                // 等零填充尾（无文件背书），把 VA 映到那里 = 写偏移飞进下一
                // 段或文件尾外的无关字节。
                if va >= fields.0 && va - fields.0 < fields.3 {   // 111 轮修：减法式（加法式溢出 trap）
                    // 病态 fileoff 近 2^64 时最终加法仍可溢出 trap——checked
                    // 加法后按 vaNotFound 干净拒绝（124 轮体检 P3）。
                    let s1 = sliceOffset.addingReportingOverflow(fields.2)
                    if s1.overflow { throw PatchError.vaNotFound(va: va, arch: arch.rawValue) }
                    let s2 = s1.partialValue.addingReportingOverflow(va - fields.0)
                    if s2.overflow { throw PatchError.vaNotFound(va: va, arch: arch.rawValue) }
                    return s2.partialValue
                }
            }
            let next = cursor.addingReportingOverflow(UInt64(cmdsize))
            guard !next.overflow, cmdsize >= 8 else { throw PatchError.not64BitMachO }
            cursor = next.partialValue
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
