import Foundation

/// Behavioral verification: prove a patch's EFFECT by calling the patched
/// function out-of-process (mini-loader route — no dyld, no initializers,
/// no app bundle deps; validated by the M2-3 spike on real 269602 x64).
///
/// Architecture: the CLI re-execs itself as a hidden `__verify-worker` so a
/// crash inside mapped code kills only the worker; the parent interprets the
/// exit status (0 = probes ran; signal = crash / environment blocks unsigned
/// executable memory).
///
/// The worker exploits this image family's layout invariants:
///   - file offset == VA across __TEXT/__DATA_CONST/__DATA → base+VA indexing
///   - imports the target calls go through PLT stubs (`ff 25 <rel32>`) whose
///     GOT slots can be redirected to native harness functions
///   - C++ magic-static regions start zeroed at runtime; raw file bytes are
///     not the runtime state → explicit zero prep
///   - arguments use WeChat's custom SSO string layout (size<<1 in byte 0,
///     LSB = long flag; short data at +1; long: size@+8, ptr@+0x10)
enum Verifier {
    enum VerifyError: Error, CustomStringConvertible {
        case noVerifySpec(arch: String)
        case workerCrashed(signal: Int32)
        case environmentBlocked
        case archMismatch(image: String, host: String)
        case mismatch(detail: String)

        var description: String {
            switch self {
            case .noVerifySpec(let arch):
                "no verify spec for \(arch) in signatures.json — behavior check unavailable for this build"
            case .workerCrashed(let sig):
                "verification worker crashed (signal \(sig)) — the function touched state we didn't model"
            case .environmentBlocked:
                "environment blocked executing mapped code (AMFI on / SIP on). "
                + "Behavioral verification needs a relaxed machine (this project's docs explain the trade-off)"
            case .archMismatch(let image, let host):
                "dylib slice is \(image) but this machine runs \(host) — behavioral verification "
                + "executes mapped code natively and cannot cross architectures"
            case .mismatch(let detail):
                "behavior mismatch: \(detail)"
            }
        }
    }

    enum ImageArch: String {
        case x86_64
        case arm64

        /// Host architecture. In a universal binary each slice sees its own
        /// compile-time arch, which equals the runtime arch — exactly what the
        /// worker needs (it executes mapped code natively, no cross-arch).
        static var host: ImageArch {
            #if arch(arm64)
            return .arm64
            #else
            return .x86_64
            #endif
        }

        static func cputypeArch(_ raw: UInt32) -> ImageArch? {
            switch raw {
            case 0x0100_000C: return .arm64
            case 0x0100_0007: return .x86_64
            default: return nil
            }
        }
    }

    struct VerifySpec: Codable {
        /// hex stub VA → "strlen" / "memcmp" (native replacements)
        let stubs: [String: String]
        /// [[hexVA, byteLen], ...] regions to zero before probing (magic statics)
        let zeroRegions: [[String]]
        /// [text, expectedOnPristine(0/1), ...]
        let probes: [[String]]

        enum CodingKeys: String, CodingKey {
            case stubs, probes
            case zeroRegions = "zero_regions"
        }
    }

    struct ProbeResult {
        let text: String
        let returned: Bool
    }

    // MARK: - arm64 specifics (270100/270099 predicate ground truth)

    /// arm64 布局差异的集中地。桩形 = `adrp x16,<page>; ldr x16,[x16,#off]; br x16`
    /// （无 x64 的 ff25 PLT）；SSO 短串布局 = 数据在偏移 0、直接长度字节在 +0x17
    /// （与 x64 的 size<<1@0 + 数据@+1 不同——两架构字符串 ABI 不同源）。
    enum ARM64 {
        static let brX16: UInt32 = 0xD61F_0200

        /// 12B 桩 → 映射内 GOT 槽偏移；形态不符返回 nil（守卫：坏 spec 静默
        /// 跳过会留 chained-fixup 原始值，调用即崩——与 x64 侧同语义）。
        static func stubSlotOffset(pcOffset: UInt64, w0: UInt32, w1: UInt32, w2: UInt32) -> Int? {
            guard (w0 >> 31) == 1, ((w0 >> 24) & 0x1F) == 0x10 else { return nil }   // adrp
            guard ((w1 >> 22) & 0x3FF) == 0x3E5, ((w1 >> 5) & 0x1F) == 16 else { return nil } // ldr x16,[x16,#imm]
            guard w2 == brX16 else { return nil }
            let immlo = (w0 >> 29) & 0x3
            let immhi = (w0 >> 5) & 0x7_FFFF
            var imm = Int64(immhi << 2 | immlo)
            if imm & (1 << 20) != 0 { imm -= (1 << 21) }
            let page = Int64(pcOffset & ~0xFFF) + (imm << 12)
            let slot = page + Int64((w1 >> 10) & 0xFFF) * 8
            return slot >= 0 ? Int(slot) : nil
        }

        static func stubSlotOffset(pcOffset: UInt64, bytes: [UInt8]) -> Int? {
            guard bytes.count >= 12 else { return nil }
            func word(_ o: Int) -> UInt32 {
                UInt32(bytes[o]) | UInt32(bytes[o+1]) << 8 | UInt32(bytes[o+2]) << 16 | UInt32(bytes[o+3]) << 24
            }
            return stubSlotOffset(pcOffset: pcOffset, w0: word(0), w1: word(4), w2: word(8))
        }

        /// arm64 探针 SSO：数据 @0、长度字节 @0x17（直接长度）。短串 only。
        static func ssoProbe(_ text: String) -> [UInt8]? {
            let bytes = Array(text.utf8)
            guard bytes.count < 0x40 else { return nil }
            var storage = [UInt8](repeating: 0, count: 24)
            for (i, byte) in bytes.enumerated() { storage[i] = byte }
            storage[0x17] = UInt8(bytes.count)
            return storage
        }

        /// parse 内 cbz 位点 -4 处的 BL → 谓词 VA（gen3 形态：
        /// `mov x0,x22; bl <pred>; cbz w0,<skip>`）。thin 镜像 VA==文件偏移。
        static func predicateVA(fileData: Data, site: UInt64) -> UInt64? {
            guard site >= 4, Int(site) <= fileData.count else { return nil }
            let word = fileData.withUnsafeBytes {
                $0.loadUnaligned(fromByteOffset: Int(site - 4), as: UInt32.self)
            }
            return blTargetVA(word: word, blVA: site - 4)
        }

        /// MachImage 形态（fat 装机件必须走这里）：VA 经段表换算到切片内
        /// 偏移。fat 容器里 arm64 切片起点 ≠ 0，直接拿原始文件字节按
        /// VA 索引会读错位置（首次实机验收前拦下的缺陷）。
        static func predicateVA(image: MachImage, site: UInt64) -> UInt64? {
            guard site >= 4, let word = image.word32(va: site - 4) else { return nil }
            return blTargetVA(word: word, blVA: site - 4)
        }

        /// BL word（小端已组装）→ 目标 VA；非 BL 返回 nil。
        static func blTargetVA(word: UInt32, blVA: UInt64) -> UInt64? {
            guard (word >> 26) == 0x25 else { return nil }   // BL: 100101
            var imm26 = Int32(bitPattern: word) & 0x3FF_FFFF
            if imm26 & (1 << 25) != 0 { imm26 -= (1 << 26) }
            let target = Int64(blVA) + Int64(imm26) * 4
            return target >= 0 ? UInt64(target) : nil
        }
    }

    // MARK: - Parent side

    /// 环境能力探针：以最小 blob（host 架构的一条 ret，va=0）真起一次
    /// worker。exit 0 = RWX 映射+执行可用（AMFI relaxed 引导，或二进制带
    /// unsigned-executable-memory entitlement——CI 验收 job 用后者）；126 =
    /// 被 AMFI 拒绝。比读 nvram boot-args 诚实：测的是 worker 的实际能力，
    /// 而非引导参数长什么样。
    static func workerCanExecute(binary: URL) -> Bool {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-rwxprobe-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
            // 裸 blob（无 Mach-O 头）→ worker 走恒等映射路径。
            var data = Data(count: 0x100)
            if ImageArch.host == .arm64 {
                data.replaceSubrange(0..<4, with: [0xC0, 0x03, 0x5F, 0xD6])   // ret
            } else {
                data[0] = 0xC3                                                // ret
            }
            try data.write(to: work.appendingPathComponent("probe.bin"))
        } catch { return false }
        defer { try? FileManager.default.removeItem(at: work) }
        let result = Shell.run(binary.path, [
            "__verify-worker", work.appendingPathComponent("probe.bin").path,
            "0", "{}", "[]", "[[\"x\",\"1\"]]",
        ])
        return result.status == 0
    }

    /// Runs behavioral probes against `dylib` (thin or fat; fat slices are
    /// extracted via lipo). Returns one result per probe, in spec order.
    static func run(binary: URL, targetVA: UInt64, spec: VerifySpec,
                    executable: URL? = nil) throws -> [ProbeResult] {
        // Fat → the HOST-arch thin slice (the worker executes mapped code
        // natively — no cross-arch); thin images must match the host too.
        let head = (try? Data(contentsOf: binary, options: .alwaysMapped).prefix(8)) ?? Data()
        let imageArch: ImageArch
        var thin = binary
        var tempThin: URL?
        let magic = head.prefix(4)
        if magic.elementsEqual(Data([0xCA, 0xFE, 0xBA, 0xBE])) {
            let host = ImageArch.host
            let out = FileManager.default.temporaryDirectory
                .appendingPathComponent("wxkeep-verify-\(UUID().uuidString).\(host.rawValue)")
            let lipo = Shell.run("/usr/bin/lipo", ["-thin", host.rawValue, binary.path, "-output", out.path])
            guard lipo.status == 0 else { throw VerifyError.archMismatch(
                image: "fat (no \(host.rawValue) slice)", host: host.rawValue) }
            thin = out
            tempThin = out
            imageArch = host
        } else if head.count >= 8, let a = ImageArch.cputypeArch(
            UInt32(head[4]) | UInt32(head[5]) << 8 | UInt32(head[6]) << 16 | UInt32(head[7]) << 24) {
            imageArch = a
        } else {
            imageArch = ImageArch.host   // bare synthetic blobs (test fixtures)
        }
        if imageArch != ImageArch.host {
            throw VerifyError.archMismatch(image: imageArch.rawValue, host: ImageArch.host.rawValue)
        }
        defer { if let tempThin { try? FileManager.default.removeItem(at: tempThin) } }

        let stubsJSON = jsonString(spec.stubs) ?? "{}"
        let zerosJSON = jsonString(spec.zeroRegions) ?? "[]"
        let probesJSON = jsonString(spec.probes) ?? "[]"
        let exe = executable ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let result = Shell.run(exe.path, [
            "__verify-worker", thin.path, String(targetVA, radix: 16),
            stubsJSON, zerosJSON, probesJSON,
        ])
        if result.status != 0 {
            if result.status > 128 { throw VerifyError.workerCrashed(signal: result.status - 128) }
            if result.status == 126 || result.status == 137 { throw VerifyError.environmentBlocked }
            throw VerifyError.workerCrashed(signal: result.status)
        }
        return result.stdout.split(separator: "\n").compactMap { line in
            // probe|<text>|<0|1>
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "probe" else { return nil }
            return ProbeResult(text: String(parts[1]), returned: parts[2] == "1")
        }
    }

    private static func jsonString<T: Encodable>(_ value: T) -> String? {
        guard let data = try? JSONEncoder().encode(value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Worker side (runs in the forked copy of this executable)

    /// Entry for `wxkeep __verify-worker <dylib> <va> <stubs> <zeros> <probes>`.
    /// Prints `probe|<text>|<0|1>` lines and exits 0; crashes on bad state.
    static func workerMain(_ args: [String]) -> Never {
        guard args.count >= 5,
              let data = try? Data(contentsOf: URL(fileURLWithPath: args[0])),
              let va = UInt64(args[1], radix: 16),
              let stubs = try? JSONDecoder().decode([String: String].self, from: Data(args[2].utf8)),
              let zeros = try? JSONDecoder().decode([[String]].self, from: Data(args[3].utf8)),
              let probes = try? JSONDecoder().decode([[String]].self, from: Data(args[4].utf8))
        else { exit(2) }

        // Map the whole thin image RWX. Image base = __TEXT vmaddr: dylibs
        // link at 0 (VA == file offset) but PIE main executables link at
        // 0x100000000 — every spec VA must be rebased by it.
        let base = data.withUnsafeBytes { raw -> UInt64 in
            // bare synthetic blobs (test fixtures) carry no Mach-O header
            guard raw.count >= 32,
                  raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self) == 0xFEEDFACF else { return 0 }
            let ncmds = raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self)
            var p = 32
            var minVM = UInt64.max
            for _ in 0..<ncmds {
                guard p + 72 <= raw.count else { break }
                let cmd = raw.loadUnaligned(fromByteOffset: p, as: UInt32.self)
                let cmdsize = Int(raw.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self))
                guard cmdsize > 0 else { break }
                if cmd == 0x19 {
                    let vmaddr = raw.loadUnaligned(fromByteOffset: p + 24, as: UInt64.self)
                    let vmsize = raw.loadUnaligned(fromByteOffset: p + 32, as: UInt64.self)
                    let fileoff = raw.loadUnaligned(fromByteOffset: p + 40, as: UInt64.self)
                    // __TEXT is the fileoff==0 CONTENT segment (PAGEZERO also
                    // sits at fileoff 0 with filesize 0 — exclude by content);
                    // its vmaddr is the base (0 for dylibs, 0x1_0000_0000 for PIE)
                    let filesize = raw.loadUnaligned(fromByteOffset: p + 48, as: UInt64.self)
                    if filesize > 0, fileoff == 0 { minVM = min(minVM, vmaddr) }
                }
                p += cmdsize
            }
            return minVM == .max ? 0 : minVM
        }
        // Segment-faithful mapping: some images (PIE executables) have
        // fileoff != vmaddr - base for later segments; copy each segment to
        // its vmaddr slot so every spec VA indexes uniformly. anon memory is
        // zero-filled, covering __bss tails beyond filesize.
        var mappedSize = 0
        let mapped = data.withUnsafeBytes { raw -> UnsafeMutableRawPointer in
            var segs: [(vmaddr: UInt64, vmsize: UInt64, fileoff: Int, filesize: UInt64)] = []
            var p = 32
            for _ in 0..<raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self) {
                guard p + 72 <= raw.count else { break }
                let cmd = raw.loadUnaligned(fromByteOffset: p, as: UInt32.self)
                let cmdsize = Int(raw.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self))
                guard cmdsize > 0 else { break }
                if cmd == 0x19 {
                    let fs = raw.loadUnaligned(fromByteOffset: p + 48, as: UInt64.self)
                    if fs > 0 {   // skip __PAGEZERO-style contentless segments
                        segs.append((raw.loadUnaligned(fromByteOffset: p + 24, as: UInt64.self),
                                     raw.loadUnaligned(fromByteOffset: p + 32, as: UInt64.self),
                                     Int(raw.loadUnaligned(fromByteOffset: p + 40, as: UInt64.self)),
                                     fs))
                    }
                }
                p += cmdsize
            }
            if segs.isEmpty {   // bare blob: identity copy, base 0
                let mem = mmap(nil, raw.count, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANON, -1, 0)
                guard let mem = mem, mem != UnsafeMutableRawPointer(bitPattern: -1) else { exit(126) }
                memcpy(mem, raw.baseAddress, raw.count)
                mappedSize = raw.count
                return mem
            }
            let top = segs.filter { $0.vmaddr >= base }.map { $0.vmaddr + $0.vmsize }.max() ?? 0
            let total = Int(top - base)
            mappedSize = total
            let mem = mmap(nil, total, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANON, -1, 0)
            guard let mem = mem, mem != UnsafeMutableRawPointer(bitPattern: -1) else { exit(126) }
            for seg in segs where seg.vmaddr >= base {
                let dst = Int(seg.vmaddr - base)
                let src = raw.baseAddress! + seg.fileoff
                let n = min(Int(seg.filesize), total - dst)
                if n > 0, dst >= 0 { memcpy(mem + dst, src, n) }
            }
            return mem
        }

        // Zero magic-static regions to their runtime-start state.
        // Bound-checked: a bad spec must fail with a clear exit code, not
        // corrupt memory adjacent to the mapping before crashing.
        for region in zeros {
            guard region.count == 2, let vaHex = UInt64(region[0], radix: 16),
                  let len = Int(region[1]), len > 0,
                  vaHex >= base, Int(vaHex - base) >= 0,
                  Int(vaHex - base) + len <= mappedSize else { exit(3) }
            memset(mapped + Int(vaHex - base), 0, len)
        }

        // Redirect import stubs to native harness functions.
        // x64: PLT `ff 25 <rel32>` → slot = stubVA + 6 + disp32.
        // arm64: `adrp x16/ldr x16,[x16,#imm]/br x16` → slot = page + imm*8.
        // Mapped image header cputype decides (same mapping serves both).
        let cpuWord = mapped.load(as: UInt32.self)   // mach header magic
        let cpuType = mapped.load(fromByteOffset: 4, as: UInt32.self)
        let isARM64 = cpuWord == 0xFEED_FACF && cpuType == 0x0100_000C
        for (stubHex, kind) in stubs {
            guard let stubVA = UInt64(stubHex, radix: 16) else { continue }
            let stub = UnsafeRawPointer(mapped + Int(stubVA - base))
            let slotOffset: Int
            if isARM64 {
                guard Int(stubVA - base) + 12 <= mappedSize else { continue }
                guard let s = ARM64.stubSlotOffset(
                    pcOffset: stubVA - base,
                    w0: stub.load(as: UInt32.self),
                    w1: stub.load(fromByteOffset: 4, as: UInt32.self),
                    w2: stub.load(fromByteOffset: 8, as: UInt32.self)) else { continue }
                slotOffset = s
            } else {
                guard stub.load(as: UInt8.self) == 0xFF,
                      stub.load(fromByteOffset: 1, as: UInt8.self) == 0x25 else { continue }
                // swift load() enforces alignment — assemble the unaligned rel32 byte-wise
                var dispValue: UInt32 = 0
                for i in 0..<4 {
                    dispValue |= UInt32(stub.load(fromByteOffset: 2 + i, as: UInt8.self)) << (8 * i)
                }
                let disp = Int32(bitPattern: dispValue)
                slotOffset = Int(stubVA - base) + 6 + Int(disp)
            }
            guard slotOffset >= 0, slotOffset + 8 <= mappedSize,
                  UInt(bitPattern: mapped + slotOffset) % 8 == 0 else { exit(3) }
            let sym = kind == "memcmp" ? "memcmp" : "strlen"
            if let fn = dlsym(dlopen(nil, RTLD_LAZY), sym) {
                (mapped + slotOffset).assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = fn
            }
        }

        // WeChat SSO string ABI: pass 24 CONTIGUOUS bytes. Array's own
        // withUnsafeMutableBytes yields the element buffer — never &array
        // (that is the array header: pointer+count, not the data).
        guard va >= base, Int(va - base) < mappedSize else { exit(3) }
        let fn: @convention(c) (UnsafeMutableRawPointer) -> Bool =
            unsafeBitCast(mapped + Int(va - base), to: (@convention(c) (UnsafeMutableRawPointer) -> Bool).self)

        var out = ""
        for probe in probes {
            guard let text = probe.first else { continue }
            let r: Bool
            if isARM64 {
                // arm64 SSO：数据 @0、长度字节 @0x17（直接长度）
                guard var storage = ARM64.ssoProbe(text) else { continue }
                r = storage.withUnsafeMutableBytes { raw in fn(raw.baseAddress!) }
            } else {
                // x64 SSO：size<<1 @byte0（LSB=long 旗），短串数据 @+1。
                // Short-SSO probes only (<23 bytes); long-string construction is
                // deliberately unsupported (no current spec needs it).
                let bytes = Array(text.utf8)
                guard bytes.count < 23 else { continue }
                var storage = [UInt8](repeating: 0, count: 24)
                storage[0] = UInt8(bytes.count << 1)
                for (i, byte) in bytes.enumerated() { storage[1 + i] = byte }
                r = storage.withUnsafeMutableBytes { raw in fn(raw.baseAddress!) }
            }
            out += "probe|\(text)|\(r ? 1 : 0)\n"
        }
        FileHandle.standardOutput.write(out.data(using: .utf8)!)
        exit(0)
    }


    // MARK: - Verdict

    /// arm64 语义：被探针的是 parse 内 cbz 的**谓词输入**（非补丁位点本身——
    /// 补丁是 cbz 分支翻转，谓词行为 pristine/patched 恒同）。本验证证明
    /// 「家族完整性 + 谓词输入路径 + harness 自检」；补丁有效性由 strict
    /// verify 的字节级证明承担（分支字节 = patch 态即生效，无条件直达）。
    static func verdictPredicate(
        results: [ProbeResult], spec: VerifySpec
    ) -> VerifyError? {
        let expecteds: [Bool?] = spec.probes.map { $0.count > 1 ? $0[1] == "1" : nil }
        for (result, expected) in zip(results, expecteds) {
            if let expected, result.returned != expected {
                return .mismatch(detail: "revokemsg predicate(\"\(result.text)\") = "
                    + "\(result.returned ? 1 : 0), expected \(expected ? 1 : 0) — "
                    + "image doesn't match the family ground truth this spec encodes")
            }
        }
        return nil
    }

    /// Compares probe results against the expected behavior for the given
    /// on-disk state (pristine expects the spec's expecteds; patched expects
    /// every probe to return the neutralized value).
    static func verdict(
        results: [ProbeResult], spec: VerifySpec, state: Patcher.Inspection.State
    ) -> VerifyError? {
        let expecteds: [Bool?] = spec.probes.map { $0.count > 1 ? $0[1] == "1" : nil }
        switch state {
        case .pristine:
            for (result, expected) in zip(results, expecteds) {
                if let expected, result.returned != expected {
                    return .mismatch(detail: "pristine image: isRevokemsg(\"\(result.text)\") = \(result.returned ? 1 : 0), expected \(expected ? 1 : 0)")
                }
            }
        case .patched:
            for (result, expected) in zip(results, expecteds) {
                if expected == true && result.returned {
                    return .mismatch(detail: "patched image still classifies \"\(result.text)\" as revokemsg — patch ineffective")
                }
            }
        case .unknown:
            return .mismatch(detail: "patch point holds unknown bytes — verify against pristine/patched expectations is undefined")
        }
        return nil
    }
}
