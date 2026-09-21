import Foundation
import Testing
@testable import wxkeep

/// Behavioral-verifier tests against a synthetic mini image (no Mach-O
/// structure needed — the worker maps the whole file with VA == file offset).
/// The worker host is the built wxkeep binary (the test runner has no
/// __verify-worker dispatch). Skipped only where the real worker probe says
/// executable memory is unavailable (arm64 uses MAP_JIT, so stock machines
/// qualify; hardened runtime without the JIT entitlement does not).
struct VerifierTests {
    /// Behavioral-mapping gate keyed on a REAL worker probe, not boot-arg
    /// archaeology: spawn `__verify-worker` once on a ret-only blob — exit 0
    /// means this environment can map executable memory (arm64 takes the
    /// MAP_JIT route — entitlement-free for non-hardened processes; x64 maps
    /// RWX directly). Exit 126 = environment refused → skip.
    /// Static-let: the probe spawns one process; memoize for the whole run.
    private static let workerProbeBlocked: Bool = {
        guard let bin = wxkeepBinary else { return true }
        return !Verifier.workerCanExecute(binary: bin)
    }()

    private static var environmentUnsuitable: Bool {
        VerifierTests.wxkeepBinary == nil || VerifierTests.workerProbeBlocked
    }

    private static let hostIsARM64: Bool = Verifier.ImageArch.host == .arm64

    private static let hostIsNotARM64: Bool = !hostIsARM64

    private static var wxkeepBinary: URL? {
        // Tests/wxkeepTests/VerifierTests.swift → repo root → .build/debug/wxkeep
        let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let url = here.appendingPathComponent(".build/debug/wxkeep")
        return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
    }

    /// isRevokemsg-shaped synthetic function (semantics mirror the real one):
    ///   fn(arg): strlen(GLOBAL) == arg.ssoSize && memcmp(arg.data, GLOBAL, len) == 0
    /// Two PLT stubs (strlen@0x140, memcmp@0x150) through junk GOT slots
    /// (0x180/0x188) — redirection is load-bearing; GLOBAL "revokems" @0x200.
    private func miniImage() -> Data {
        var blob = Data(count: 0x400)
        func emit(_ off: Int, _ bytes: [UInt8]) { blob.replaceSubrange(off..<off + bytes.count, with: Data(bytes)) }
        func rel32(_ from: Int, _ to: Int) -> [UInt8] {
            withUnsafeBytes(of: Int32(to - from).littleEndian) { Array($0) }
        }
        emit(0x100, [0x53])                              // push rbx
        emit(0x101, [0x48, 0x89, 0xFB])                  // mov rbx, rdi
        emit(0x104, [0x48, 0x8D, 0x3D] + rel32(0x10B, 0x200))  // lea rdi,[rip+GLOBAL]
        emit(0x10B, [0xE8] + rel32(0x110, 0x140))        // call strlen-stub
        emit(0x110, [0x8A, 0x0B])                        // mov cl, byte [rbx]
        emit(0x112, [0xC0, 0xE9, 0x01])                  // shr cl, 1
        emit(0x115, [0x48, 0x0F, 0xBE, 0xC9])            // movsx rcx, cl
        emit(0x119, [0x48, 0x39, 0xC8])                  // cmp rax, rcx
        emit(0x11C, [0x75, 0x1A])                        // jne ret0 (0x138)
        emit(0x11E, [0x48, 0x8D, 0x7B, 0x01])            // lea rdi, [rbx+1]
        emit(0x122, [0x48, 0x8D, 0x35] + rel32(0x129, 0x200))  // lea rsi,[rip+GLOBAL]
        emit(0x129, [0x48, 0x89, 0xC2])                  // mov rdx, rax
        emit(0x12C, [0xE8] + rel32(0x131, 0x150))        // call memcmp-stub
        emit(0x131, [0x85, 0xC0])                        // test eax, eax
        emit(0x133, [0x0F, 0x94, 0xC0])                  // sete al
        emit(0x136, [0x5B, 0xC3])                        // pop rbx; ret
        emit(0x138, [0x31, 0xC0, 0x5B, 0xC3])            // ret0: xor eax; pop; ret
        emit(0x140, [0xFF, 0x25] + rel32(0x146, 0x180))  // jmp [rip+GOT1]
        emit(0x150, [0xFF, 0x25] + rel32(0x156, 0x188))  // jmp [rip+GOT2]
        emit(0x180, [0xDE, 0xAD, 0xBE, 0xEF, 0x0B, 0xAD, 0xF0, 0x0D])
        emit(0x188, [0xEF, 0xBE, 0xAD, 0xDE, 0xD0, 0x0F, 0xAA, 0x0E])
        emit(0x200, Array("revokems\0".utf8))
        return blob
    }

    private var spec: Verifier.VerifySpec {
        .init(stubs: ["140": "strlen", "150": "memcmp"],
              zeroRegions: [["1C0", "16"]],
              probes: [["revokems", "1"], ["other", "0"], ["", "0"]])
    }

    @Test(.disabled(if: VerifierTests.environmentUnsuitable || VerifierTests.hostIsARM64,
                   "x86_64 host required — this fixture is raw x64 code; the worker executes it natively"))
    func pristineImageClassifiesCorrectly() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-verifier-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let dylib = work.appendingPathComponent("mini.bin")
        try miniImage().write(to: dylib)

        let results = try Verifier.run(binary: dylib, targetVA: 0x100, spec: spec,
                                       executable: Self.wxkeepBinary)
        #expect(results.map(\.returned) == [true, false, false])
        #expect(Verifier.verdict(results: results, spec: spec, state: .pristine) == nil)
    }

    @Test(.disabled(if: VerifierTests.environmentUnsuitable || VerifierTests.hostIsARM64,
                   "x86_64 host required — this fixture is raw x64 code; the worker executes it natively"))
    func patchedImageNeutralized() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-verifier-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        var blob = miniImage()
        blob.replaceSubrange(0x100..<0x103, with: Data([0x31, 0xC0, 0xC3]))  // xor eax,eax; ret
        let dylib = work.appendingPathComponent("mini-patched.bin")
        try blob.write(to: dylib)

        let results = try Verifier.run(binary: dylib, targetVA: 0x100, spec: spec,
                                       executable: Self.wxkeepBinary)
        #expect(results.map(\.returned) == [false, false, false])
        #expect(Verifier.verdict(results: results, spec: spec, state: .patched) == nil)
    }

    @Test func verdictFlagsIneffectivePatch() {
        let spec2 = Verifier.VerifySpec(stubs: [:], zeroRegions: [], probes: [["revokems", "1"]])
        let bad = [Verifier.ProbeResult(text: "revokemsg", returned: true)]
        let failure = Verifier.verdict(results: bad, spec: spec2, state: .patched)
        #expect(failure != nil)
    }

    // MARK: - arm64 decoders (pure logic — runs on any host arch)

    @Test func arm64StubSlotDecodeMatchesGroundTruth() {
        // 270100 strlen 桩 @0x6FD28EC 的真实 12 字节（adrp x16,0x998c000;
        // ldr x16,[x16,#0x1e0]; br x16）→ GOT 槽 0x998C1E0。
        let bytes: [UInt8] = [0xD0, 0x4D, 0x01, 0xD0, 0x10, 0xF2, 0x40, 0xF9, 0x00, 0x02, 0x1F, 0xD6]
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0x6FD2_8EC, bytes: bytes) == 0x998C_1E0)
        // memcmp 桩 @0x6FD1D70 → 0x998B000 + 0x9B0
        let m: [UInt8] = [0xD0, 0x4D, 0x01, 0xD0, 0x10, 0xDA, 0x44, 0xF9, 0x00, 0x02, 0x1F, 0xD6]
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0x6FD1_D70, bytes: m) == 0x998B_9B0)
        // 形态守卫：垃圾字节必须拒绝（坏 spec 静默跳过 = 槽位留原始值必崩）
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0, bytes: [UInt8](repeating: 0, count: 12)) == nil)
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0, bytes: [0xFF, 0x25]) == nil)
    }

    @Test func arm64SSOProbeLayout() {
        // arm64 短串：数据 @0、直接长度 @0x17（270100 谓词 ldrsb [x19,#0x17] 实证）
        guard let sso = Verifier.ARM64.ssoProbe("revokemsg") else {
            Issue.record("probe rejected"); return
        }
        #expect(sso.count == 24)
        #expect(Array(sso[0..<9].prefix(9)) == Array("revokemsg".utf8))
        #expect(sso[0x17] == 9)
        #expect(sso[0] == UInt8(ascii: "r"))   // 数据在偏移 0（非 x64 的 +1）
        // 长串拒绝（谓词只做短串路径的验证；长串构造未建模）
        #expect(Verifier.ARM64.ssoProbe(String(repeating: "a", count: 0x40)) == nil)
    }

    @Test func arm64PredicateVADecode() {
        // gen3 形态：cbz 位点 -4 处 BL。构造 BL +0x10（imm26=4）@site-4。
        // BL 编码 = 0x94000000 | imm26
        var blob = Data(count: 0x100)
        let site: UInt64 = 0x80
        let word: UInt32 = 0x9400_0000 | 4   // bl +0x10 → 谓词 = site-4+0x10
        blob.withUnsafeMutableBytes { $0.loadUnaligned(as: UInt32.self) }
        blob.replaceSubrange(Int(site - 4)..<Int(site), with: withUnsafeBytes(of: word.littleEndian) { Data($0) })
        #expect(Verifier.ARM64.predicateVA(fileData: blob, site: site) == site - 4 + 0x10)
        // 负位移：bl -0x10（imm26 = 2^26 - 4）
        let back: UInt32 = 0x9400_0000 | (UInt32(1) << 26 - 4)
        blob.replaceSubrange(Int(site - 4)..<Int(site), with: withUnsafeBytes(of: back.littleEndian) { Data($0) })
        #expect(Verifier.ARM64.predicateVA(fileData: blob, site: site) == site - 4 - 0x10)
        // 非 BL 拒绝
        blob.replaceSubrange(Int(site - 4)..<Int(site), with: Data([0x00, 0x00, 0x00, 0x14]))  // b (非 bl)
        #expect(Verifier.ARM64.predicateVA(fileData: blob, site: site) == nil)
    }

    @Test func verdictPredicateSemantics() {
        // arm64 语义：谓词在两态下行为相同（补丁在下游 cbz）——
        // spec 预期恒为判据，patched 态不要求"归零"。
        let spec2 = Verifier.VerifySpec(stubs: [:], zeroRegions: [], probes: [["revokemsg", "1"]])
        let good = [Verifier.ProbeResult(text: "revokemsg", returned: true)]
        #expect(Verifier.verdictPredicate(results: good, spec: spec2) == nil)
        let bad = [Verifier.ProbeResult(text: "revokemsg", returned: false)]
        #expect(Verifier.verdictPredicate(results: bad, spec: spec2) != nil)
    }

    // MARK: - predicateVA on real-world fat images (any host arch)

    /// 装机 wechat.dylib 是 fat 双架构：arm64 切片起点 ≠ 0，原始文件字节
    /// 按 VA 直索引会读错位置。CLI verify 的 arm64 分支必须走 MachImage
    /// 切片路径——本测试锁死该行为（首次实机验收前静态拦下的缺陷）。
    @Test func arm64PredicateVAOnFatImageUsesSliceBytes() throws {
        // BL +0x40 @0x100，cbz site @0x104 → 谓词 VA 0x140
        let bl: UInt32 = 0x9400_0000 | 0x10
        let code: [(offset: Int, bytes: [UInt8])] =
            [(0x100, withUnsafeBytes(of: bl.littleEndian) { Array($0) })]
        let armThin = MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: code)
        let x64Thin = MachOFixture.thin(cputype: MachOFixture.x64CPU)
        let fat = MachOFixture.fat(arm64: armThin, x64: x64Thin)

        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-pred-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let thinURL = work.appendingPathComponent("thin.dylib")
        let fatURL = work.appendingPathComponent("fat.dylib")
        try armThin.write(to: thinURL)
        try fat.image.write(to: fatURL)

        let viaThin = try MachImage(file: thinURL, arch: .arm64)
        let viaFat = try MachImage(file: fatURL, arch: .arm64)
        #expect(Verifier.ARM64.predicateVA(image: viaThin, site: 0x104) == 0x140)
        #expect(Verifier.ARM64.predicateVA(image: viaFat, site: 0x104) == 0x140)
        // 病理证明：fat 里 0x100 处是 0xCC 填充（arm64 切片在 0x400 起），
        // 旧路径（原始字节直读）在这里必反解失败。
        #expect(fat.image[0x100...0x103] == Data(repeating: 0xCC, count: 4))
        #expect(Verifier.ARM64.predicateVA(fileData: fat.image, site: 0x104) == nil)
    }

    // MARK: - arm64 synthetic mini image (worker-path acceptance harness)

    /// isRevokemsg-shaped arm64 predicate, mirror of the x64 mini image:
    ///   fn(arg): strlen(GLOBAL) == arg.lenByte@0x17 && memcmp(arg.data@0, GLOBAL, len) == 0
    /// Real Mach-O arm64 thin (via MachOFixture) so the worker takes the
    /// segment-faithful mapping + arm64 SSO layout path; imports go through
    /// adrp x16/ldr x16,[x16,#imm]/br x16 stubs at 0x180/0x190 into junk GOT
    /// slots 0x1C0/0x1C8 (redirection is load-bearing); GLOBAL "revokems" @0x200.
    /// The argument must live in a CALLEE-SAVED register across the strlen
    /// call (x19, spilled in the prologue — mirror of the x64 twin's rbx):
    /// the first cut kept it in x8, which the PCS makes caller-saved, and
    /// the first arm64 execution (CI 2026-09-21) came back all-false when
    /// libc's strlen left a different value there.
    private func arm64MiniImage() -> Data {
        func le32(_ v: UInt32) -> [UInt8] {
            withUnsafeBytes(of: v.littleEndian) { Array($0) }
        }
        let code: [(offset: Int, bytes: [UInt8])] = [
            (0x100, le32(0xA9BF_7BFD)),  // stp x29,x30,[sp,#-16]!
            (0x104, le32(0xA9BF_53F3)),  // stp x19,x20,[sp,#-16]!  (save arg reg)
            (0x108, le32(0xAA00_03F3)),  // mov x19, x0            (save arg, callee-saved)
            (0x10C, le32(0x9000_0000)),  // adrp x0, #0
            (0x110, le32(0x9108_0000)),  // add x0, x0, #0x200    (GLOBAL)
            (0x114, le32(0x9400_001B)),  // bl strlen-stub (0x180)
            (0x118, le32(0x3940_5E69)),  // ldrb w9, [x19, #0x17] (arm64 SSO len)
            (0x11C, le32(0x6B09_001F)),  // cmp w0, w9
            (0x120, le32(0x5400_0161)),  // b.ne ret0 (0x14C)
            (0x124, le32(0xAA13_03E0)),  // mov x0, x19           (arg.data @0)
            (0x128, le32(0x9000_0001)),  // adrp x1, #0
            (0x12C, le32(0x9108_0021)),  // add x1, x1, #0x200    (GLOBAL)
            (0x130, le32(0x2A09_03E2)),  // mov w2, w9            (len)
            (0x134, le32(0x9400_0017)),  // bl memcmp-stub (0x190)
            (0x138, le32(0x7100_001F)),  // cmp w0, #0
            (0x13C, le32(0x1A9F_17E0)),  // cset w0, eq
            (0x140, le32(0xA8C1_53F3)),  // ldp x19,x20,[sp],#16
            (0x144, le32(0xA8C1_7BFD)),  // ldp x29,x30,[sp],#16
            (0x148, le32(0xD65F_03C0)),  // ret
            (0x14C, le32(0x5280_0000)),  // ret0: mov w0, #0
            (0x150, le32(0x17FF_FFFC)),  // b 0x140 (shared epilogue)
            // strlen stub → GOT 0x1C0
            (0x180, le32(0x9000_0010)),  // adrp x16, #0
            (0x184, le32(0xF940_E210)),  // ldr x16, [x16, #0x1C0]
            (0x188, le32(0xD61F_0200)),  // br x16
            // memcmp stub → GOT 0x1C8
            (0x190, le32(0x9000_0010)),  // adrp x16, #0
            (0x194, le32(0xF940_E610)),  // ldr x16, [x16, #0x1C8]
            (0x198, le32(0xD61F_0200)),  // br x16
            // junk GOT slots (worker redirection replaces them)
            (0x1C0, [0x0D, 0xF0, 0xAD, 0x0B, 0xEF, 0xBE, 0xAD, 0xDE]),
            (0x1C8, [0xDE, 0xAD, 0xBE, 0xEF, 0x0E, 0xAA, 0x0F, 0xD0]),
            (0x200, Array("revokems\0".utf8)),
        ]
        return MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: code)
    }

    private var arm64Spec: Verifier.VerifySpec {
        .init(stubs: ["180": "strlen", "190": "memcmp"],
              zeroRegions: [],
              probes: [["revokems", "1"], ["other", "0"], ["", "0"]])
    }

    /// Stub encodings decode against the same decoder the worker uses —
    /// runs on ANY host (this is the local verification of the hand-assembled
    /// arm64 image; execution itself needs an arm64 host).
    @Test func arm64MiniImageStubEncodingsDecode() throws {
        let image = arm64MiniImage()
        func word(_ off: Int) -> UInt32 {
            image.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: off, as: UInt32.self) }
        }
        // stub 形态门：adrp x16 / ldr x16 / br x16 三件套 + 槽位 = 0x1C0 / 0x1C8
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0x180, w0: word(0x180), w1: word(0x184), w2: word(0x188)) == 0x1C0)
        #expect(Verifier.ARM64.stubSlotOffset(pcOffset: 0x190, w0: word(0x190), w1: word(0x194), w2: word(0x198)) == 0x1C8)
        // 桽内的 BL 目标与 MachImage 反解一致（谓词路径同款解码器）
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-armmini-\(UUID().uuidString).dylib")
        try image.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let mach = try MachImage(file: url, arch: .arm64)
        #expect(mach.word32(va: 0x114) == 0x9400_001B)
        #expect(Verifier.ARM64.blTargetVA(word: 0x9400_001B, blVA: 0x114) == 0x180)
    }

    /// Full worker round-trip on the arm64 mini image — the arm64 execution
    /// path acceptance harness. Runs only on arm64 hosts whose environment
    /// passes the executable-memory probe (ARM dev machine, CI runner, or any stock arm64 Mac via MAP_JIT).
    @Test(.disabled(if: VerifierTests.environmentUnsuitable || VerifierTests.hostIsNotARM64,
                   "arm64 host + executable-memory-capable environment required — worker executes mapped code natively"))
    func arm64MiniPredicateClassifiesCorrectly() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-verifier-arm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let dylib = work.appendingPathComponent("arm-mini.dylib")
        try arm64MiniImage().write(to: dylib)

        let results = try Verifier.run(binary: dylib, targetVA: 0x100, spec: arm64Spec,
                                       executable: Self.wxkeepBinary)
        #expect(results.map(\.returned) == [true, false, false])
        #expect(Verifier.verdictPredicate(results: results, spec: arm64Spec) == nil)
    }
}
