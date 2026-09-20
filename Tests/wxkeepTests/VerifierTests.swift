import Foundation
import Testing
@testable import wxkeep

/// Behavioral-verifier tests against a synthetic mini image (no Mach-O
/// structure needed — the worker maps the whole file with VA == file offset).
/// The worker host is the built wxkeep binary (the test runner has no
/// __verify-worker dispatch). Skipped where SIP would block RWX mapping.
struct VerifierTests {
    /// RWX-mapping gate keyed on AMFI, not SIP — GitHub runners report SIP
    /// disabled yet AMFI still refuses unsigned executable memory (the exact
    /// SIP≠AMFI independence this project's doctor documents; the gate itself
    /// fell into that trap when it checked csrutil). The boot-arg is the
    /// real switch for executing mapped code.
    private static var environmentUnsuitable: Bool {
        if VerifierTests.wxkeepBinary == nil { return true }
        let nvram = Shell.run("/usr/sbin/nvram", ["boot-args"])
        return !(nvram.status == 0 && nvram.stdout.contains("amfi_get_out_of_my_way"))
    }

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

    @Test(.disabled(if: VerifierTests.environmentUnsuitable,
                   "SIP/AMFI on or no built binary — behavioral mapping needs the dev machine"))
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

    @Test(.disabled(if: VerifierTests.environmentUnsuitable,
                   "SIP/AMFI on or no built binary — behavioral mapping needs the dev machine"))
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
}
