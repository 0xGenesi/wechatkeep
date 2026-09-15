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
}
