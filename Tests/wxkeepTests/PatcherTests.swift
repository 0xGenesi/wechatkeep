import Foundation
import Testing
@testable import wxkeep

final class PatcherTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    private func writeBinary(_ data: Data, name: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func bytes(at url: URL, offset: Int, count: Int) throws -> String {
        let data = try Data(contentsOf: url)
        return data.subdata(in: offset..<offset + count).hexUppercase
    }

    // MARK: thin slices

    @Test func patchThinX86() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]),
            name: "thin-x64.dylib")
        let outcome = try Patcher.patch(
            binary: binary,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E553504889FB"])],
            identifier: "revoke")
        #expect(outcome == [.written])
        #expect(try bytes(at: binary, offset: 0x100, count: 3) == "31C0C3")
    }

    @Test func alreadyPatchedIsIdempotent() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: [
                (0x100, [0x00, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]),
            ]),
            name: "already.dylib")
        let outcome = try Patcher.patch(
            binary: binary,
            entries: [MachOFixture.entry(.arm64, addr: "100", asm: "00008052C0035FD6", expected: ["F44FBEA9FD7B01A9"])],
            identifier: "revoke")
        #expect(outcome == [.alreadyPatched])
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "00008052C0035FD6")
    }

    @Test func expectedVariantsAcceptPatchedState() throws {
        // Variant switching: bytes currently hold the *silent* patch; the entry
        // accepts both pristine and silent → nothing to write.
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: [
                (0x100, [0x82, 0x00, 0x00, 0x14]),  // b SKIP (silent-patched state)
            ]),
            name: "variants.dylib")
        let outcome = try Patcher.patch(
            binary: binary,
            entries: [MachOFixture.entry(.arm64, addr: "100", asm: "82000014", expected: ["40100034", "82000014"])],
            identifier: "revoke")
        #expect(outcome == [.alreadyPatched])
    }

    // MARK: fat slices

    @Test func fatPatchesEachArchInItsOwnSlice() throws {
        let (image, armOffset, x64Offset) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
            ]))
        let binary = try writeBinary(image, name: "fat.dylib")
        let outcomes = try Patcher.patch(
            binary: binary,
            entries: [
                MachOFixture.entry(.arm64, addr: "100", asm: "00008052C0035FD6", expected: ["F44FBEA9FD7B01A9"]),
                MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E553504889FB"]),
            ],
            identifier: "revoke")
        #expect(outcomes == [.written, .written])
        #expect(try bytes(at: binary, offset: armOffset + 0x100, count: 8) == "00008052C0035FD6")
        #expect(try bytes(at: binary, offset: x64Offset + 0x100, count: 3) == "31C0C3")
        // Cross-check: the x86 entry must not have touched the arm64 slice.
        // Slice offset 0x40 is the vmsize field of its LC_SEGMENT_64 (0x400 LE).
        #expect(try bytes(at: binary, offset: armOffset + 0x40, count: 4) == "00040000")
    }

    // MARK: safety contract

    @Test func preflightWritesNothingWhenAnyEntryMismatch() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
                (0x140, [0xDE, 0xAD, 0xBE, 0xEF]),  // foreign bytes
            ]),
            name: "preflight.dylib")
        expectThrows(
            try Patcher.patch(
                binary: binary,
                entries: [
                    MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E553504889FB"]),
                    MachOFixture.entry(.x86_64, addr: "140", asm: "31C0C3", expected: ["11223344"]),
                ],
                identifier: "revoke"))
        // The core guarantee: entry #1 (individually fine) stays untouched.
        #expect(try bytes(at: binary, offset: 0x100, count: 4) == "554889E5")
        #expect(try bytes(at: binary, offset: 0x140, count: 4) == "DEADBEEF")
    }

    @Test func missingExpectedIsQuarantined() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]),
            ]),
            name: "quarantine.dylib")
        let entry = MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: nil)
        expectThrows(try Patcher.patch(binary: binary, entries: [entry], identifier: "revoke"))
        #expect(try bytes(at: binary, offset: 0x100, count: 3) == "554889")

        // Explicit override writes it.
        let outcome = try Patcher.patch(
            binary: binary, entries: [entry], identifier: "revoke", allowUnverified: true)
        #expect(outcome == [.written])
        #expect(try bytes(at: binary, offset: 0x100, count: 3) == "31C0C3")
    }

    @Test func dryRunWritesNothing() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5]),
            ]),
            name: "dryrun.dylib")
        _ = try Patcher.patch(
            binary: binary,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E5"])],
            identifier: "revoke", dryRun: true)
        #expect(try bytes(at: binary, offset: 0x100, count: 4) == "554889E5")
    }

    @Test func outOfRangeVAIsRejected() throws {
        let binary = try writeBinary(MachOFixture.thin(cputype: MachOFixture.x64CPU), name: "range.dylib")
        expectThrows(
            try Patcher.patch(
                binary: binary,
                entries: [MachOFixture.entry(.x86_64, addr: "FFFF00", asm: "31C0C3", expected: ["554889E5"])],
                identifier: "revoke"))
    }

    @Test func noArchMatchThrows() throws {
        let binary = try writeBinary(MachOFixture.thin(cputype: MachOFixture.x64CPU), name: "noarch.dylib")
        expectThrows(
            try Patcher.patch(
                binary: binary,
                entries: [MachOFixture.entry(.arm64, addr: "100", asm: "00008052", expected: ["F44FBEA9"])],
                identifier: "revoke"))
    }

    // MARK: inspect

    @Test func inspectClassifiesStates() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x31, 0xC0, 0xC3]),        // patched
                (0x120, [0x55, 0x48, 0x89, 0xE5]),  // pristine
                (0x140, [0xDE, 0xAD, 0xBE, 0xEF]),  // unknown
            ]),
            name: "inspect.dylib")
        let inspections = try Patcher.inspect(
            binary: binary,
            entries: [
                MachOFixture.entry(.x86_64, addr: "100", asm: "31C0C3", expected: ["554889E5"]),
                MachOFixture.entry(.x86_64, addr: "120", asm: "31C0C3", expected: ["554889E5"]),
                MachOFixture.entry(.x86_64, addr: "140", asm: "31C0C3", expected: ["554889E5"]),
            ],
            identifier: "revoke")
        let states: [Patcher.Inspection.State] = inspections.map(\.state)
        #expect(states == [.patched, .pristine, .unknown])
    }
}

struct ConfigTests {
    @Test func expectedDecodesFromStringOrArray() throws {
        let json = """
        [{"version":"1","targets":[{"identifier":"revoke","entries":[
            {"arch":"x86_64","addr":"40","expected":"554889E5","asm":"31C0C3"},
            {"arch":"arm64","addr":"80","expected":["F44FBEA9","82000014"],"asm":"00008052"}
        ]}]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        let entries = config.entry(build: "1")!.targets[0].entries
        #expect(entries[0].expected?.values == ["554889E5"])
        #expect(entries[1].expected?.values == ["F44FBEA9", "82000014"])
    }

    @Test func badHexFailsFast() {
        let json = """
        [{"version":"1","targets":[{"identifier":"revoke","entries":[
            {"arch":"x86_64","addr":"GG","expected":"554889E5","asm":"31C0C3"}
        ]}]}]
        """
        expectThrows(try Config(data: Data(json.utf8), origin: "inline"))
    }

    @Test func addrAndRecipeAreMutuallyExclusive() {
        let json = """
        [{"version":"1","targets":[{"identifier":"revoke","entries":[
            {"arch":"x86_64","addr":"40","recipe":{"anchor":"imm"},"expected":"554889E5","asm":"31C0C3"}
        ]}]}]
        """
        expectThrows(try Config(data: Data(json.utf8), origin: "inline"))
    }
}

// MARK: - expected 通配（branch-flip 配方化，ROADMAP ①）

final class ExpectedWildcardTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    private func writeBinary(_ data: Data, name: String) throws -> URL {
        let url = workDir.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func bytes(at url: URL, offset: Int, count: Int) throws -> String {
        let data = try Data(contentsOf: url)
        return data.subdata(in: offset..<offset + count).hexUppercase
    }

    /// 解析守卫的配方形态：test al,al; je rel32 → xor al,al（ZF=1 ⇒ je 恒跳），
    /// rel32 逐构建漂移由 `????????` 吸收，asm 与构建无关。
    private let guardEntry = MachOFixture.entry(
        .x86_64, addr: "100", asm: "30C0", expected: ["84C00F84????????"])

    @Test func wildcardAcceptsRel32Drift() throws {
        for disp in [[UInt8(0x3C), 0x11, 0x00, 0x00], [UInt8(0xA6), 0x00, 0x00, 0x00]] {
            let binary = try writeBinary(
                MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                    (0x100, [0x84, 0xC0, 0x0F, 0x84] + disp),
                ]),
                name: "drift-\(disp[0]).dylib")
            let outcome = try Patcher.patch(binary: binary, entries: [guardEntry], identifier: "revoke")
            #expect(outcome == [.written])
            // 只写 asm 跨度（2B）；je 的 opcode 与 disp32 原样留在盘上
            #expect(try bytes(at: binary, offset: 0x100, count: 8)
                    == "30C00F84" + Data(disp).hexUppercase)
        }
    }

    @Test func wildcardRejectsOpcodeDrift() throws {
        let binary = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x84, 0xC0, 0x0F, 0x85, 0x3C, 0x11, 0x00, 0x00]),  // jne ≠ je
            ]),
            name: "opcode-drift.dylib")
        let error = expectThrows(
            try Patcher.patch(binary: binary, entries: [guardEntry], identifier: "revoke"))
        guard case Patcher.PatchError.expectedMismatch = error else {
            Issue.record("expected expectedMismatch, got \(error)")
            return
        }
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "84C00F853C110000")  // 未写入
    }

    @Test func maskSuffixToleratesNibble() throws {
        // byte1 mask F0：低半字节任意（C0/C3 都行），高半字节必须 C
        let entry = MachOFixture.entry(
            .x86_64, addr: "100", asm: "30C0", expected: ["84C0:maskFFF0"])
        for byte1 in [0xC0, 0xC3] {
            let binary = try writeBinary(
                MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                    (0x100, [0x84, UInt8(byte1)]),
                ]),
                name: "mask-\(byte1).dylib")
            #expect(try Patcher.patch(binary: binary, entries: [entry], identifier: "revoke") == [.written])
        }
        let reject = try writeBinary(
            MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
                (0x100, [0x85, 0xC0]),   // 高半字节漂移：拒绝
            ]),
            name: "mask-reject.dylib")
        expectThrows(try Patcher.patch(binary: reject, entries: [entry], identifier: "revoke"))
    }

    @Test func concretePrefixStopsAtFirstWildcard() {
        #expect(ExpectedPattern(spec: "84C00F84????????")!.concretePrefix(2) == Data([0x84, 0xC0]))
        #expect(ExpectedPattern(spec: "84C00F84????????")!.concretePrefix(4) == Data([0x84, 0xC0, 0x0F, 0x84]))
        #expect(ExpectedPattern(spec: "84C00F84????????")!.concretePrefix(5) == nil)
        #expect(ExpectedPattern(spec: "84C00F84????????")!.isFullyConcrete == false)
        #expect(ExpectedPattern(spec: "84C00F84")!.isFullyConcrete == true)
        #expect(ExpectedPattern(spec: "84C?")!.concretePrefix(2) == nil)  // 写入跨度内通配 → 不可物化
        #expect(ExpectedPattern(spec: "84C0:maskFFF0")!.concretePrefix(2) == nil)  // mask 挖空同样阻断
        #expect(ExpectedPattern(spec: "84??C") == nil)   // 奇数半字节
        #expect(ExpectedPattern(spec: "84G0") == nil)    // 非 hex 非通配
        #expect(ExpectedPattern(spec: "84C0:maskZZ") == nil)
    }

    @Test func restoreAsmMaterializesPrefixOnly() {
        // 通配起点在 asm 跨度之外 → 只需物化前缀，恢复可行
        #expect(Engine.restoreAsm(for: guardEntry) == "84C0")
        // 通配渗入写入跨度 → 目录数据不可恢复（须备份/重装）
        let inSpan = MachOFixture.entry(
            .x86_64, addr: "100", asm: "30C0", expected: ["84????0F84????"])
        #expect(Engine.restoreAsm(for: inSpan) == nil)
        // 全具体 → 原样透传（既有条目行为不变）
        let concrete = MachOFixture.entry(
            .x86_64, addr: "100", asm: "30C0", expected: ["84C00F84"])
        #expect(Engine.restoreAsm(for: concrete) == "84C00F84")
        // 全具体但带冗余 :maskFFFF 后缀 → 物化为纯 hex；
        // 若把后缀原样带回，下游 Data(hex:) 强解包会崩
        let masked = MachOFixture.entry(
            .x86_64, addr: "100", asm: "30C0", expected: ["84C0:maskFFFF"])
        #expect(Engine.restoreAsm(for: masked) == "84C0")
        // 归一化条目（asm ∈ expected）：恢复目标 = asm 本身
        let normalized = MachOFixture.entry(
            .x86_64, addr: "100", asm: "31C0C3", expected: ["31C0C3", "554889E5"])
        #expect(Engine.restoreAsm(for: normalized) == "31C0C3")
    }

    /// 端到端：patch（通配门）→ Engine.restoreTargets（前缀物化）→ 字节还原
    /// → 幂等再 restore 判 alreadyPatched。
    @Test func wildcardEntryRoundTripsThroughRestore() throws {
        let app = workDir.appendingPathComponent("WeChat.app", isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let binary = resources.appendingPathComponent("wechat.dylib")
        let pristine: [UInt8] = [0x84, 0xC0, 0x0F, 0x84, 0x3C, 0x11, 0x00, 0x00]
        try MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [(0x100, pristine)]).write(to: binary)

        let target = Config.Target(
            identifier: "revoke", binary: "Contents/Resources/wechat.dylib", entries: [guardEntry])
        _ = try Patcher.patch(binary: binary, entries: [guardEntry], identifier: "revoke")
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "30C00F843C110000")

        let undo = try Engine.restoreTargets(app: app, targets: [target], dryRun: false)
        #expect(undo.wroteAnything)
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "84C00F843C110000")

        let again = try Engine.restoreTargets(app: app, targets: [target], dryRun: false)
        #expect(!again.wroteAnything)   // 幂等：已是原始态
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "84C00F843C110000")
    }

    /// 通配渗入写入跨度的条目：restore 前置拒绝（任何字节都不写）
    @Test func unrestorableWildcardEntryFailsBeforeWrite() throws {
        let app = workDir.appendingPathComponent("WeChat2.app", isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let binary = resources.appendingPathComponent("wechat.dylib")
        try MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
            (0x100, [0x30, 0xC0, 0x0F, 0x84, 0x3C, 0x11, 0x00, 0x00]),  // patched 态
        ]).write(to: binary)
        let bad = MachOFixture.entry(
            .x86_64, addr: "100", asm: "30C0", expected: ["84????0F84????"])
        let target = Config.Target(
            identifier: "revoke", binary: "Contents/Resources/wechat.dylib", entries: [bad])
        let error = expectThrows(try Engine.restoreTargets(app: app, targets: [target], dryRun: false))
        guard case Engine.EngineError.restoreUnavailable = error else {
            Issue.record("expected restoreUnavailable, got \(error)")
            return
        }
        #expect(try bytes(at: binary, offset: 0x100, count: 8) == "30C00F843C110000")  // 未动
    }

    @Test func configValidationAcceptsWildcardExpected() throws {
        let json = """
        [{"version":"270100","targets":[{"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
            {"arch":"x86_64","addr":"100","expected":"84C00F84????????","asm":"30C0"}
        ]}]}]
        """
        let config = try Config(data: Data(json.utf8), origin: "inline")
        #expect(config.entry(build: "270100")!.targets[0].entries[0].expected?.values
               == ["84C00F84????????"])

        let malformed = """
        [{"version":"1","targets":[{"identifier":"revoke","entries":[
            {"arch":"x86_64","addr":"100","expected":"84C0?????","asm":"30C0"}
        ]}]}]
        """
        expectThrows(try Config(data: Data(malformed.utf8), origin: "inline"))
    }
}
