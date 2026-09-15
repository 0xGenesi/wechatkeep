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
