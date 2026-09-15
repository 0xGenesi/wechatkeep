import Foundation
import Testing
@testable import wxkeep

final class RecipeEngineTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-recipe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    // MARK: fixture builders

    /// Layout: dead code + padding + function containing a movabs imm64 + decoy
    /// function with the same immediate but no callers.
    private func x64Image(
        entryPrologue: [UInt8] = [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB],
        decoy: Bool = true
    ) throws -> (url: URL, entryVA: Int, decoyVA: Int?) {
        var code: [(Int, [UInt8])] = []
        // boundary before the real function: previous function's ret + padding
        code.append((0xF0, [0xC3]))
        code.append((0xF1, [UInt8](repeating: 0xCC, count: 0xF)))
        // real function at 0x100: prologue, movabs rax imm64("revokems"), padding, ret
        var fn = entryPrologue
        fn += [0x48, 0xB8] + Array("revokems".utf8)
        fn += Array(repeating: 0x90, count: 4)
        fn += [0xC3]
        code.append((0x100, fn))
        // caller site at 0x180: call rel32 → 0x100
        let disp = 0x100 - (0x180 + 5)
        code.append((0x180, [0xE8] + withUnsafeBytes(of: Int32(disp).littleEndian) { Array($0) }))
        var decoyVA: Int? = nil
        if decoy {
            // decoy at 0x200: previous ret + padding boundary, own movabs, no callers
            var d = entryPrologue
            d += [0x48, 0xB8] + Array("revokems".utf8)
            d += [0xC3]
            code.append((0x1FF, [0xC3]))            // boundary before decoy
            code.append((0x200, [0xCC, 0xCC]))       // padding
            code.append((0x202, d))
            decoyVA = 0x202
            _ = decoyVA
        }
        let image = MachOFixture.thin(cputype: MachOFixture.x64CPU, code: code)
        let url = workDir.appendingPathComponent("recipe-x64.dylib")
        try image.write(to: url)
        return (url, 0x100, decoyVA)
    }

    // MARK: tests

    @Test func resolvesX64RevokeRecipe() throws {
        let (url, entryVA, _) = try x64Image()
        let image = try MachImage(file: url, arch: .x86_64)
        let recipe = RecipeEngine.Recipe(
            anchor: "imm64:revokems", derive: "padding-boundary",
            confirm: ["unique-positive-callers"])
        let va = try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64)
        #expect(va == UInt64(entryVA))
    }

    @Test func decoyWithoutCallersIsFiltered() throws {
        // The decoy carries the same immediate; only the called entry survives.
        let (url, entryVA, _) = try x64Image(decoy: true)
        let image = try MachImage(file: url, arch: .x86_64)
        let recipe = RecipeEngine.Recipe(
            anchor: "imm64:revokems", derive: "padding-boundary",
            confirm: ["unique-positive-callers"])
        #expect(try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64) == UInt64(entryVA))
    }

    @Test func twoCalledCandidatesAreAmbiguous() throws {
        // Second caller site calls the decoy too → both survive → refuse.
        let (url, _, decoyVA) = try x64Image()
        guard let decoy = decoyVA else { return }
        var data = try Data(contentsOf: url)
        let callSite = 0x188
        let disp = decoy - (callSite + 5)
        data.replaceSubrange(callSite..<(callSite+5),
                             with: [0xE8] + withUnsafeBytes(of: Int32(disp).littleEndian) { Array($0) })
        let patchedURL = workDir.appendingPathComponent("ambig.dylib")
        try data.write(to: patchedURL)
        let image = try MachImage(file: patchedURL, arch: .x86_64)
        let recipe = RecipeEngine.Recipe(
            anchor: "imm64:revokems", derive: "padding-boundary",
            confirm: ["unique-positive-callers"])
        expectThrows(try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64))
    }

    @Test func missingAnchorIsNoHit() throws {
        let (url, _, _) = try x64Image()
        let image = try MachImage(file: url, arch: .x86_64)
        let recipe = RecipeEngine.Recipe(anchor: "imm64:sysmsgxx", derive: "self", confirm: [])
        expectThrows(try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64))
    }

    @Test func resolvesArm64GeometricRecipe() throws {
        // gen3 shape: cbz at site, str x0 [x19,#imm] at +0x7a0 (Rt masked)
        let cbz: [UInt8] = [0x40, 0x10, 0x00, 0x34]
        let strX0: [UInt8] = [0x60, 0xE6, 0x00, 0xF9]
        let decoyCbz: [UInt8] = [0x40, 0x10, 0x00, 0x34]
        let image = MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0xA00, code: [
            (0x200, cbz),
            (0x200 + 0x7A0, strX0),
            (0x600, decoyCbz),                      // decoy without second anchor
        ])
        let url = workDir.appendingPathComponent("recipe-arm64.dylib")
        try image.write(to: url)
        let mach = try MachImage(file: url, arch: .arm64)
        let recipe = RecipeEngine.Recipe(
            anchor: "bytes:40100034", derive: "self",
            confirm: ["bytes@+7A0:60E600F9:maskFFFFFFE0"])
        #expect(try RecipeEngine.resolve(recipe: recipe, image: mach, arch: .arm64) == 0x200)
    }

    @Test func recipeEntryPatchesThroughPatcher() throws {
        // End-to-end: config entry carrying a recipe (no addr) resolves inside
        // Patcher and writes under the expected-byte gate.
        let (url, entryVA, _) = try x64Image()
        var entry = MachOFixture.entry(
            .x86_64, addr: "", asm: "31C0C3",
            expected: ["554889E553504889FB"])
        entry.addr = nil
        entry.recipe = ["anchor": "imm64:revokems", "derive": "padding-boundary",
                        "confirm": "unique-positive-callers"]
        let outcomes = try Patcher.patch(
            binary: url, entries: [entry], identifier: "revoke")
        #expect(outcomes == [.written])
        let data = try Data(contentsOf: url)
        #expect(data.subdata(in: entryVA..<(entryVA+3)).hexUppercase == "31C0C3")
    }

    @Test func recipeResolutionStillRespectsExpectedGate() throws {
        // Prologue differs from expected → resolution succeeds but the write
        // is refused (recipe picks WHERE; the gate decides WHETHER).
        let (url, _, _) = try x64Image(
            entryPrologue: [0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41])
        var entry = MachOFixture.entry(.x86_64, addr: "", asm: "31C0C3",
                                       expected: ["554889E553504889FB"])
        entry.addr = nil
        entry.recipe = ["anchor": "imm64:revokems", "derive": "padding-boundary",
                        "confirm": "unique-positive-callers"]
        expectThrows(try Patcher.patch(binary: url, entries: [entry], identifier: "revoke"))
        let data = try Data(contentsOf: url)
        #expect(data[0x100] == 0x55, "nothing may be written when the gate fails")
    }
}
