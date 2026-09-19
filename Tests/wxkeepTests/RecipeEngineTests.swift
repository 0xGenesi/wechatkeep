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

struct AutoLocateTests {
    /// 回归（locate --append 跨 binary 分组）：gen0 主程序配方与 wechat.dylib
    /// 配方同轮命中时，条目必须落进各自 binary 的 Target——旧实现把全部条目
    /// 池进一个 "revoke" 组，Target.binary 取 recipes.values.first（字典迭代
    /// 序不定），主程序条目会被贴上 dylib 的 binary，expected 门去错误的文件
    /// 上校验，patch 必然 expectedMismatch。
    @Test func mergeLocatedSplitsEntriesByBinary() {
        var versionEntry = Config.VersionEntry(version: "33480", targets: [
            Config.Target(identifier: "revoke", binary: "Contents/Resources/wechat.dylib", entries: [
                MachOFixture.entry(.arm64, addr: "100", asm: "00008052C0035FD6",
                                   expected: ["F44FBEA9FD7B01A9"]),
            ])
        ])
        let located: [(binary: String?, identifier: String, entry: Config.PatchEntry)] = [
            ("Contents/Resources/wechat.dylib", "revoke",
             MachOFixture.entry(.x86_64, addr: "200", asm: "31C0C3909090909090",
                                expected: ["554889E553504889FB"], source: "recipe:revoke_x64")),
            ("Contents/MacOS/WeChat", "revoke",
             MachOFixture.entry(.arm64, addr: "3CBE7B0", asm: "00008052C0035FD6",
                                expected: ["F44FBEA9FD7B01A9"], source: "recipe:revoke_arm64_gen0")),
        ]
        Engine.mergeLocated(located, into: &versionEntry)

        // dylib 条目并入既有 Target（arch 去重：arm64 已在场，仅追加 x86_64）
        let dylibTarget = versionEntry.targets.first {
            $0.identifier == "revoke" && $0.binary == "Contents/Resources/wechat.dylib"
        }
        #expect(dylibTarget?.entries.count == 2)
        #expect(dylibTarget?.entries.map(\.arch) == [.arm64, .x86_64])

        // 主程序条目必须独立成 Target：binary 正确，不被并进 dylib 组
        let mainTarget = versionEntry.targets.first {
            $0.identifier == "revoke" && $0.binary == "Contents/MacOS/WeChat"
        }
        #expect(mainTarget?.entries.count == 1)
        #expect(mainTarget?.entries.first?.addr == "3CBE7B0")
    }

    /// 同 arch 已在场时 recipe 条目不重复追加（精编条目优先，合并幂等）
    @Test func mergeLocatedDedupesByArch() {
        var versionEntry = Config.VersionEntry(version: "270099", targets: [
            Config.Target(identifier: "revoke", binary: "Contents/Resources/wechat.dylib", entries: [
                MachOFixture.entry(.x86_64, addr: "4e8d440", asm: "31C0C3909090909090",
                                   expected: ["554889E553504889FB"]),
            ])
        ])
        let located: [(binary: String?, identifier: String, entry: Config.PatchEntry)] = [
            ("Contents/Resources/wechat.dylib", "revoke",
             MachOFixture.entry(.x86_64, addr: "537de29", asm: "30C0",
                                expected: ["84C00F84????????"])),
        ]
        Engine.mergeLocated(located, into: &versionEntry)
        #expect(versionEntry.targets.count == 1)
        #expect(versionEntry.targets[0].entries.count == 1, "同 arch 已有精编条目，recipe 条目不追加")
    }

    /// 配方名 → identifier 归类：update*/multiInstance* 前缀进各自目标域，
    /// 未知前缀保守归 revoke（现役行为）。硬编码 "revoke" 的旧实现会把
    /// update 配方错标成变体域目标——silent 才应用、keeptip 漏打。
    @Test func recipeNameMapsToTargetIdentifier() {
        #expect(Engine.identifier(forRecipeName: "revoke_x64") == "revoke")
        #expect(Engine.identifier(forRecipeName: "revoke_arm64_gen3") == "revoke")
        #expect(Engine.identifier(forRecipeName: "parse_guard_x64") == "revoke")
        #expect(Engine.identifier(forRecipeName: "update_x64") == "update")
        #expect(Engine.identifier(forRecipeName: "UpdateManager") == "update")
        #expect(Engine.identifier(forRecipeName: "multiInstance_gen1") == "multiInstance")
    }

    /// update 配方条目与 revoke 条目同轮 locate 时必须落进不同 Target
    /// （identifier+binary 双键分组），且不吞并既有 revoke 目标。
    @Test func mergeLocatedSeparatesUpdateFromRevoke() {
        var versionEntry = Config.VersionEntry(version: "270100", targets: [
            Config.Target(identifier: "revoke", binary: "Contents/Resources/wechat.dylib", entries: [
                MachOFixture.entry(.x86_64, addr: "4e8d5d0", asm: "31C0C3909090909090",
                                   expected: ["554889E553504889FB"]),
            ])
        ])
        let located: [(binary: String?, identifier: String, entry: Config.PatchEntry)] = [
            ("Contents/Resources/wechat.dylib", "update",
             MachOFixture.entry(.x86_64, addr: "6c00000", asm: "C3",
                                expected: ["554889E5"], source: "recipe:update_x64")),
        ]
        Engine.mergeLocated(located, into: &versionEntry)
        #expect(versionEntry.targets.count == 2)
        let updateTarget = versionEntry.targets.first { $0.identifier == "update" }
        #expect(updateTarget?.entries.count == 1)
        #expect(versionEntry.targets.first { $0.identifier == "revoke" }?.entries.count == 1)
    }

    /// Signatures.load 的 hex 门：auto-locate 合成条目绕过 Config.validate，
    /// 坏 asm/expected 会让 Patcher 的 Data(hex:) 强解包 trap——必须在装载期
    /// 拒成干净的 malformed 错误。
    @Test func signaturesLoadRejectsBadHex() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-sig-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let badAsm = """
        {"recipes":{"r1":{"arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
        "expected":"554889E553504889FB","asm":"31C0C390909090909","binary":null}}}
        """
        try badAsm.write(to: dir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)
        #expect(throws: (any Error).self) {
            _ = try Signatures.load(explicit: dir.appendingPathComponent("signatures.json").path)
        }

        let badExpected = """
        {"recipes":{"r1":{"arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
        "expected":"ZZGG","asm":"31C0C3","binary":null}}}
        """
        try badExpected.write(to: dir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)
        #expect(throws: (any Error).self) {
            _ = try Signatures.load(explicit: dir.appendingPathComponent("signatures.json").path)
        }

        // 合法通配形态不受影响
        let wild = """
        {"recipes":{"r1":{"arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
        "expected":"84C00F84????????","asm":"30C0","binary":null}}}
        """
        try wild.write(to: dir.appendingPathComponent("signatures.json"), atomically: true, encoding: .utf8)
        let signatures = try Signatures.load(explicit: dir.appendingPathComponent("signatures.json").path)
        #expect(signatures.recipes["r1"]?.asm == "30C0")
    }

    @Test func autoLocatedEntrySynthesizesAndPatches() throws {
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-autolocate-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: workDir) }
        let app = workDir.appendingPathComponent("Fake.app/Contents/Resources")
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)

        // Real-shaped fixture: boundary + called function containing the imm64.
        let fn: [UInt8] = [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB,
                           0x48, 0xB8] + Array("revokems".utf8) + [0x90, 0x90, 0xC3]
        let disp = 0x100 - (0x180 + 5)
        let image = MachOFixture.thin(cputype: MachOFixture.x64CPU, code: [
            (0xF0, [0xC3]), (0xF1, [UInt8](repeating: 0xCC, count: 0xF)),
            (0x100, fn),
            (0x180, [0xE8] + withUnsafeBytes(of: Int32(disp).littleEndian) { Array($0) }),
        ])
        try image.write(to: app.appendingPathComponent("wechat.dylib"))
        let infoPlist = """
        <?xml version="1.0"?><plist version="1.0"><dict>
        <key>CFBundleVersion</key><string>777777</string>
        </dict></plist>
        """
        try infoPlist.data(using: .utf8)!.write(to: workDir.appendingPathComponent("Fake.app/Contents/Info.plist"))

        let signatures = Signatures(recipes: [
            "test_revoke_x64": .init(
                arch: .x86_64, anchor: "imm64:revokems", derive: "padding-boundary",
                confirm: "unique-positive-callers",
                expected: "554889E553504889FB", asm: "31C0C3909090909090",
                binary: "Contents/Resources/wechat.dylib"),
        ])
        guard let entry = Engine.autoLocatedEntry(app: workDir.appendingPathComponent("Fake.app"),
                                                  signatures: signatures) else {
            Issue.record("auto-locate synthesized nothing")
            return
        }
        #expect(entry.version == "777777")
        #expect(entry.targets.count == 1)
        #expect(entry.targets[0].entries[0].addr == "100")
        #expect(entry.targets[0].entries[0].source == "recipe:test_revoke_x64")

        // The synthesized entry flows straight into the patch path.
        let summary = try Engine.patch(
            app: workDir.appendingPathComponent("Fake.app"), versionEntry: entry,
            variant: "silent", dryRun: false, allowUnverified: false, only: nil)
        #expect(summary.wroteAnything)
        let patched = try Data(contentsOf: app.appendingPathComponent("wechat.dylib"))
        #expect(patched.subdata(in: 0x100..<0x103).hexUppercase == "31C0C3")
    }
}
