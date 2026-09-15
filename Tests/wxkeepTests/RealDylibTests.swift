import Foundation
import Testing
@testable import wxkeep

/// Full-chain integration against the REAL 269602 fat dylib (327 MB):
/// patch → inspect → restore → inspect, plus recipe resolution on the
/// pristine image. Runs only when WXKEEP_REAL_DYLIB points at the pristine
/// backup (dev machines); CI runners have no WeChat and skip cleanly.
struct RealDylibTests {
    private static var realDylib: URL? {
        guard let path = ProcessInfo.processInfo.environment["WXKEEP_REAL_DYLIB"],
              FileManager.default.fileExists(atPath: path) else { return nil }
        return URL(fileURLWithPath: path)
    }

    @Test(.disabled(if: realDylib == nil, "WXKEEP_REAL_DYLIB not set — real-dylib chain skipped"))
    func patchInspectRestoreChainOnReal269602() throws {
        let source = try #require(Self.realDylib)
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-real-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        // Work on a copy — never the backup itself.
        let dylib = work.appendingPathComponent("wechat.dylib")
        try FileManager.default.copyItem(at: source, to: dylib)

        let catalogJSON = """
        [{"version":"269602","targets":[
            {"identifier":"revoke","binary":"x","entries":[
                {"arch":"arm64","addr":"44DE938","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
                {"arch":"x86_64","addr":"4BC5940","expected":"554889E553504889FB","asm":"31C0C3909090909090","source":"wxkeep-analysis"}
            ]}
        ]}]
        """
        let config = try Config(data: Data(catalogJSON.utf8), origin: "inline")
        let entry = config.entry(build: "269602")!
        let entries = entry.targets[0].entries

        // 0. pristine: recipe resolves the known x64 address on the REAL image.
        let image = try MachImage(file: dylib, arch: .x86_64)
        let recipe = try RecipeEngine.Recipe(
            anchor: "imm64:revokems", derive: "padding-boundary",
            confirm: ["unique-positive-callers"])
        #expect(try RecipeEngine.resolve(recipe: recipe, image: image, arch: .x86_64) == 0x4BC5940)

        // 1. pristine inspect: both arches pristine.
        var states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.pristine, .pristine])

        // 2. patch both slices.
        let outcomes = try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
        #expect(outcomes == [.written, .written])
        states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.patched, .patched])

        // 3. idempotent re-patch.
        let again = try Patcher.patch(binary: dylib, entries: entries, identifier: "revoke")
        #expect(again == [.alreadyPatched, .alreadyPatched])

        // 4. recipe STILL resolves on the patched image (two-boundary design).
        let image2 = try MachImage(file: dylib, arch: .x86_64)
        #expect(try RecipeEngine.resolve(recipe: recipe, image: image2, arch: .x86_64) == 0x4BC5940)

        // 5. restore inversion returns both slices to pristine.
        let inverted = entries.map { e -> Config.PatchEntry in
            var copy = e
            copy.asm = e.expected!.values[0]
            copy.expected = Config.ExpectedVariants([e.asm] + e.expected!.values)
            return copy
        }
        let restored = try Patcher.patch(binary: dylib, entries: inverted, identifier: "revoke")
        #expect(restored == [.written, .written])
        states = try Patcher.inspect(binary: dylib, entries: entries, identifier: "revoke")
        #expect(states.map(\.state) == [.pristine, .pristine])
    }
}
