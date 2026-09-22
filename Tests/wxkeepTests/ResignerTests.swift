import Foundation
import Testing
@testable import wxkeep

/// Resigner tests. The pipeline pieces that don't need real codesign run as
/// plain unit tests; the end-to-end test builds a codesignable mini .app,
/// pre-signs its executable WITH entitlements, patches, re-signs through the
/// real pipeline, and asserts strict verification passes and the profile
/// survived (the exact regression class that killed WeChat in production for
/// predecessor projects).
final class ResignerTests {
    let workDir: URL

    init() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-resign-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: workDir) }

    // MARK: - unit level

    @Test func candidatesEnumerateCodeObjects() throws {
        let app = workDir.appendingPathComponent("Cand.app")
        let fm = FileManager.default
        for dir in ["Contents/MacOS", "Contents/Resources", "Contents/Frameworks/Foo.framework",
                    "Contents/PlugIns/Share.appex/Contents/MacOS"] {
            try fm.createDirectory(at: app.appendingPathComponent(dir), withIntermediateDirectories: true)
        }
        let mainURL = app.appendingPathComponent("Contents/MacOS/WeChat")
        try Data([0x55]).write(to: mainURL)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: mainURL.path)
        try Data([0x55]).write(to: app.appendingPathComponent("Contents/Resources/wechat.dylib"))
        try Data([0x55]).write(to: app.appendingPathComponent("Contents/Frameworks/libx.so"))
        try Data([0x55]).write(to: app.appendingPathComponent("Contents/PlugIns/Share.appex/Contents/MacOS/Share"))
        try Data([0x55]).write(to: app.appendingPathComponent("Contents/Resources/data.bin"))  // not code
        try fm.createSymbolicLink(atPath: app.appendingPathComponent("Contents/Resources/link.dylib").path,
                              withDestinationPath: "../Resources/wechat.dylib")

        let candidates = Resigner.codeSigningCandidates(app: app).map(\.lastPathComponent).sorted()
        #expect(candidates.contains("Cand.app"))
        #expect(candidates.contains("WeChat"))
        #expect(candidates.contains("wechat.dylib"))
        #expect(candidates.contains("libx.so"))
        #expect(candidates.contains("Share.appex"))
        #expect(!candidates.contains("data.bin"))
        #expect(!candidates.contains("link.dylib"))
        // the appex's inner executable is covered by signing the appex itself
        #expect(!candidates.contains("Share"))
    }

    @Test func plistsEqualIsSemantic() {
        let a: [String: Any] = ["com.apple.security.app-sandbox": true, "b.key": Data([1])]
        let b: [String: Any] = ["b.key": Data([1]), "com.apple.security.app-sandbox": true]  // reordered
        let c: [String: Any] = ["com.apple.security.app-sandbox": false]
        #expect(Resigner.plistsEqual(a, b))
        #expect(!Resigner.plistsEqual(a, c))
        #expect(Resigner.plistsEqual(nil, nil))
        #expect(!Resigner.plistsEqual(a, nil))
    }

    @Test func inspectEntitlementsOnUnsignedFileReturnsNil() throws {
        let url = workDir.appendingPathComponent("plain.bin")
        try Data([0x55, 0x48]).write(to: url)
        #expect(Resigner.inspectEntitlements(url) == nil)
    }

    // MARK: - end-to-end with real codesign

    // The integration test compiles REAL binaries with clang at runtime —
    // synthetic Mach-O never survives codesign's strict validation, and the
    // production path always deals with compiler output anyway.
    private func compile(_ source: String, name: String, args: [String]) throws -> URL {
        let src = workDir.appendingPathComponent(name + ".c")
        try source.data(using: .utf8)!.write(to: src)
        let out = workDir.appendingPathComponent(name)
        let result = Shell.run("/usr/bin/clang", args + [src.path, "-o", out.path])
        guard result.status == 0 else {
            throw DummyError2(result.stderr)
        }
        return out
    }

    @Test func fullPipelinePreservesEntitlementsAndVerifies() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/codesign"),
              FileManager.default.isExecutableFile(atPath: "/usr/bin/clang") else {
            Issue.record("codesign/clang unavailable — cannot run integration test")
            return
        }
        let app = workDir.appendingPathComponent("Fake.app")
        let fm = FileManager.default
        try fm.createDirectory(at: app.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        try fm.createDirectory(at: app.appendingPathComponent("Contents/Resources"), withIntermediateDirectories: true)

        // Real main executable + real dylib carrying a unique 9-byte marker.
        let marker: [UInt8] = [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]
        let main = try compile("int main(void) { return 0; }\n", name: "FakeMain", args: [])
        let dylib = try compile(
            """
            const unsigned char wxkeep_site[9] = {0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB};
            int wxkeep_keep(void) { return wxkeep_site[0] + wxkeep_site[8]; }
            """,
            name: "libwx.dylib", args: ["-shared"])
        try fm.copyItem(at: main, to: app.appendingPathComponent("Contents/MacOS/WeChat"))
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: app.appendingPathComponent("Contents/MacOS/WeChat").path)
        try fm.copyItem(at: dylib, to: app.appendingPathComponent("Contents/Resources/wechat.dylib"))

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>CFBundleIdentifier</key><string>org.wxkeep.fake</string>
          <key>CFBundleExecutable</key><string>WeChat</string>
          <key>CFBundleVersion</key><string>999999</string>
        </dict></plist>
        """
        try plist.data(using: .utf8)!.write(to: app.appendingPathComponent("Contents/Info.plist"))

        // Pre-sign the main executable WITH a profile — this is what must survive.
        let profileURL = workDir.appendingPathComponent("ent.plist")
        try """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>com.apple.security.app-sandbox</key><true/>
          <key>com.apple.security.network-client</key><true/>
        </dict></plist>
        """.data(using: .utf8)!.write(to: profileURL)
        let pre = Shell.run("/usr/bin/codesign",
            ["-f", "-s", "-", "--entitlements", profileURL.path,
             app.appendingPathComponent("Contents/MacOS/WeChat").path])
        guard pre.status == 0 else {
            Issue.record("codesign refused the executable: \(pre.stderr)")
            return
        }

        // Locate the marker in the real dylib → VA via MachImage segments.
        let dylibURL = app.appendingPathComponent("Contents/Resources/wechat.dylib")
        let blob = try Data(contentsOf: dylibURL)
        guard let hit = blob.range(of: Data(marker)) else {
            Issue.record("marker not emitted into dylib")
            return
        }
        // marker file offset → VA via the segment table of the real dylib.
        // clang compiles for the HOST arch — pick the matching slice or the
        // image lookup fails on the other-arch CI runners.
        #if arch(arm64)
        let hostArch = Config.Arch.arm64
        #else
        let hostArch = Config.Arch.x86_64
        #endif
        let image = try MachImage(file: dylibURL, arch: hostArch)
        var markerVA: UInt64? = nil
        for seg in image.segments {
            let segStart = Int(seg.fileoff), segEnd = Int(seg.fileoff) + Int(seg.vmsize)
            if hit.lowerBound >= segStart && hit.lowerBound < segEnd {
                markerVA = seg.vmaddr + UInt64(hit.lowerBound - segStart)
                break
            }
        }
        guard let mva = markerVA else {
            Issue.record("marker outside any segment")
            return
        }

        let catalog = """
        [{"version":"999999","targets":[
            {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
                {"arch":"\(hostArch.rawValue)","addr":"\(String(mva, radix: 16))",
                 "expected":"554889E553504889FB","asm":"31C0C3909090909090"}
            ]}
        ]}]
        """
        let config = try Config(data: Data(catalog.utf8), origin: "inline")
        let summary = try Engine.patch(
            app: app, build: "999999", config: config, variant: "silent",
            dryRun: false, allowUnverified: false, only: nil)
        #expect(summary.wroteAnything)
        #expect(summary.patchedBinaries == ["Contents/Resources/wechat.dylib"])

        try Resigner.resign(app: app, patchedBinaries: summary.patchedBinaries)

        // 1. Strict verification passes.
        let verify = Shell.run("/usr/bin/codesign",
            ["--verify", "--deep", "--strict", "--verbose=2", app.path])
        #expect(verify.status == 0, "strict verify failed: \(verify.stderr)")

        // 2. The pre-existing entitlements survived re-signing.
        let profile = Resigner.inspectEntitlements(app.appendingPathComponent("Contents/MacOS/WeChat"))
        #expect(profile?["com.apple.security.app-sandbox"] != nil,
                "sandbox entitlement lost — the exact production killer")
        #expect(profile?["com.apple.security.network-client"] != nil)

        // 3. Patch bytes still in place after all the signing churn.
        let patched = try Data(contentsOf: dylibURL)
        #expect(patched.range(of: Data([0x31, 0xC0, 0xC3])) != nil)
        #expect(patched.range(of: Data(marker)) == nil)
    }

    /// Drift 恢复的 profile 按对象终态选择：重签集成员恢复 original+injected，
    /// 未触碰对象恢复原始 profile。旧实现一律用 resignPlist——未触碰对象被盖上
    /// 注入键后，复查按原始 profile 比对必然再判 drift，恢复分支不可收敛。
    @Test func driftRepairProfilePerObjectEndState() {
        let patched = workDir.appendingPathComponent("patched.dylib")
        let untouched = workDir.appendingPathComponent("untouched.dylib")
        let original: [String: Any] = ["com.apple.security.app-sandbox": true]
        var withInjection = original
        for (k, v) in Resigner.injectedKeys where withInjection[k] == nil { withInjection[k] = v }
        let snapshot = Resigner.Snapshot(entries: [
            Resigner.Entry(url: patched, plist: original, resignPlist: withInjection),
            Resigner.Entry(url: untouched, plist: original, resignPlist: withInjection),
        ])
        let resigned: Set<String> = [patched.standardizedFileURL.path]

        let repairPatched = Resigner.driftRepairProfile(snapshot, resigned: resigned, url: patched)
        let repairUntouched = Resigner.driftRepairProfile(snapshot, resigned: resigned, url: untouched)
        #expect(repairPatched?.count == withInjection.count,
                "resigned-set members restore original+injected")
        #expect(repairUntouched?.count == original.count,
                "untouched objects restore their ORIGINAL profile (old behavior re-stamped injected keys and could never converge)")
        #expect(repairUntouched?["com.apple.security.cs.disable-library-validation"] == nil)

        // 无 entitlements 的对象 → nil（重签不带 entitlements）
        let bare = workDir.appendingPathComponent("bare.dylib")
        let bareSnapshot = Resigner.Snapshot(
            entries: [Resigner.Entry(url: bare, plist: nil, resignPlist: nil)])
        #expect(Resigner.driftRepairProfile(bareSnapshot, resigned: [], url: bare) == nil)
        #expect(Resigner.driftRepairProfile(bareSnapshot,
                                            resigned: [bare.standardizedFileURL.path],
                                            url: bare) == nil)
    }
}

struct DummyError2: Error { let message: String; init(_ m: String) { message = m } }
