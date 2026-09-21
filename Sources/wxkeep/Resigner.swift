import Foundation

/// Re-signs a patched app bundle while preserving every original entitlement.
///
/// The hard-learned contract from predecessor projects (zengtianli issue #1038
/// and our own on-device SIGKILL):
/// 1. Snapshot entitlements of every code object BEFORE touching signatures.
/// 2. Patched nested binaries get signed first (with their own profile +
///    library-validation/unsigned-memory keys injected) so the outer --deep
///    pass wraps a validly-signed dylib.
/// 3. Root gets a shallow pass (no --deep — see resign() step 2; nested code
///    that was never touched keeps its original signature).
/// 4. Drift check: every snapshotted profile must survive, semantically equal;
///    drifted objects are re-signed explicitly, deepest-first.
/// 5. `codesign --verify --deep --strict` must pass before we report success.
///
/// Known limitation (reassessed 2026-09): ad-hoc + restricted entitlements on
/// macOS 15+ is NOT a kill prediction — mainstream tools ship exactly this
/// configuration on stock SIP-on machines (the sunnyyoung #1038 crashes came
/// from entitlements being STRIPPED, not kept). Doctor reports it as
/// watch-level with a crash-log triage command; AMFI boot-args are no longer
/// prescribed. macOS 15+ additionally needs --force-library-entitlements or
/// codesign silently drops entitlements on nested libraries (added in sign()).
enum Resigner {
    enum ResignError: Error, CustomStringConvertible {
        case snapshotFailed(String)
        case signFailed(path: String, stderr: String)
        case entitlementsDrift([String])
        case verifyFailed(String)

        var description: String {
            switch self {
            case .snapshotFailed(let detail):
                "entitlements snapshot failed: \(detail)"
            case .signFailed(let path, let stderr):
                "codesign failed for \(path): \(stderr)"
            case .entitlementsDrift(let paths):
                "entitlements drifted after re-signing (refusing to claim success): "
                + paths.joined(separator: ", ")
            case .verifyFailed(let stderr):
                "codesign --verify --deep --strict failed: \(stderr)"
            }
        }
    }

    // MARK: - Snapshot

    struct Entry {
        let url: URL
        /// Original entitlements plist (nil = none / not signed code).
        let plist: [String: Any]?
        /// Profile to re-sign with: original + injected runtime keys (nil = none).
        let resignPlist: [String: Any]?
    }

    struct Snapshot {
        let entries: [Entry]

        func plist(for url: URL) -> [String: Any]? {
            entries.first { $0.url.standardizedFileURL.path == url.standardizedFileURL.path }?.plist
        }
        func resignPlist(for url: URL) -> [String: Any]? {
            entries.first { $0.url.standardizedFileURL.path == url.standardizedFileURL.path }?.resignPlist
        }
    }

    /// Keys injected into every NON-EMPTY profile (idempotently):
    /// without disable-library-validation the first framework load aborts after
    /// re-signing strips the Tencent team id; without unsigned-executable-memory
    /// wechat.dylib gets SIGKILLed when it jumps into plain mmap'd RX pages.
    static let injectedKeys: [String: Bool] = [
        "com.apple.security.cs.disable-library-validation": true,
        "com.apple.security.cs.allow-unsigned-executable-memory": true,
    ]

    static func capture(app: URL) throws -> Snapshot {
        var entries: [Entry] = []
        for candidate in codeSigningCandidates(app: app) {
            let plist = inspectEntitlements(candidate)
            // Profile to re-sign with: original + injected runtime keys.
            // Empty profiles stay empty (stamping keys onto key-less code is
            // its own failure mode).
            var resign: [String: Any]? = nil
            if var p = plist {
                for (key, value) in injectedKeys where p[key] == nil {
                    p[key] = value
                }
                resign = p
            }
            entries.append(Entry(url: candidate, plist: plist, resignPlist: resign))
        }
        guard !entries.isEmpty else {
            throw ResignError.snapshotFailed("no code objects found under \(app.path)")
        }
        return Snapshot(entries: entries)
    }

    /// All plausibly-signed code objects in the bundle: nested bundles by
    /// directory extension, dylibs/so by file extension, plus any executable
    /// file. Symlinks are skipped (they re-sign their target).
    static func codeSigningCandidates(app: URL) -> [URL] {
        let fm = FileManager.default
        guard let walker = fm.enumerator(at: app, includingPropertiesForKeys: [
            .isDirectoryKey, .isSymbolicLinkKey, .isExecutableKey, .isRegularFileKey,
        ], options: [.skipsHiddenFiles]) else { return [] }

        var out: [URL] = []
        for case let url as URL in walker {
            let values = try? url.resourceValues(forKeys: [
                .isDirectoryKey, .isSymbolicLinkKey, .isExecutableKey, .isRegularFileKey,
            ])
            if values?.isSymbolicLink == true { continue }
            let ext = url.pathExtension.lowercased()
            if values?.isDirectory == true {
                if ["app", "appex", "bundle", "framework", "plugin", "service", "xpc"].contains(ext) {
                    out.append(url)
                    // nested bundles are signed as a whole; do not descend further
                    walker.skipDescendants()
                }
                continue
            }
            if values?.isRegularFile == true && (ext == "dylib" || ext == "so") {
                out.append(url)
                continue
            }
            if values?.isRegularFile == true && values?.isExecutable == true && !url.path.contains("/Resources/") {
                out.append(url)
            }
        }
        // The bundle root itself (signed last, --deep).
        out.insert(app, at: 0)
        return out
    }

    /// `codesign -d --entitlements - --xml` → plist dict, or nil when the
    /// object is unsigned / carries no entitlements.
    static func inspectEntitlements(_ url: URL) -> [String: Any]? {
        let result = Shell.run("/usr/bin/codesign",
                               ["-d", "--entitlements", "-", "--xml", url.path])
        guard result.status == 0, !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        guard let data = result.stdout.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data, options: [], format: nil) as? [String: Any]
        else { return nil }
        return plist
    }

    // MARK: - Resign pipeline

    /// Full pipeline. `patchedBinaries` are relative paths inside the bundle
    /// (e.g. "Contents/Resources/wechat.dylib") that were byte-modified.
    static func resign(app: URL, patchedBinaries: [String]) throws {
        let snapshot = try capture(app: app)
        print(String(format: "[resign] %d code objects, %d with entitlements",
                     snapshot.entries.count, snapshot.entries.filter { $0.plist != nil }.count))

        // 1. Patched nested binaries first, with their snapshotted profile.
        for relative in patchedBinaries where !relative.isEmpty {
            let binary = URL(fileURLWithPath: app.path).appendingPathComponent(relative)
            guard binary.standardizedFileURL.path != app.standardizedFileURL.path else { continue }
            try sign(binary: binary, entitlements: snapshot.resignPlist(for: binary))
        }

        // 2. Root shallow pass with the MAIN EXECUTABLE's profile (original +
        //    injected keys) — signing the bundle == signing its main binary.
        //    No --deep: it retired 2026-09-21 (270100 rehearsal finding).
        //    --deep re-signs UNTOUCHED nested code (XPlayer.app …) ad-hoc, and
        //    codesign then seals XPlayer's non-Mach-O
        //    Frameworks/vk_swiftshader_icd.json as a cdhash-only nested entry
        //    that fails `--verify --deep --strict` with "code object is not
        //    signed at all" (official 270100 ships a designated-requirement
        //    seal that verifies; our --deep rewrite doesn't). Byte-modified
        //    binaries are already explicitly signed in step 1, so the root
        //    never needs to recurse. (The old nil-entitlements root pass
        //    STRIPPED the main executable's entitlements on purpose and let
        //    step 3's drift loop put them back — under --deep that also
        //    stamped the profile onto nested code; shallow + explicit profile
        //    does it in one pass.)
        try sign(binary: app, entitlements: snapshot.resignPlist(for: app))

        // 3. Drift detection & explicit re-sign of survivors, deepest-first.
        //    End-state is per-object: re-signed objects (patched binaries +
        //    root) must carry original+injected; UNTOUCHED objects must still
        //    match their ORIGINAL profile — expecting injected keys there
        //    would flag every object the shallow pass correctly left alone.
        var resigned = Set(
            patchedBinaries.filter { !$0.isEmpty }
                .map { URL(fileURLWithPath: app.path).appendingPathComponent($0).standardizedFileURL.path }
            + [app.standardizedFileURL.path])
        // The bundle root and its main executable are ONE signing object —
        // `codesign <app>` stamps the main binary itself. When the root is
        // re-signed the main executable changes too, so it must be checked
        // against the re-signed end state, not its original profile.
        if let main = mainExecutable(app: app) {
            resigned.insert(main.standardizedFileURL.path)
        }
        var drifted = mismatches(snapshot, app: app, resigned: resigned)
        if !drifted.isEmpty {
            print("[resign] \(drifted.count) profile(s) drifted after signing; restoring explicitly")
            for url in drifted.sorted(by: depthFirst) {
                try sign(binary: url, entitlements: snapshot.resignPlist(for: url))
            }
            drifted = mismatches(snapshot, app: app, resigned: resigned)
            guard drifted.isEmpty else {
                throw ResignError.entitlementsDrift(drifted.map(\.lastPathComponent))
            }
        }

        // 4. Hard verification.
        let verify = Shell.run("/usr/bin/codesign",
                               ["--verify", "--deep", "--strict", "--verbose=2", app.path])
        guard verify.status == 0 else {
            throw ResignError.verifyFailed(verify.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        print("[resign] codesign --verify --deep --strict: OK")

        // 5. Provenance xattrs (macOS 15) — best effort, read-only files make
        //    this fail on otherwise-valid bundles. Scoped to
        //    com.apple.provenance ONLY: a blanket `xattr -cr` also wipes the
        //    com.apple.cs.* xattrs where 270100's
        //    XPlayer/.../Frameworks/vk_swiftshader_icd.json carries its
        //    DETACHED code signature (the file is a signed code object
        //    despite being plain JSON). Wiping those turns the bundle
        //    unverifiable ("code object is not signed at all") only AFTER
        //    the step-4 gate has already passed — the breakage ships
        //    silently. find's per-file `xattr -d` errors on files lacking
        //    the attribute; that noise is expected and harmless.
        _ = Shell.run("/usr/bin/find",
                      [app.path, "-exec", "/usr/bin/xattr",
                       "-d", "com.apple.provenance", "{}", "+"])
    }

    /// Main executable URL from Info.plist's CFBundleExecutable, or nil when
    /// unreadable (then nothing extra joins the re-signed set).
    static func mainExecutable(app: URL) -> URL? {
        guard let data = try? Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let exe = plist["CFBundleExecutable"] as? String, !exe.isEmpty
        else { return nil }
        return app.appendingPathComponent("Contents/MacOS/\(exe)")
    }

    private static func depthFirst(_ a: URL, _ b: URL) -> Bool {
        let da = a.pathComponents.count, db = b.pathComponents.count
        return da == db ? a.path > b.path : da > db
    }

    /// Snapshot entries whose current profile no longer matches the INTENDED
    /// end state. Per-object: entries in `resigned` (patched binaries + root)
    /// must carry original + injected runtime keys — comparing those against
    /// the raw original would flag our own injections as drift forever.
    /// Untouched entries must still match their ORIGINAL profile: under the
    /// shallow root pass they keep their vendor signature, which never
    /// carries our injected keys.
    static func mismatches(_ snapshot: Snapshot, app: URL, resigned: Set<String>) -> [URL] {
        snapshot.entries.compactMap { entry in
            let intended = resigned.contains(entry.url.standardizedFileURL.path)
                ? entry.resignPlist : entry.plist
            if plistsEqual(inspectEntitlements(entry.url), intended) { return nil }
            return entry.url
        }
    }

    private static func sign(binary: URL, entitlements: [String: Any]?, deep: Bool = false) throws {
        var args = ["--force", "--sign", "-",
                    "--preserve-metadata=identifier,flags,runtime"]
        // macOS 15+ codesign 默认不再把 entitlements 嵌入库（dylib/framework）
        // 签名——不强制回填会永久漂移成 entitlementsDrift（社区双实现
        // zengtianli/fzlzjerry 同款 flag；旧版 codesign 无此选项，按系统版本条件加）。
        if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 {
            args += ["--force-library-entitlements"]
        }
        var tempPlist: URL?
        if let entitlements, !entitlements.isEmpty {
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("wxkeep-ent-\(UUID().uuidString).plist")
            let data = try PropertyListSerialization.data(
                fromPropertyList: entitlements, format: .xml, options: 0)
            try data.write(to: url)
            args += ["--entitlements", url.path]
            tempPlist = url
        }
        if deep { args += ["--deep"] }
        args.append(binary.path)
        defer { if let tempPlist { try? FileManager.default.removeItem(at: tempPlist) } }
        let result = Shell.run("/usr/bin/codesign", args)
        guard result.status == 0 else {
            throw ResignError.signFailed(
                path: binary.path,
                stderr: (result.stderr + result.stdout).trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// Semantic comparison — codesign reorders keys, so byte/serialization
    /// comparison lies. NSDictionary.isEqual is order-independent for plist
    /// value types (String/Bool/Data/Array/Dictionary).
    static func plistsEqual(_ a: [String: Any]?, _ b: [String: Any]?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (l?, r?):
            return (l as NSDictionary).isEqual(r as NSDictionary)
        default: return false
        }
    }
}
