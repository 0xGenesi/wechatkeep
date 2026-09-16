import Foundation

/// Clone-based multi-instance: copy WeChat.app with an independent bundle ID
/// so macOS treats each copy as a separate app with its own data container.
///
/// Design (borrowed from fzlzjerry/wechat-antirecall, adapted):
/// - NO binary patching — works on ANY WeChat build, survives updates
/// - Each clone gets a unique bundle ID (com.tencent.xinWeChat.wxkeep.N)
///   → separate sandbox container → independent login/data
/// - URL schemes are stripped from clones so they don't fight the original
///   over wechat:// links
/// - Clones are marked via a plist key for self-identification (list/remove)
/// - A patched clone stays patched; an unpatched clone stays stock — clones
///   inherit whatever state the source .app had at copy time
enum Clone {
    enum CloneError: Error, CustomStringConvertible {
        case sourceNotFound(String)
        case destinationExists(String)
        case copyFailed(String)
        case plistWriteFailed(String)
        case resignFailed(String)
        case launchFailed(String)
        case notAClone(String)

        var description: String {
            switch self {
            case .sourceNotFound(let p): return "源未找到: \(p)"
            case .destinationExists(let p): return "目标已存在: \(p)（用 --replace 覆盖）"
            case .copyFailed(let d): return "复制失败: \(d)"
            case .plistWriteFailed(let d): return "Info.plist 写入失败: \(d)"
            case .resignFailed(let d): return "重签名失败: \(d)"
            case .launchFailed(let d): return "启动失败: \(d)"
            case .notAClone(let p): return "\(p) 不是 wxkeep 克隆（缺少标记）"
            }
        }
    }

    static let markerKey = "io.github.wxkeep.clone"
    static let originalBundleID = "com.tencent.xinWeChat"

    /// The macOS Applications dir is the conventional home; we accept any dir.
    static func defaultDirectory() -> URL {
        URL(fileURLWithPath: "/Applications")
    }

    /// Lists wxkeep clones in a directory (marker key present in Info.plist).
    static func list(in directory: URL? = nil) -> [(url: URL, index: Int, bundleID: String)] {
        let dir = directory ?? defaultDirectory()
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: [.isDirectoryKey]) else { return [] }
        return contents.compactMap { url in
            guard url.pathExtension == "app" else { return nil }
            let plist = url.appendingPathComponent("Contents/Info.plist")
            guard let dict = NSDictionary(contentsOf: plist) as? [String: Any],
                  let marker = dict[markerKey] as? Int else { return nil }
            let bid = dict["CFBundleIdentifier"] as? String ?? "?"
            return (url, marker, bid)
        }.sorted { $0.index < $1.index }
    }

    /// Creates clone #N (next free index if nil).
    /// Returns the clone's URL. The caller should NOT have WeChat running.
    @discardableResult
    static func create(
        source: URL, index: Int? = nil, directory: URL? = nil, replace: Bool = false
    ) throws -> URL {
        let fm = FileManager.default
        guard fm.fileExists(atPath: source.appendingPathComponent("Contents/Info.plist").path) else {
            throw CloneError.sourceNotFound(source.path)
        }
        let dir = directory ?? source.deletingLastPathComponent()
        let idx = index ?? nextFreeIndex(in: dir)
        let name = "WeChat wxkeep \(idx).app"
        let dest = dir.appendingPathComponent(name)
        if fm.fileExists(atPath: dest.path) {
            guard replace else { throw CloneError.destinationExists(dest.path) }
            // 与 remove 同规：只覆盖 wxkeep 克隆，拒绝删无标记的用户 app
            let destPlist = dest.appendingPathComponent("Contents/Info.plist")
            guard let d = NSDictionary(contentsOf: destPlist) as? [String: Any],
                  d[markerKey] is Int else {
                throw CloneError.notAClone(dest.lastPathComponent)
            }
            try fm.removeItem(at: dest)
        }

        // 1. Pre-write: destination directory must be writable (admin /Applications or custom dir)
        guard fm.isWritableFile(atPath: dir.path) else {
            throw CloneError.copyFailed("\(dir.path) 不可写（标准用户请用 --app 自定义目录，或加 sudo）")
        }

        // 2. Copy; on any later failure remove the partial clone (fail-loudly convention)
        do { try fm.copyItem(at: source, to: dest) }
        catch { throw CloneError.copyFailed(error.localizedDescription) }
        func cleanup() { try? fm.removeItem(at: dest) }

        // 2. Rewrite Info.plist: unique bundle ID + marker + strip URL schemes
        let plist = dest.appendingPathComponent("Contents/Info.plist")
        guard let dict = NSMutableDictionary(contentsOf: plist) else {
            throw CloneError.plistWriteFailed("unreadable")
        }
        let newBundleID = "\(originalBundleID).wxkeep.\(idx)"
        dict["CFBundleIdentifier"] = newBundleID
        dict["CFBundleDisplayName"] = "WeChat \(idx)"
        dict["CFBundleName"] = "WeChat \(idx)"
        dict[markerKey] = idx
        //剥离 URL scheme，防与原微信抢占 wechat:// 链接
        dict.removeObject(forKey: "CFBundleURLTypes")
        guard dict.write(to: plist, atomically: true) else {
            cleanup()
            throw CloneError.plistWriteFailed("write failed")
        }

        // 3. Re-sign the clone (bundle ID changed → must re-sign to launch).
        // A REAL Mach-O main executable is mandatory; synthetic test stubs
        // (non-Mach-O bytes) skip signing. Missing/unreadable executable is fatal.
        let main = dest.appendingPathComponent("Contents/MacOS/WeChat")
        guard let handle = try? FileHandle(forReadingFrom: main),
              let head = try? handle.read(upToCount: 4), head.count == 4 else {
            cleanup()
            throw CloneError.resignFailed("主程序不存在或不可读（Contents/MacOS/WeChat）")
        }
        try? handle.close()
        let magics: Set<Data> = [
            Data([0xCF, 0xFA, 0xED, 0xFE]),  // MH_MAGIC_64 LE
            Data([0xFE, 0xED, 0xFA, 0xCF]),  // MH_MAGIC_64 BE
            Data([0xCA, 0xFE, 0xBA, 0xBE]),  // FAT BE
            Data([0xBE, 0xBA, 0xFE, 0xCA]),  // FAT LE
            Data([0xCE, 0xFA, 0xED, 0xFE]),  // MH_CIGAM_64
        ]
        if magics.contains(head) {
            let sign = Shell.run("/usr/bin/codesign",
                ["-f", "-s", "-", "--preserve-metadata=entitlements,requirements,flags",
                 dest.path])
            guard sign.status == 0 else {
                cleanup()
                throw CloneError.resignFailed((sign.stderr + sign.stdout).prefix(200).description)
            }
        }
        return dest
    }

    /// Removes a clone (refuses to touch anything without the marker).
    static func remove(_ cloneURL: URL) throws {
        let plist = cloneURL.appendingPathComponent("Contents/Info.plist")
        guard let dict = NSDictionary(contentsOf: plist) as? [String: Any],
              dict[markerKey] is Int else {
            throw CloneError.notAClone(cloneURL.lastPathComponent)
        }
        try FileManager.default.removeItem(at: cloneURL)
    }

    static func nextFreeIndex(in directory: URL) -> Int {
        let used = Set(list(in: directory).map(\.index))
        var i = 1
        while used.contains(i) { i += 1 }
        return i
    }

    /// Launches a clone via `open`.
    static func launch(_ cloneURL: URL) throws {
        let r = Shell.run("/usr/bin/open", [cloneURL.path])
        guard r.status == 0 else {
            throw CloneError.launchFailed(r.stderr)
        }
    }
}
