import Foundation
import Testing
@testable import wxkeep

struct CloneAndPrivacyTests {
    // MARK: Clone（不碰真实 /Applications；在 tmp 里搭假 .app）

    private func makeFakeApp(named: String, in dir: URL, bundleID: String, marker: Int? = nil) throws -> URL {
        let app = dir.appendingPathComponent(named)
        try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents/MacOS"), withIntermediateDirectories: true)
        try Data([0x55]).write(to: app.appendingPathComponent("Contents/MacOS/WeChat"))
        let dict = NSMutableDictionary()
        dict["CFBundleIdentifier"] = bundleID
        dict["CFBundleVersion"] = "999999"
        dict["CFBundleURLTypes"] = [["CFBundleURLSchemes": ["wechat"]]]
        if let m = marker { dict[Clone.markerKey] = m }
        guard (dict as NSDictionary).write(to: app.appendingPathComponent("Contents/Info.plist"), atomically: true) else {
            throw Clone.CloneError.plistWriteFailed("test fixture")
        }
        return app
    }

    @Test func cloneCreateListRemoveRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-clone-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let source = try makeFakeApp(named: "WeChat.app", in: dir, bundleID: Clone.originalBundleID)
        let clone = try Clone.create(source: source, directory: dir)
        #expect(FileManager.default.fileExists(atPath: clone.path))

        // list 发现它
        let found = Clone.list(in: dir)
        #expect(found.count == 1)
        #expect(found[0].index == 1)
        #expect(found[0].bundleID == "com.tencent.xinWeChat.wxkeep.1")

        // plist 被改：bundle ID 换、URL scheme 剥、marker 在
        let dict = NSDictionary(contentsOf: clone.appendingPathComponent("Contents/Info.plist")) as? [String: Any]
        #expect(dict?["CFBundleIdentifier"] as? String == "com.tencent.xinWeChat.wxkeep.1")
        #expect(dict?[Clone.markerKey] as? Int == 1)
        #expect(dict?["CFBundleURLTypes"] == nil)

        // remove 删除；对非克隆（无 marker）拒绝
        try Clone.remove(clone)
        #expect(Clone.list(in: dir).isEmpty)
        expectThrows(try Clone.remove(source))
    }

    @Test func nextFreeIndexSkipsUsed() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-clone-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = try makeFakeApp(named: "WeChat wxkeep 1.app", in: dir, bundleID: "x.1", marker: 1)
        _ = try makeFakeApp(named: "WeChat wxkeep 3.app", in: dir, bundleID: "x.3", marker: 3)
        #expect(Clone.nextFreeIndex(in: dir) == 2)
    }

    // MARK: PrivacyGuard（读结构；写入依赖 cfprefd 域所有权，真机验证）

    @Test func privacyReadCoversAllKeys() {
        let statuses = PrivacyGuard.read()
        #expect(statuses.count == PrivacyGuard.keys.count)
        #expect(statuses.contains { $0.key == "SUSendProfileInfo" })
    }

    @Test func privacyRenderMarksState() {
        let statuses = [
            PrivacyGuard.Status(key: "K1", value: "0", guarded: true, meaning: "a"),
            PrivacyGuard.Status(key: "K2", value: "1", guarded: false, meaning: "b"),
        ]
        let text = PrivacyGuard.render(statuses)
        #expect(text.contains("[✓] K1 = 0"))
        #expect(text.contains("[✗] K2 = 1"))
    }
}
