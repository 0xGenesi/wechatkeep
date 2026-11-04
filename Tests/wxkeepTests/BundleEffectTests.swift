import Foundation
import Testing
@testable import wxkeep

/// L13 bundle 级写入局部性（V6-DEPTH D17/R16，133 轮）。
///
/// patch 的作用域主张从「单文件位点级」升格为「bundle 全树」——关闭
/// V5-DEPTH §5 的登记项（「全 bundle 级（多文件+Info.plist 面）未做」）。
/// patch 真实修改的不止目标二进制：备份文件（设计内）；重签场景还有
/// 签名面（本测试 --no-resign 语义不触——Engine 层不重签，重签归 CLI +
/// L6/L9 + codesign 判官，两域解耦见 V6-DEPTH §6）。
///
/// 合成镜像（CI 常跑）断言：
///   ① patch 后全树差分文件集合 ⊆ {目标 dylib ∪ .wxkeep-bak-* 备份}；
///   ② 诱饵逐字节不动：Info.plist / 主可执行同族 Mach-O / framework 内
///      Mach-O / 普通文件——**字节级**而非哈希级（L2 教训：哈希藏不住的
///      是通配尾部，这里反过来：哈希相等的证据力不如直读字节）；
///   ③ 目标 dylib 位点级 diff ⊆ 声明位点区间（位点外零写入直证）；
///   ④ restore 后除备份外全树恒等（备份 keep-3 轮换是设计内残留），
///      目标 dylib 整文件 == pristine；
///   ⑤ 负控：位点外人为注入一字节 → 局部性检查必红（检测器能报错）。
struct BundleEffectTests {
    private static let catalogJSON = """
    [{"version":"999995","targets":[
      {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
        {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"}
      ]},
      {"identifier":"update","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"1C0","expected":"9101E65E","asm":"C0035FD6"},
        {"arch":"x86_64","addr":"1C0","expected":"85C00F85CA000000","asm":"31C09090"}
      ]}
    ]}]
    """

    /// 目标 dylib 的位点区间（slice 内偏移 + len）——fat 全文件偏移在
    /// 断言时加 sliceOffset。
    private static let siteSpans: [(arch: Config.Arch, va: UInt64, len: Int)] = [
        (.arm64, 0x100, 8), (.arm64, 0x1C0, 4),
        (.x86_64, 0x100, 9), (.x86_64, 0x1C0, 8),
    ]

    private struct Rig {
        let app: URL
        let dylib: URL
        let armOffset: Int
        let x64Offset: Int
        let tree: [String: Data]   // bundle 相对路径 → 内容（pristine 快照）
    }

    private static func makeRig(work: URL, name: String) throws -> Rig {
        let (image, armOffset, x64Offset) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
                (0x1C0, [0x91, 0x01, 0xE6, 0x5E]),
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
                (0x1C0, [0x85, 0xC0, 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00]),
            ]))

        let app = work.appendingPathComponent(name, isDirectory: true)
        // 四类诱饵：plist / 主可执行族 Mach-O / framework 内 Mach-O / 普通文件
        let macos = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        let frameworks = app.appendingPathComponent(
            "Contents/Frameworks/Decoy.framework", isDirectory: true)
        for dir in [macos, resources, frameworks] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        let dylib = resources.appendingPathComponent("wechat.dylib")
        try image.write(to: dylib)

        let decoyMachO = MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400,
                                           code: [(0x200, [0xDE, 0xAD, 0xBE, 0xEF])])
        let decoyFrameworkMachO = MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400,
                                                    code: [(0x200, [0xCA, 0xFE, 0xBA, 0xBE])])
        let mainExecutable = macos.appendingPathComponent("WeChat")
        try decoyMachO.write(to: mainExecutable)
        try decoyFrameworkMachO.write(to: frameworks.appendingPathComponent("Decoy"))
        let infoPlist = app.appendingPathComponent("Contents/Info.plist")
        try Data("<plist><version>99.99</version></plist>".utf8).write(to: infoPlist)
        let decoyBin = resources.appendingPathComponent("decoy.bin")
        try Data(repeating: 0x5A, count: 64).write(to: decoyBin)

        // 全树快照（递归）
        var tree: [String: Data] = try treeSnapshot(app)
        return Rig(app: app, dylib: dylib, armOffset: armOffset,
                   x64Offset: x64Offset, tree: tree)
    }

    /// 全树快照：键 = bundle 相对路径。enumerator 的 URL 会解析符号链接
    ///（/tmp → /private/tmp），而 app.path 保持原形——双边先 resolving-
    /// SymlinksInPath 归一再剥前缀，否则键漂成绝对路径（实测翻车形态）。
    private static func treeSnapshot(_ app: URL) throws -> [String: Data] {
        var tree: [String: Data] = [:]
        let root = app.resolvingSymlinksInPath().path
        let enumerator = FileManager.default.enumerator(
            at: app, includingPropertiesForKeys: [.isRegularFileKey])!
        for case let url as URL in enumerator {
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true
            else { continue }
            let abs = url.resolvingSymlinksInPath().path
            guard abs.hasPrefix(root + "/") else { continue }
            tree[String(abs.dropFirst(root.count + 1))] = try Data(contentsOf: url)
        }
        return tree
    }

    /// 差异字节段收集：连续不同字节合并为区间（位点级直证的面）。
    static func differingRanges(_ a: Data, _ b: Data) -> [Range<Int>] {
        let count = min(a.count, b.count)
        var ranges: [Range<Int>] = []
        var start: Int? = nil
        for i in 0..<count {
            if a[i] != b[i] {
                if start == nil { start = i }
            } else if let s = start {
                ranges.append(s..<i)
                start = nil
            }
        }
        if let s = start { ranges.append(s..<count) }
        if a.count != b.count { ranges.append(count..<max(a.count, b.count)) }
        return ranges
    }

    /// 位点级局部性检查：dylib 差分段 ⊆ 声明位点区间（fat 全文件偏移）。
    /// internal static：负控用例直接复用（检测器灵敏度的被测面）。
    static func localityHolds(pristine: Data, patched: Data,
                              armOffset: Int, x64Offset: Int) -> Bool {
        let allowed: [(Int, Int)] = siteSpans.map { span in
            let base = span.arch == .arm64 ? armOffset : x64Offset
            return (base + Int(span.va), base + Int(span.va) + span.len)
        }
        for range in differingRanges(pristine, patched) {
            let contained = allowed.contains { lo, hi in
                range.lowerBound >= lo && range.upperBound <= hi
            }
            if !contained { return false }
        }
        return true
    }

    @Test func patchTouchesOnlyTargetAndBackupsAcrossBundleTree() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-bundle-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        let rig = try Self.makeRig(work: work, name: "Bundle.app")
        let config = try Config(data: Data(Self.catalogJSON.utf8), origin: "bundle-effect")

        _ = try Engine.patch(app: rig.app, build: "999995", config: config, variant: "silent",
                             dryRun: false, allowUnverified: false, only: nil)

        // ① 全树差分文件集合 ⊆ {目标 dylib ∪ 备份}
        let after = try Self.treeSnapshot(rig.app)
        let targetRel = "Contents/Resources/wechat.dylib"
        var changed: Set<String> = []
        var added: Set<String> = []
        for (rel, data) in after {
            if let before = rig.tree[rel] {
                if before != data { changed.insert(rel) }
            } else {
                added.insert(rel)
            }
        }
        #expect(changed == [targetRel],
                "全树差分越界：changed = \(changed.sorted().joined(separator: ", "))")
        let backupRel = added.filter { $0.contains(".wxkeep-bak-") }
        #expect(added == backupRel,
                "新增文件越界（应为备份轮换）：added = \(added.sorted().joined(separator: ", "))")
        #expect(backupRel.count == 1, "silent patch 应恰好产生 1 份备份")

        // ② 诱饵逐字节不动
        for decoy in ["Contents/Info.plist", "Contents/MacOS/WeChat",
                      "Contents/Frameworks/Decoy.framework/Decoy", "Contents/Resources/decoy.bin"] {
            #expect(after[decoy] == rig.tree[decoy], "诱饵被触碰：\(decoy)")
        }

        // ③ 目标 dylib 位点级 diff ⊆ 声明位点区间
        let patchedDylib = try Data(contentsOf: rig.dylib)
        let pristineDylib = rig.tree[targetRel]!
        #expect(Self.localityHolds(pristine: pristineDylib, patched: patchedDylib,
                                   armOffset: rig.armOffset, x64Offset: rig.x64Offset),
                "位点级局部性破坏：diff 越出声明位点区间")

        // ④ restore 后除备份外全树恒等
        _ = try Engine.restore(app: rig.app, build: "999995", config: config, dryRun: false)
        let restored = try Self.treeSnapshot(rig.app)
        for (rel, data) in restored where !rel.contains(".wxkeep-bak-") {
            #expect(data == rig.tree[rel], "restore 后文件未还原：\(rel)")
        }
        #expect(restored[targetRel] == pristineDylib,
                "restore 后目标 dylib 整文件 ≠ pristine")
    }

    /// ⑤ 负控：位点外人为注入一字节 → 局部性检查必红（检测器能报错）。
    @Test func outOfSiteTamperingIsDetected() throws {
        // 平面 0x1000 缓冲模拟 fat 坐标（arm 切片 @0x400 起）——纯函数面，
        // 不经 MachOFixture（检测器逻辑自身的灵敏度，与 fixture 布局解耦）。
        // 缓冲必须 ≥ 索引上限（0x700）——Data 下标越界即 trap。
        let pristine = Data(repeating: 0xCC, count: 0x1000)
        var tampered = pristine
        // 0x700 = arm 切片内位点外填充区（位点 ∈ [0x500,0x5C8)，切片
        // [0x400,0x800)）——单字节注入即应触发。
        tampered[0x300 + 0x400] = 0xFF
        #expect(!Self.localityHolds(pristine: pristine, patched: tampered,
                                    armOffset: 0x400, x64Offset: 0x800),
                "位点外注入未被检出——局部性检测器失灵")
        // 对照：位点内变化不触发（sensitivity 方向二）
        var inSite = pristine
        inSite[0x400 + 0x100] = 0x00   // arm 切片 revoke 位点首字节
        #expect(Self.localityHolds(pristine: pristine, patched: inSite,
                                   armOffset: 0x400, x64Offset: 0x800),
                "位点内变化误报——负控反向灵敏度（不得把合法写入判为越界）")
    }
}
