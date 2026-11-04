import Foundation
import Testing
@testable import wxkeep

/// L10 崩溃点穷举矩阵（V6-DEPTH D14/R13，133 轮）。
///
/// M08 写故障缝（debugWriteFailureAt，126 轮立）此前只有 fail-at-0 一个
/// 杀例——「任意写位点失败都可收敛」从未被证明。本套件把穷举补满：
/// 5 个命令场景 × 各自**全部**写位点 k，每格 fail-at(k) 注入后断言五不变量：
///   ① 抛错类型正确（PartialWriteFailure——journal 必须保留给 doctor 判读）；
///   ② 失败瞬间盘面全部位点 ∈ 合法集（inspect 零 .unknown）；
///   ③ restore 收敛后位点级字节 == pristine（签名尾是恢复重签的设计内
///     噪声——codesign 会 append 签名 blob，整文件 sha 不可作判据；位点级
///     直证把「崩溃收敛」与「局部性」解耦，后者归 L13 BundleEffectTests）；
///   ④ 崩溃后恢复 == 干净直打（restore 后再执行同命令，位点字节与对照
///     副本恒等——跨崩溃路径确定性）；
///   ⑤ 恢复重签防线被真实触达（debugAttemptHook 计数 ≥1——必崩态防线
///     不会因注入而缺席）。
/// 对照副本同时**实测**该场景的写位点数并与登记对账——位点数不是拍脑袋，
/// 格子自校验（若引擎写入数与登记不符，格子立即红）。
///
/// .serialized：debugWriteFailureAt/debugAttemptHook 是进程全局缝，套件内
/// 串行消除歧义；对外仍靠 URL 限定（闭包对非本夹具路径恒返 nil）与其他
/// 并行套件共存——EngineTests 同款纪律。仅 DEBUG（缝本身 DEBUG-only，
/// swift test 即 debug 配置）。
/// **跨套件互踩窗口（133 轮双评审 P1 登记）**：URL 限定只防误注入，防不了
/// 全局槽的 set/复位与 EngineTests.undoMidWriteFailure 等并行用例的窗口
/// 重叠——重叠时双方缝被互相清空，产生 flaky 红（红向安全，无假绿）。
/// 复现时重跑该用例即可；结构性解法（每套件独立缝槽）需产品缝 API 演进，
/// 不在测试侧硬造。
#if DEBUG
@Suite(.serialized)
struct CrashMatrixTests {
    /// 与 SyntheticL2L6Tests 同款三 target 目录：silent 位（retify）/
    /// keeptip 位（归一化 + cbz + store-zero）/ update 位。位点 VA==fileoff
    /// （MachOFixture 布局合同）。
    private static let catalogJSON = """
    [{"version":"999997","targets":[
      {"identifier":"revoke","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"100","expected":"F44FBEA9FD7B01A9","asm":"00008052C0035FD6"},
        {"arch":"x86_64","addr":"100","expected":"554889E553504889FB","asm":"31C0C3909090909090"}
      ]},
      {"identifier":"revoke-keeptip","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"100","expected":["00008052C0035FD6","F44FBEA9FD7B01A9"],"asm":"F44FBEA9FD7B01A9"},
        {"arch":"arm64","addr":"140","expected":["40100034","82000014"],"asm":"40100034"},
        {"arch":"arm64","addr":"180","expected":["60E600F9"],"asm":"7FE600F9"},
        {"arch":"x86_64","addr":"140","expected":["4889C2"],"asm":"31D290"}
      ]},
      {"identifier":"update","binary":"Contents/Resources/wechat.dylib","entries":[
        {"arch":"arm64","addr":"1C0","expected":"9101E65E","asm":"C0035FD6"},
        {"arch":"x86_64","addr":"1C0","expected":"85C00F85CA000000","asm":"31C09090"}
      ]}
    ]}]
    """

    /// 位点区间（arch, va, len）——len = max(asm, expected 变体) 字节，
    /// 与 Patcher 的 siteLen 语义同源。位点级直证与对照快照共用。
    private static let siteSpans: [(arch: Config.Arch, va: UInt64, len: Int)] = [
        (.arm64, 0x100, 8), (.arm64, 0x140, 4), (.arm64, 0x180, 4), (.arm64, 0x1C0, 4),
        (.x86_64, 0x100, 9), (.x86_64, 0x140, 3), (.x86_64, 0x1C0, 8),
    ]

    /// 崩溃矩阵格子登记：(前置态, 目标命令, 写位点数)。
    /// 写位点数 = **对照副本实测**（写序的顺序效应——undo 臂先还原共享 VA、
    /// 归一化条目随后判 alreadyPatched skip；silent 未碰位点 restore 时
    /// pristine 已就位 skip——人工推演在此翻过车：首轮登记 5/7 被实测
    /// 4/4 推翻，登记表只能由实测产生）。
    /// registeredWriteCountsMatchCleanPaths 与每格对照副本双重复核对账。
    private struct Cell: CustomStringConvertible {
        let pre: String?      // nil = pristine；"silent"/"keeptip"
        let cmd: String       // "silent"/"keeptip"/"restore"
        let writes: Int
        var description: String { "\(pre ?? "pristine") → \(cmd)" }
    }

    private static func cell(_ pre: String?, _ cmd: String, _ writes: Int, _ k: Int)
        -> (pre: String?, cmd: String, writes: Int, k: Int) {
        (pre, cmd, writes, k)
    }

    /// 全矩阵：5 场景 × 各自全部写位点 k（k ∈ 0..<writes）= 20 格。
    private static let matrix: [(pre: String?, cmd: String, writes: Int, k: Int)] = [
        cell(nil, "silent", 4, 0), cell(nil, "silent", 4, 1),
        cell(nil, "silent", 4, 2), cell(nil, "silent", 4, 3),
        cell(nil, "keeptip", 4, 0), cell(nil, "keeptip", 4, 1),
        cell(nil, "keeptip", 4, 2), cell(nil, "keeptip", 4, 3),
        cell("silent", "keeptip", 4, 0), cell("silent", "keeptip", 4, 1),
        cell("silent", "keeptip", 4, 2), cell("silent", "keeptip", 4, 3),
        cell("silent", "restore", 4, 0), cell("silent", "restore", 4, 1),
        cell("silent", "restore", 4, 2), cell("silent", "restore", 4, 3),
        cell("keeptip", "restore", 4, 0), cell("keeptip", "restore", 4, 1),
        cell("keeptip", "restore", 4, 2), cell("keeptip", "restore", 4, 3),
    ]

    // MARK: - fixtures

    private struct Rig {
        let app: URL
        let dylib: URL
        let armOffset: Int
        let x64Offset: Int
    }

    private func makeRig(work: URL, name: String) throws -> Rig {
        let (image, armOffset, x64Offset) = MachOFixture.fat(
            arm64: MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: [
                (0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
                (0x140, [0x40, 0x10, 0x00, 0x34]),
                (0x180, [0x60, 0xE6, 0x00, 0xF9]),
                (0x1C0, [0x91, 0x01, 0xE6, 0x5E]),
            ]),
            x64: MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: [
                (0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
                (0x140, [0x48, 0x89, 0xC2]),
                (0x1C0, [0x85, 0xC0, 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00]),
            ]))
        let app = work.appendingPathComponent(name, isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        let dylib = resources.appendingPathComponent("wechat.dylib")
        try image.write(to: dylib)
        return Rig(app: app, dylib: dylib, armOffset: armOffset, x64Offset: x64Offset)
    }

    private func makeConfig() throws -> Config {
        try Config(data: Data(Self.catalogJSON.utf8), origin: "crash-matrix")
    }

    private func run(_ cmd: String, app: URL, config: Config) throws -> Engine.RunSummary {
        if cmd == "restore" {
            return try Engine.restore(app: app, build: "999997", config: config, dryRun: false)
        }
        return try Engine.patch(app: app, build: "999997", config: config, variant: cmd,
                                dryRun: false, allowUnverified: false, only: nil)
    }

    /// 读某切片某 VA 的 len 字节（fixture VA==slice 内偏移合同）。
    private func sliceBytes(_ rig: Rig, arch: Config.Arch, va: UInt64, len: Int) throws -> Data {
        let data = try Data(contentsOf: rig.dylib)
        let base = arch == .arm64 ? rig.armOffset : rig.x64Offset
        return data.subdata(in: (base + Int(va))..<(base + Int(va) + len))
    }

    /// 全部位点字节快照：[(arch, va, len, hex)]——对照终态与恢复直证共用。
    private func siteSnapshot(_ rig: Rig) throws -> [(Config.Arch, UInt64, Int, String)] {
        try Self.siteSpans.map { span in
            (span.arch, span.va, span.len,
             try sliceBytes(rig, arch: span.arch, va: span.va, len: span.len).hexUppercase)
        }
    }

    /// pristine 模板的位点字节（按 MachOFixture 生成序重建，不持有第二份 Rig）。
    private func pristineBytes(arch: Config.Arch, va: UInt64, len: Int) -> Data {
        let code: [(Int, [UInt8])] = arch == .arm64
            ? [(0x100, [0xF4, 0x4F, 0xBE, 0xA9, 0xFD, 0x7B, 0x01, 0xA9]),
               (0x140, [0x40, 0x10, 0x00, 0x34]),
               (0x180, [0x60, 0xE6, 0x00, 0xF9]),
               (0x1C0, [0x91, 0x01, 0xE6, 0x5E])]
            : [(0x100, [0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]),
               (0x140, [0x48, 0x89, 0xC2]),
               (0x1C0, [0x85, 0xC0, 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00])]
        var slice = Data(count: 0x400)
        for (offset, bytes) in code {
            slice.replaceSubrange(offset..<(offset + bytes.count), with: Data(bytes))
        }
        return slice.subdata(in: Int(va)..<(Int(va) + len))
    }

    private func assertLegalSites(_ label: String, app: URL, config: Config) throws {
        let entry = try #require(config.entry(build: "999997"))
        for target in entry.targets {
            let bin = app.appendingPathComponent(target.binary ?? "Contents/MacOS/WeChat")
            let inspections = try Patcher.inspect(binary: bin, entries: target.entries,
                                                  identifier: "crash-matrix")
            let unknown = inspections.filter { $0.state == .unknown }
            #expect(unknown.isEmpty,
                    "\(label): \(target.identifier) \(unknown.count) 个位点 ∉ 合法集")
        }
    }

    private func makeWork(_ tag: String) throws -> URL {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-crash-\(tag)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        return work
    }

    // MARK: - 单格协议

    private func runCell(_ cell: (pre: String?, cmd: String, writes: Int, k: Int)) throws {
        let config = try makeConfig()
        let work = try makeWork("\(cell.pre ?? "p")-\(cell.cmd)-\(cell.k)")
        defer { try? FileManager.default.removeItem(at: work) }

        // 注入副本：pristine →（前置态）→ fail-at(k) 注入的 cmd
        let rig = try makeRig(work: work, name: "Inject.app")
        if let pre = cell.pre {
            _ = try run(pre, app: rig.app, config: config)
        }

        // 对照副本：同路径无注入 —— 写位点数实测对账 + 终态位点字节参照
        let refWork = work.appendingPathComponent("ref", isDirectory: true)
        try FileManager.default.createDirectory(at: refWork, withIntermediateDirectories: true)
        let ref = try makeRig(work: refWork, name: "Ref.app")
        if let pre = cell.pre {
            _ = try run(pre, app: ref.app, config: config)
        }
        var writeCount = 0
        Patcher.debugWriteFailureAt = { url, _ in
            guard url.path == ref.dylib.path else { return nil }
            writeCount += 1
            return nil   // 对照只计数不注入
        }
        defer { Patcher.debugWriteFailureAt = nil }   // 早退路径兜底（P2-8）
        _ = try run(cell.cmd, app: ref.app, config: config)
        Patcher.debugWriteFailureAt = nil
        #expect(writeCount == cell.writes,
                "\(cell): 登记写位点数 \(cell.writes) ≠ 实测 \(writeCount)——格子登记过期")
        let refSites = try siteSnapshot(ref)

        // —— 注入执行：fail-at(k) ——
        let targetPath = rig.dylib.path
        var injectCount = 0
        var resignAttempts = 0
        Resigner.debugAttemptHook = { resignAttempts += 1 }
        struct InjectedWriteFailure: Error {}
        Patcher.debugWriteFailureAt = { url, _ in
            guard url.path == targetPath else { return nil }
            injectCount += 1
            return injectCount == cell.k + 1 ? InjectedWriteFailure() : nil
        }
        do {
            _ = try run(cell.cmd, app: rig.app, config: config)
            Issue.record("\(cell) k=\(cell.k): 注入未触发（写计数 \(injectCount) < k+1=\(cell.k + 1)）——格子登记过期或缝失效")
            return
        } catch let e as Engine.PartialWriteFailure {
            _ = e   // ① 预期：journal 必须保留的错误族
        } catch {
            Issue.record("\(cell) k=\(cell.k): 错误类型不对（应 PartialWriteFailure，得 \(error)）")
        }
        Patcher.debugWriteFailureAt = nil
        Resigner.debugAttemptHook = nil
        // （早退 return 路径的缝兜底：上面两个显式复位已覆盖主路径，
        //  return 分支泄漏的闭包只对死 UUID 路径生效且下次 set 覆盖——
        //  见文件头「跨套件互踩窗口」登记。）
        #expect(injectCount == cell.k + 1, "\(cell) k=\(cell.k): 注入点漂移（计数 \(injectCount)）")
        // ⑤ 恢复重签防线：patch 命令失败路径必须触达（Engine.patch 外层
        // catch 的「字节已改+陈旧签名 = 启动必崩态」防线）；restore 路径按
        // 设计**无**恢复重签（Engine.restoreTargets 失败只记账+包
        // PartialWriteFailure，journal 留给 doctor interrupted 判读）——
        // 行为差异如实断言，不把 restore 拉进 patch 的防线语义。
        if cell.cmd == "restore" {
            #expect(resignAttempts == 0,
                    "\(cell) k=\(cell.k): restore 失败路径不应触发恢复重签（现触达 \(resignAttempts) 次）")
        } else {
            #expect(resignAttempts >= 1,
                    "\(cell) k=\(cell.k): 恢复重签防线未被触达（⑤）")
        }

        // ② 失败瞬间盘面合法集
        try assertLegalSites("crash \(cell) k=\(cell.k)/failed", app: rig.app, config: config)

        // ③ restore 收敛 → 位点级字节 == pristine
        _ = try Engine.restore(app: rig.app, build: "999997", config: config, dryRun: false)
        try assertLegalSites("crash \(cell) k=\(cell.k)/restored", app: rig.app, config: config)
        for span in Self.siteSpans {
            let onDisk = try sliceBytes(rig, arch: span.arch, va: span.va, len: span.len)
            #expect(onDisk == pristineBytes(arch: span.arch, va: span.va, len: span.len),
                    "\(cell) k=\(cell.k): restore 后 \(span.arch)@\(String(span.va, radix: 16)) 字节 ≠ pristine")
        }

        // ④ 崩溃后恢复 == 干净直打（元组数组无 ==，逐元素对账）
        _ = try run(cell.cmd, app: rig.app, config: config)
        let crashRecovered = try siteSnapshot(rig)
        for (recovered, reference) in zip(crashRecovered, refSites) {
            // 动态消息非字面量——Comment(...) 显式包装（#expect 的字符串
            // 转换只对字面量生效）。
            let detail = Comment("\(cell) k=\(cell.k): \(recovered.0)@\(String(recovered.1, radix: 16)) 崩溃恢复终态 \(recovered.3) ≠ 干净直打 \(reference.3)（跨崩溃确定性破坏）")
            #expect(recovered.0 == reference.0 && recovered.1 == reference.1
                    && recovered.2 == reference.2 && recovered.3 == reference.3,
                    detail)
        }
    }

    // MARK: - 矩阵（参数化：每格独立用例，失败定位到格）

    @Test(arguments: CrashMatrixTests.matrix)
    func crashCellInjectsAtEveryWriteSite(_ cell: (pre: String?, cmd: String, writes: Int, k: Int)) throws {
        try runCell(cell)
    }

    /// 格子登记自校验（非注入，独立于矩阵）：每场景干净路径的实测写位点数
    /// 必须与登记一致——k 上界（writes-1）的依据，与每格对照对账互为冗余。
    @Test func registeredWriteCountsMatchCleanPaths() throws {
        let config = try makeConfig()
        let work = try makeWork("count-audit")
        defer { try? FileManager.default.removeItem(at: work) }
        let expectations: [(String?, String, Int)] = [
            (nil, "silent", 4), (nil, "keeptip", 4),
            ("silent", "keeptip", 4), ("silent", "restore", 4),
            ("keeptip", "restore", 4),
        ]
        for (pre, cmd, expected) in expectations {
            let rig = try makeRig(work: work, name: "Count-\(pre ?? "p")-\(cmd)")
            if let pre { _ = try run(pre, app: rig.app, config: config) }
            var count = 0
            Patcher.debugWriteFailureAt = { url, _ in
                guard url.path == rig.dylib.path else { return nil }
                count += 1
                return nil
            }
            defer { Patcher.debugWriteFailureAt = nil }   // 早退兜底
            _ = try run(cmd, app: rig.app, config: config)
            Patcher.debugWriteFailureAt = nil
            #expect(count == expected,
                    "\(pre ?? "pristine")→\(cmd): 登记 \(expected) ≠ 实测 \(count)")
        }
    }
}
#endif
