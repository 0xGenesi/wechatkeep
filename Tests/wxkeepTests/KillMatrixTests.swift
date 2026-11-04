import Foundation
import Testing
@testable import wxkeep

/// L16 非合作崩溃矩阵（V7-DEPTH D20/R20，134 轮）。
///
/// L10（CrashMatrixTests）的 fail-at(k) 是**合作式**注入：代码抛错 →
/// Swift unwind → defer/清理路径执行。那是「引擎优雅处理错误」的模型。
/// 断电/SIGKILL 是**非合作式**：零展开、journal 停在半行、没有任何清理
/// ——两个故障模型（SQLite 崩溃测试机械的经典分工：模拟故障测恢复逻辑，
/// 真 kill 测盘面不变式）。
///
/// 本套件以**子进程真跑 CLI**（完整编排链：journal → 引擎 → 重签）在
/// 与 fail-at(k) 相同的写位点自毙 `SIGKILL`（Patcher.debugKillAtWriteSite
/// 双钥匙：WXKEEP_KILL_AT=位点序号 + WXKEEP_KILL_BIN=目标二进制路径），
/// 每格断言：
///   ① 子进程确实死于信号（terminationReason == .uncaughtSignal，信号 9
///      ——排除「优雅退出伪装崩溃」）；
///   ② 尸体盘面全部位点 ∈ 合法集（inspect 零 .unknown——半行 journal
///      不产生幻觉态）；
///   ③ `wxkeep doctor` 对尸体状态只读判读不崩（exit 0；interrupted
///      journal 的精确指路路径真实可达）；
///   ④ `wxkeep restore` 收敛：位点级字节 == pristine；
///   ⑤ 跨崩溃确定性：restore 后重打 == 干净直打（对照副本位点级恒等）。
///
/// 抖动臂（jitter）：不定位点、随机墙钟偏移 kill 真 CLI——覆盖缝外
/// 崩溃空间（journal 写入中/重签中/进程退出路径）的采样。若 kill 落在
/// 命令完成后（进程已退出），该试验退化为「干净跑 + 恢复」断言面，
/// 同样成立。
///
/// 隔离：子进程经 WXKEEP_DATA_DIR（DEBUG 环境缝）把 journal/备份导向
/// 沙盒目录——不污染真实用户数据位；写位点数由父进程计数缝对照副本
/// 实测对账（L10 纪律：登记只能由实测产生）。
///
/// 诚实边界：夹具 Mach-O 不过 codesign 严格校验（ResignerTests 同结论
/// ——合成 Mach-O 从不存活），全链 --no-resign。**resign 阶段的非合作
/// kill 未被本套件覆盖**——该面由 L10 throw 臂（重签防线触达）+ journal
/// resigned 确认位（110 轮）+ journal 残留强制重签（111 轮）间接承接；
/// 真件 resign 相位的 SIGKILL = 真件 SOP 增量（需真 WeChat 副本，登记
/// V7-DEPTH §6）。
#if DEBUG
@Suite(.serialized)
struct KillMatrixTests {
    /// 与 CrashMatrixTests 同款三 target 目录（build 999999 独立段）。
    private static let catalogJSON = """
    [{"version":"999999","targets":[
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

    private static let siteSpans: [(arch: Config.Arch, va: UInt64, len: Int)] = [
        (.arm64, 0x100, 8), (.arm64, 0x140, 4), (.arm64, 0x180, 4), (.arm64, 0x1C0, 4),
        (.x86_64, 0x100, 9), (.x86_64, 0x140, 3), (.x86_64, 0x1C0, 8),
    ]

    /// 崩溃矩阵格子（与 L10 同表：5 场景 × 4 写位点 = 20 格）。
    /// 写位点数 = L10 对照副本实测值；本套件另有独立计数缝对账（若引擎
    /// 写入数漂移，格子红）。
    private static let matrix: [(pre: String?, cmd: String, writes: Int, k: Int)] = [
        (nil, "silent", 4, 0), (nil, "silent", 4, 1), (nil, "silent", 4, 2), (nil, "silent", 4, 3),
        (nil, "keeptip", 4, 0), (nil, "keeptip", 4, 1), (nil, "keeptip", 4, 2), (nil, "keeptip", 4, 3),
        ("silent", "keeptip", 4, 0), ("silent", "keeptip", 4, 1), ("silent", "keeptip", 4, 2), ("silent", "keeptip", 4, 3),
        ("silent", "restore", 4, 0), ("silent", "restore", 4, 1), ("silent", "restore", 4, 2), ("silent", "restore", 4, 3),
        ("keeptip", "restore", 4, 0), ("keeptip", "restore", 4, 1), ("keeptip", "restore", 4, 2), ("keeptip", "restore", 4, 3),
    ]

    // MARK: - CLI 定位与子进程

    /// Tests/wxkeepTests/X.swift → 仓根 → .build（三跳 + 双布局兼容，
    /// VerifierTests 同款）。
    private func cliBinary() throws -> URL {
        let here = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        for rel in [".build/out/Products/Debug/wxkeep", ".build/debug/wxkeep"] {
            let p = here.appendingPathComponent(rel)
            if FileManager.default.isExecutableFile(atPath: p.path) { return p }
        }
        throw CocoaError(.fileNoSuchFile,
                          userInfo: [NSFilePathErrorKey: "wxkeep CLI binary not built"])
    }

    private struct CLIResult {
        let reason: Process.TerminationReason
        let status: Int32
        let stdout: String
    }

    private func runCLI(_ args: [String], env extra: [String: String] = [:],
                               expectExit0: Bool = true) throws -> CLIResult {
        let p = Process()
        p.executableURL = try cliBinary()
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        for (k, v) in extra { env[k] = v }
        p.environment = env
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        p.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let result = CLIResult(reason: p.terminationReason, status: p.terminationStatus,
                               stdout: String(data: data, encoding: .utf8) ?? "")
        if expectExit0 {
            #expect(result.reason == .exit && result.status == 0,
                    "CLI \(args.joined(separator: " ")) 意外退出：reason=\(result.reason.rawValue) status=\(result.status)\n\(result.stdout.suffix(2000))")
        }
        return result
    }

    // MARK: - fixtures

    private struct Rig {
        let appPath: String
        let dylibPath: String     // == WXKEEP_KILL_BIN 期望值（同串拼接，无标准化差）
        let dylib: URL
        let armOffset: Int
        let x64Offset: Int
        let configPath: String
        let dataDir: URL
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

        // Bundle(url:) 判定 app 的最小 Info.plist：CFBundleVersion = catalog 键。
        // CFBundleExecutable 必须指真实主可执行文件——CLI 编排链的 Resigner
        // 会签 bundle 根（codesign 以主可执行为核心），缺失 = "main
        // executable failed strict validation"（首跑实证）。MachOFixture 是
        // MH_DYLIB，主可执行槽改 MH_EXECUTE 头（filetype @+12）。
        let plist: [String: String] = ["CFBundleVersion": "999999",
                                       "CFBundleShortVersionString": "9.9.9",
                                       "CFBundleExecutable": name.replacingOccurrences(of: ".app", with: "")]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist,
                                                           format: .xml, options: 0)
        try plistData.write(to: app.appendingPathComponent("Contents/Info.plist"))
        let macosDir = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macosDir, withIntermediateDirectories: true)
        var mainExe = MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x200)
        mainExe[12] = 0x02   // MH_EXECUTE（little-endian UInt32 低位字节）
        mainExe[13] = 0; mainExe[14] = 0; mainExe[15] = 0
        try mainExe.write(to: macosDir.appendingPathComponent(
            name.replacingOccurrences(of: ".app", with: "")))

        let configURL = work.appendingPathComponent("\(name)-config.json")
        try Data(Self.catalogJSON.utf8).write(to: configURL)
        let dataDir = work.appendingPathComponent("\(name)-data", isDirectory: true)
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)

        let appPath = app.path
        let dylibPath = URL(fileURLWithPath: appPath)
            .appendingPathComponent("Contents/Resources/wechat.dylib").path
        return Rig(appPath: appPath, dylibPath: dylibPath, dylib: dylib,
                   armOffset: armOffset, x64Offset: x64Offset,
                   configPath: configURL.path, dataDir: dataDir)
    }

    private func baseEnv(_ rig: Rig) -> [String: String] {
        ["WXKEEP_DATA_DIR": rig.dataDir.path]
    }

    private func patchArgs(_ rig: Rig, variant: String) -> [String] {
        ["patch", "--variant", variant, "--no-resign", "-a", rig.appPath, "-c", rig.configPath]
    }
    private func restoreArgs(_ rig: Rig) -> [String] {
        ["restore", "--no-resign", "-a", rig.appPath, "-c", rig.configPath]
    }
    private func doctorArgs(_ rig: Rig) -> [String] {
        ["doctor", "-a", rig.appPath, "-c", rig.configPath]
    }

    // MARK: - 断言原语

    private func sliceBytes(_ rig: Rig, arch: Config.Arch, va: UInt64, len: Int) throws -> Data {
        let data = try Data(contentsOf: URL(fileURLWithPath: rig.dylibPath))
        let base = arch == .arm64 ? rig.armOffset : rig.x64Offset
        return data.subdata(in: (base + Int(va))..<(base + Int(va) + len))
    }

    private func siteHexMap(_ rig: Rig) throws -> [String: String] {
        var out: [String: String] = [:]
        for span in Self.siteSpans {
            out["\(span.arch.rawValue):\(String(span.va, radix: 16))"] =
                try sliceBytes(rig, arch: span.arch, va: span.va, len: span.len).hexUppercase
        }
        return out
    }

    private static let pristineMap: [String: String] = [
        "arm64:100": "F44FBEA9FD7B01A9", "arm64:140": "40100034",
        "arm64:180": "60E600F9", "arm64:1c0": "9101E65E",
        "x86_64:100": "554889E553504889FB", "x86_64:140": "4889C2",
        "x86_64:1c0": "85C00F85CA000000",
    ]

    private func assertLegalSites(_ label: String, rig: Rig) throws {
        let config = try Config(data: Data(Self.catalogJSON.utf8), origin: "kill-matrix")
        let entry = try #require(config.entry(build: "999999"))
        for target in entry.targets {
            let bin = URL(fileURLWithPath: rig.appPath)
                .appendingPathComponent(target.binary ?? "Contents/MacOS/WeChat")
            let inspections = try Patcher.inspect(binary: bin, entries: target.entries,
                                                  identifier: "kill-matrix")
            let unknown = inspections.filter { $0.state == .unknown }
            #expect(unknown.isEmpty,
                    "\(label): \(target.identifier) \(unknown.count) 个位点 ∉ 合法集")
        }
    }

    /// 干净直打对照（⑤ 断言的基准）：fresh rig 上干净执行同命令的终态字节。
    private func cleanTerminal(work: URL, pre: String?, cmd: String) throws -> [String: String] {
        let rig = try makeRig(work: work, name: "CTL-\(UUID().uuidString.prefix(8))")
        if let pre { _ = try runCLI(patchArgs(rig, variant: pre), env: baseEnv(rig)) }
        _ = try cmd == "restore"
            ? runCLI(restoreArgs(rig), env: baseEnv(rig))
            : runCLI(patchArgs(rig, variant: cmd), env: baseEnv(rig))
        return try siteHexMap(rig)
    }

    // MARK: - 写位点数对账（登记由实测产生——L10 纪律）

    @Test func registeredWriteCountsMatchCleanPaths() throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-killctl-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        // 场景去重：矩阵按 k 展开 4 格/场景，计数对账按场景一次。
        var seen = Set<String>()
        for (pre, cmd, writes, _) in Self.matrix {
            guard seen.insert("\(pre ?? "p")|\(cmd)").inserted else { continue }
            let rig = try makeRig(work: work, name: "WC-\(UUID().uuidString.prefix(8))")
            let config = try Config(data: Data(Self.catalogJSON.utf8), origin: "kill-matrix")
            if let pre {
                _ = try Engine.patch(app: URL(fileURLWithPath: rig.appPath), build: "999999",
                                     config: config, variant: pre, dryRun: false,
                                     allowUnverified: false, only: nil)
            }
            // 计数面 = RunSummary 汇总行（"N written, M already-patched" /
            // "N restored"）——不占 debugWriteFailureAt 全局缝：并行套件
            //（EngineTests 等）对该缝的 set/复位互踩曾致计数假低（首跑
            // flaky 红实录；CrashMatrixTests 文件头同案登记）。summary 行
            // 是引擎自报，天然无竞态。
            let summary: Engine.RunSummary
            if cmd == "restore" {
                summary = try Engine.restore(app: URL(fileURLWithPath: rig.appPath), build: "999999",
                                             config: config, dryRun: false)
            } else {
                summary = try Engine.patch(app: URL(fileURLWithPath: rig.appPath), build: "999999",
                                           config: config, variant: cmd, dryRun: false,
                                           allowUnverified: false, only: nil)
            }
            // 与 L10 seam 口径对齐 = Patcher 写调用数：新写（lines 的
            // written 计数）+ undo/restore 臂还原写（restoredSites 逐位点账）。
            var writeCount = summary.restoredSites.count
            for line in summary.lines {
                for m in line.matches(of: /(?<n>\d+) (?:written|restored)/) {
                    writeCount += Int(m.n) ?? 0
                }
            }
            #expect(writeCount == writes,
                    "\(pre ?? "pristine") → \(cmd): 实测写位点 \(writeCount) ≠ 登记 \(writes)（lines=\(summary.lines.joined(separator: " | "))）")
        }
    }

    // MARK: - 矩阵本体（20 格：位点级自毙）

    @Test(arguments: KillMatrixTests.matrix)
    func recoveryConvergesAfterKillAtSite(_ cell: (pre: String?, cmd: String, writes: Int, k: Int)) throws {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-kill-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let label = "\(cell.pre ?? "pristine") → \(cell.cmd) kill@\(cell.k)"

        let rig = try makeRig(work: work, name: "KILL.app")
        // 前置态（干净子进程）
        if let pre = cell.pre { _ = try runCLI(patchArgs(rig, variant: pre), env: baseEnv(rig)) }

        // 自毙运行：与 fail-at(k) 同位点、kill 代替 throw。
        let killEnv = baseEnv(rig).merging(["WXKEEP_KILL_AT": String(cell.k + 1),   // 1 基：第 k+1 次写前自毙（L10 fail-at(k) 同语义）
                                            "WXKEEP_KILL_BIN": rig.dylibPath]) { $1 }
        let killArgs = cell.cmd == "restore" ? restoreArgs(rig) : patchArgs(rig, variant: cell.cmd)
        let killed = try runCLI(killArgs, env: killEnv, expectExit0: false)
        #expect(killed.reason == .uncaughtSignal && killed.status == 9,
                "\(label): 未死于 SIGKILL（reason=\(killed.reason.rawValue) status=\(killed.status)）——缝未触发或被吞")

        // ② 尸体盘面合法性；③ doctor 只读判读；④ restore 收敛 == pristine；
        try assertLegalSites(label, rig: rig)
        _ = try runCLI(doctorArgs(rig), env: baseEnv(rig))
        _ = try runCLI(restoreArgs(rig), env: baseEnv(rig))
        let afterRestore = try siteHexMap(rig)
        for (site, hex) in Self.pristineMap {
            #expect(afterRestore[site] == hex, "\(label): restore 后 \(site) ≠ pristine（\(afterRestore[site] ?? "?")）")
        }

        // ⑤ 跨崩溃确定性：restore 后重打 == 干净直打。
        if cell.cmd != "restore" {
            _ = try runCLI(patchArgs(rig, variant: cell.cmd), env: baseEnv(rig))
            let afterRepatch = try siteHexMap(rig)
            let clean = try cleanTerminal(work: work, pre: cell.pre, cmd: cell.cmd)
            for (site, hex) in clean {
                #expect(afterRepatch[site] == hex,
                        "\(label): 重打 \(site) \(afterRepatch[site] ?? "?") ≠ 干净直打 \(hex)")
            }
        }
    }

    // MARK: - 抖动臂（缝外崩溃空间采样）

    /// 随机墙钟偏移 kill 真 CLI。默认 12 试验（CI 时长预算）；SOP 加大：
    /// WXKEEP_KILL_JITTER_TRIALS=200。kill 落在完成后 = 干净跑，断言面同构。
    @Test func jitterKillsAlwaysLeaveRecoverableState() throws {
        let trials = Int(ProcessInfo.processInfo.environment["WXKEEP_KILL_JITTER_TRIALS"] ?? "") ?? 12
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-jitter-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }
        let rig = try makeRig(work: work, name: "JIT.app")

        // 一次干净跑测基准时长（kill 偏移域 ≈ [30ms, 1.4×T]）。
        let started = Date()
        _ = try runCLI(patchArgs(rig, variant: "silent"), env: baseEnv(rig))
        _ = try runCLI(restoreArgs(rig), env: baseEnv(rig))
        let baseline = Date().timeIntervalSince(started)
        #expect(baseline > 0.05, "基准时长异常小：\(baseline)s——spawn 可能未真跑")

        var killedCount = 0
        for trial in 0..<trials {
            let offsetUS = UInt32.random(in: 30_000...UInt32(max(60_000, UInt32(baseline * 1.4 * 1_000_000))))
            let p = Process()
            p.executableURL = try cliBinary()
            p.arguments = patchArgs(rig, variant: "keeptip")
            p.environment = ProcessInfo.processInfo.environment
                .merging(baseEnv(rig)) { $1 }
            let out = Pipe()
            p.standardOutput = out
            p.standardError = out
            try p.run()
            usleep(offsetUS)
            if p.isRunning { _ = kill(p.processIdentifier, SIGKILL); killedCount += 1 }
            p.waitUntilExit()
            _ = out.fileHandleForReading.readDataToEndOfFile()

            try assertLegalSites("jitter[\(trial)]", rig: rig)
            _ = try runCLI(restoreArgs(rig), env: baseEnv(rig))
            let after = try siteHexMap(rig)
            for (site, hex) in Self.pristineMap {
                #expect(after[site] == hex,
                        "jitter[\(trial)]: restore 后 \(site) ≠ pristine（\(after[site] ?? "?")）")
            }
        }
        // 灵敏度自证：试验域内确有 kill 落在运行窗（否则抖动臂退化为纯干净跑）。
        #expect(killedCount > 0,
                "\(trials) 次试验全部落在运行窗外——偏移域需重估（基准 \(baseline)s）")
    }
}
#endif
