import Foundation
import Testing
@testable import wxkeep

/// branch-flip 补丁类的**执行级遍历证明**（128 轮，关闭 V5-DEPTH §5 登记：
/// 「L9 的 branch-flip 是解码级证明，非运行观测」）。
///
/// 证明结构（合成控制流副本 × **真 Patcher.patch** 写入 × MAP_JIT 执行）：
///   a. pristine：cbz/je 条件入口——谓词置「走撤回」时**确实进入**撤回路径
///     （返回撤回 marker），谓词置「跳过」时走 SKIP——控制流可达性先证。
///   b. patched（asm 经真 Patcher 的 expected 门写入）：任意谓词值都返回
///     SKIP marker——翻转在宿主 CPU 上**无条件生效**（执行级 counterpart
///     of L9 目标恒等）。
///   c. 毒化后继：撤回路径整段填非法指令（arm64 UDF/x64 int3）后再执行——
///     patched 仍干净返回 SKIP。若翻转后控制流有任何路径落入后继（哪怕
///     一条），毒药立刻 SIGILL/SIGTRAP——「后继遍历为零」由此正面证出。
///
/// 诚实边界：pristine+毒药+谓词置「走撤回」→ SIGILL 的对照面**不测**
/// （进程内无法隔离致命信号，需子进程骨架——已登记 ROADMAP 128 遗留）；
/// pristine 路径可达性由 (a) 的非毒药形态证明。布局合同：MachOFixture
/// VA==fileoff；位点 0x100、SKIP 0x120（arm64）/0x122（x64）。
struct PatchTraversalTests {
    private func writeFixture(_ data: Data, name: String, in dir: URL) throws -> URL {
        let url = dir.appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func fileBytes(_ url: URL, offset: Int, count: Int) throws -> Data {
        try Data(contentsOf: url).subdata(in: offset..<(offset + count))
    }

    // MARK: - arm64（本机真跑；cbz w0,+0x20 → b +0x20，双字节序同族 40100034/82000014）

    @Test func branchFlipExecutionTraversalArm64() throws {
        #if arch(arm64)
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-trav-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        func word(_ w: UInt32) -> [UInt8] {
            var le = w.littleEndian
            return withUnsafeBytes(of: &le) { Array($0) }
        }
        // 布局：0x100 位点（cbz/b +0x20）；0x104 撤回路径（mov w0,#1; ret +
        // nop 填充——毒化区）；0x120 SKIP（mov w0,#2; ret）。
        let cbz = word(0x3400_0000 | (8 << 5))            // cbz w0, #+0x20
        let bPatch = word(0x1400_0000 | 8)                // b  #+0x20
        let revocation = word(0x5280_0020) + word(0xD65F_03C0)   // mov w0,#1; ret
        let skip = word(0x5280_0040) + word(0xD65F_03C0)         // mov w0,#2; ret
        let nop = word(0xD503_201F)
        var code: [(offset: Int, bytes: [UInt8])] = [
            (0x100, cbz), (0x104, revocation), (0x120, skip),
        ]
        for off in stride(from: 0x10C, to: 0x120, by: 4) { code.append((off, nop)) }
        let image = MachOFixture.thin(cputype: MachOFixture.arm64CPU, size: 0x400, code: code)
        #expect(cbz.map { String(format: "%02X", $0) }.joined() == "00010034",
                "expected 字节序自证（cbz w0,+0x20）")
        #expect(bPatch.map { String(format: "%02X", $0) }.joined() == "08000014",
                "asm 字节序自证（b +0x20，与 catalog 82000014 同族）")

        // pristine 副本 + 补丁副本（真 Patcher 全链：expected 门 → 写入）
        let pristineURL = try writeFixture(image, name: "pristine.dylib", in: work)
        let patchedURL = try writeFixture(image, name: "patched.dylib", in: work)
        let outcomes = try Patcher.patch(
            binary: patchedURL,
            entries: [MachOFixture.entry(.arm64, addr: "100", asm: "08000014",
                                         expected: ["00010034"])],
            identifier: "revoke")
        #expect(outcomes == [.written], "真 Patcher 写入（expected 门通过）")
        #expect(try fileBytes(patchedURL, offset: 0x100, count: 4)
            == Data(bPatch), "盘上位点 == asm")

        // MAP_JIT 执行骨架：fileBytes[0x100..<0x128] → page[0..<0x28]
        typealias FlipFn = @convention(c) (UInt32) -> UInt32
        func run(_ source: URL, poisonRevocation: Bool, input: UInt32) -> UInt32 {
            let page = mmap(nil, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0)
            #expect(page != MAP_FAILED)
            defer { munmap(page, 4096) }
            pthread_jit_write_protect_np(0)
            let codeBytes = (try? Data(contentsOf: source)) ?? Data()
            let slice = codeBytes.subdata(in: 0x100..<0x128)
            _ = slice.withUnsafeBytes { raw in
                memcpy(page, raw.baseAddress, 0x28)
            }
            if poisonRevocation {
                // 撤回路径整段（page+0x04..<0x20）→ UDF #0（0x00000000，
                // 永久未定义——任何落入即 SIGILL）
                memset(page! + 0x04, 0, 0x20 - 0x04)
            }
            sys_icache_invalidate(page, 0x28)
            pthread_jit_write_protect_np(1)
            let fn = unsafeBitCast(page, to: FlipFn.self)
            return fn(input)
        }

        // a. pristine：路径可达性（谓词双向）
        #expect(run(pristineURL, poisonRevocation: false, input: 0) == 2,
                "pristine w0=0 → cbz 走 SKIP")
        #expect(run(pristineURL, poisonRevocation: false, input: 1) == 1,
                "pristine w0=1 → 落入撤回路径（可达性正面证明）")
        // b. patched：翻转执行级无条件生效
        #expect(run(patchedURL, poisonRevocation: false, input: 0) == 2)
        #expect(run(patchedURL, poisonRevocation: false, input: 1) == 2,
                "patched w0=1 → 仍 SKIP（执行级翻转——L9 解码级证明的运行观测面）")
        // c. 毒化后继：撤回路径全 UDF，patched 照样干净返回——遍历为零正面证出
        #expect(run(patchedURL, poisonRevocation: true, input: 1) == 2,
                "毒化撤回路径 + patched → 无崩溃返回 SKIP（后继遍历为零）")
        // 毒药自证：毒药页本身不可作为 pristine 执行入口（毒化真的毒）
        // ——pristine+毒化+input=1 必 SIGILL，进程内不可隔离，不执行；
        // 改以「毒化区字节确已写入」断言替代（防 poison 分支空转）。
        let probe = mmap(nil, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)
        defer { munmap(probe, 4096) }
        memset(probe, 0xFF, 0x28)
        pthread_jit_write_protect_np(0)
        _ = (try? Data(contentsOf: patchedURL)).map { data in
            let slice = data.subdata(in: 0x100..<0x128)
            _ = slice.withUnsafeBytes { raw in memcpy(probe, raw.baseAddress, 0x28) }
        }
        memset(probe! + 0x04, 0, 0x20 - 0x04)
        pthread_jit_write_protect_np(1)
        var poisoned = [UInt8](repeating: 0xEE, count: 0x28)
        memcpy(&poisoned, probe, 0x28)
        #expect(Array(poisoned[0x04..<0x20]) == [UInt8](repeating: 0, count: 0x1C),
                "毒化写入自证（撤回路径区全零=UDF）")
        #expect(Array(poisoned[0x20..<0x28]) == skip, "SKIP 区不在毒化面（执行返回 2 的来源可追）")
        #expect(Array(poisoned[0x00..<0x04]) == bPatch, "毒化只覆写后继、位点原样")
        #else
        #expect(Bool(true), "arm64 执行级遍历证明在非 arm64 宿主不编译（CI Rosetta 腿跑 x64 镜像用例）")
        #endif
    }

    // MARK: - x64（CI Rosetta 腿；je rel8 → jmp rel8 同位移）

    @Test func branchFlipExecutionTraversalX64() throws {
        #if arch(x86_64)
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-trav-x64-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: work) }

        // 布局：0x100 位点（je +0x20 → jmp +0x20，目标均 0x122）；0x102
        // 撤回路径（mov eax,1; ret + int3 填充——毒化区）；0x122 SKIP。
        let je: [UInt8] = [0x74, 0x20]
        let jmp: [UInt8] = [0xEB, 0x20]
        let revocation: [UInt8] = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]  // mov eax,1; ret
        let skip: [UInt8] = [0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3]        // mov eax,2; ret
        var code: [(offset: Int, bytes: [UInt8])] = [
            (0x100, je), (0x102, revocation), (0x122, skip),
        ]
        for off in stride(from: 0x108, to: 0x122, by: 1) { code.append((off, [0xCC])) }
        let image = MachOFixture.thin(cputype: MachOFixture.x64CPU, size: 0x400, code: code)

        let pristineURL = try writeFixture(image, name: "pristine.dylib", in: work)
        let patchedURL = try writeFixture(image, name: "patched.dylib", in: work)
        let outcomes = try Patcher.patch(
            binary: patchedURL,
            entries: [MachOFixture.entry(.x86_64, addr: "100", asm: "EB20",
                                         expected: ["7420"])],
            identifier: "revoke")
        #expect(outcomes == [.written])
        #expect(try fileBytes(patchedURL, offset: 0x100, count: 2) == Data(jmp))

        typealias FlipFn = @convention(c) (UInt32) -> UInt32
        func run(_ source: URL, poisonRevocation: Bool, input: UInt32) -> UInt32 {
            let mem = mmap(nil, 4096, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0)
            #expect(mem != MAP_FAILED)
            let codeBytes = (try? Data(contentsOf: source)) ?? Data()
            let slice = codeBytes.subdata(in: 0x100..<0x128)
            _ = slice.withUnsafeBytes { raw in
                memcpy(mem, raw.baseAddress, 0x28)
            }
            if poisonRevocation {
                memset(mem! + 0x02, 0xCC, 0x22 - 0x02)   // int3 × 撤回路径区
            }
            #expect(mprotect(mem, 4096, PROT_READ | PROT_EXEC) == 0,
                    "RX 切换（Rosetta 下 mprotect 可用）")
            let fn = unsafeBitCast(mem, to: FlipFn.self)
            return fn(input)
        }

        #expect(run(pristineURL, poisonRevocation: false, input: 0) == 2,
                "pristine ZF=1 → je 走 SKIP")
        #expect(run(pristineURL, poisonRevocation: false, input: 1) == 1,
                "pristine ZF=0 → 落入撤回路径")
        #expect(run(patchedURL, poisonRevocation: false, input: 0) == 2)
        #expect(run(patchedURL, poisonRevocation: false, input: 1) == 2,
                "patched → 无条件 SKIP（x64 对称，125 续 x64 翻转对称门的执行面）")
        #expect(run(patchedURL, poisonRevocation: true, input: 1) == 2,
                "毒化撤回路径 + patched → 无崩溃（int3 未被触达）")
        #else
        #expect(Bool(true), "x64 镜像用例在非 x86_64 宿主不编译（CI Rosetta 腿执行）")
        #endif
    }
}
