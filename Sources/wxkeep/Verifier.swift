import Foundation

#if arch(arm64)
// JIT 区懒修复处理器（macOS 27 专用兜底——np 开关失效、回调 API 被移除）：
// 故障落在 JIT 区内即 mprotect 授 RWX 并返回（指令自动重试）；mprotect 被
// 拒则打印 errno（= 系统最终策略的答案）。macOS ≤15 np 正常，永不触发。
// 区域信息走文件级全局（@convention(c) 处理器不能捕获局部量）。
//
// 无分配纪律（136 轮评审 P2）：处理器内禁一切 malloc 路径——fault 本身
// 可能正发生在分配器内部（堆扩容首触新页的 lazy fault 是现实常见源），
// 处理器内重入分配器 = 同线程死锁 → worker 永挂（父进程 Shell.run 无
// 超时=登记债，verify 整条命令挂死）。字符串插值/String(radix:)/Array
// 追加全数回避：静态前缀在**启动时**物化为全局 [UInt8]，动态值
//（errno/fault_addr/region/sig）经栈上指针写进预分配缓冲 + 手写 u64→hex
// ——write(2) 本身 async-signal-safe。
nonisolated(unsafe) var workerJITRegionAddr: UInt = 0
nonisolated(unsafe) var workerJITRegionSize: Int = 0
nonisolated(unsafe) var workerDiagBuf = [UInt8](repeating: 0, count: 192)
nonisolated(unsafe) let workerDiagDeniedPrefix =
    Array("wxkeep-verify: JIT mprotect denied errno=".utf8)
nonisolated(unsafe) let workerDiagOutsidePrefix =
    Array("wxkeep-verify: signal ".utf8)
nonisolated(unsafe) let workerDiagFaultMid = Array(" fault=0x".utf8)
nonisolated(unsafe) let workerDiagRegionMid = Array(" region=0x".utf8)
nonisolated(unsafe) let workerDiagPlusMid = Array("+0x".utf8)
nonisolated(unsafe) let workerDiagSigMid = Array(" sig=".utf8)
nonisolated(unsafe) let workerDiagOutsideMid = Array(" outside-JIT addr=0x".utf8)
nonisolated(unsafe) let workerDiagTail = Array(" unmodeled-state\n".utf8)

/// 手写 u64→小写 hex（无前导零；0 输出 "0"）。只写预分配缓冲，不分配。
@inline(__always)
func workerDiagHex(_ v: UInt64, into p: UnsafeMutablePointer<UInt8>, from i: Int) -> Int {
    var i = i, started = false, shift = 60
    while shift >= 0 {
        let nib = UInt8((v >> UInt64(shift)) & 0xF)
        if nib != 0 || started || shift == 0 {
            p[i] = nib < 10 ? nib + 48 : nib + 87   // '0'..'9' / 'a'..'f'
            i += 1; started = true
        }
        shift -= 4
    }
    return i
}

/// 手写 i32→十进制（负数带 '-'；errno/sig 用）。不分配。
@inline(__always)
func workerDiagDec(_ v: Int32, into p: UnsafeMutablePointer<UInt8>, from i: Int) -> Int {
    var i = i
    var value = v
    if value < 0 { p[i] = 45; i += 1; value = v == Int32.min ? v : -v }   // '-'
    if v == Int32.min {   // 唯一溢出处直接落位（-(min) 不可表示）
        for c in "2147483648".utf8 { p[i] = c; i += 1 }
        return i
    }
    var digits = 0, probe = value
    repeat { digits += 1; probe /= 10 } while probe > 0
    i += digits
    var w = i - 1
    repeat { p[w] = UInt8(48 + value % 10); w -= 1; value /= 10 } while value > 0
    return i
}

let workerJITFaultHandler: @convention(c) (Int32, UnsafeMutablePointer<siginfo_t>?, UnsafeMutableRawPointer?) -> Void = { sig, info, _ in
    let addr = info.map { UInt(bitPattern: $0.pointee.si_addr) } ?? 0
    if addr >= workerJITRegionAddr, addr < workerJITRegionAddr + UInt(max(workerJITRegionSize, 0)) {
        let page = addr & ~UInt(0x3FFF)   // 16K 页对齐
        if mprotect(UnsafeMutableRawPointer(bitPattern: page)!, 0x4000,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0 { return }   // 重试故障指令
        workerDiagBuf.withUnsafeMutableBufferPointer { b in
            guard let p = b.baseAddress else { return }
            var i = 0
            for c in workerDiagDeniedPrefix { p[i] = c; i += 1 }
            i = workerDiagDec(errno, into: p, from: i)
            for c in workerDiagFaultMid { p[i] = c; i += 1 }
            i = workerDiagHex(UInt64(addr), into: p, from: i)
            for c in workerDiagRegionMid { p[i] = c; i += 1 }
            i = workerDiagHex(UInt64(workerJITRegionAddr), into: p, from: i)
            for c in workerDiagPlusMid { p[i] = c; i += 1 }
            i = workerDiagHex(UInt64(UInt(max(workerJITRegionSize, 0))), into: p, from: i)
            for c in workerDiagSigMid { p[i] = c; i += 1 }
            i = workerDiagDec(sig, into: p, from: i)
            p[i] = 10; i += 1   // '\n'
            _ = write(2, p, i)
        }
    } else {
        workerDiagBuf.withUnsafeMutableBufferPointer { b in
            guard let p = b.baseAddress else { return }
            var i = 0
            for c in workerDiagOutsidePrefix { p[i] = c; i += 1 }
            i = workerDiagDec(sig, into: p, from: i)
            for c in workerDiagOutsideMid { p[i] = c; i += 1 }
            i = workerDiagHex(UInt64(addr), into: p, from: i)
            for c in workerDiagTail { p[i] = c; i += 1 }
            _ = write(2, p, i)
        }
    }
    _exit(129)
}
#endif

/// Behavioral verification: prove a patch's EFFECT by calling the patched
/// function out-of-process (mini-loader route — no dyld, no initializers,
/// no app bundle deps; validated by the M2-3 spike on real 269602 x64).
///
/// Architecture: the CLI re-execs itself as a hidden `__verify-worker` so a
/// crash inside mapped code kills only the worker; the parent interprets the
/// exit status (0 = probes ran; signal = crash / environment blocks unsigned
/// executable memory).
///
/// The worker exploits this image family's layout invariants:
///   - file offset == VA across __TEXT/__DATA_CONST/__DATA → base+VA indexing
///   - imports the target calls go through PLT stubs (`ff 25 <rel32>`) whose
///     GOT slots can be redirected to native harness functions
///   - C++ magic-static regions start zeroed at runtime; raw file bytes are
///     not the runtime state → explicit zero prep
///   - arguments use WeChat's custom SSO string layout (size<<1 in byte 0,
///     LSB = long flag; short data at +1; long: size@+8, ptr@+0x10)
enum Verifier {
    enum VerifyError: Error, CustomStringConvertible {
        case noVerifySpec(arch: String)
        case workerCrashed(signal: Int32)
        case environmentBlocked
        case specRejected(String)
        /// spec 绑定单一构建家族（270099 族）：stub VA 在本镜像里不是桩 /
        /// 越界 = spec 不适用于该构建。优雅跳过路径，不是失败。
        case specNotApplicable(String)
        case archMismatch(image: String, host: String)
        case mismatch(detail: String)

        var description: String {
            switch self {
            case .noVerifySpec(let arch):
                "no verify spec for \(arch) in signatures.json — behavior check unavailable for this build"
            case .workerCrashed(let sig):
                "verification worker crashed (signal \(sig)) — the function touched state we didn't model"
            case .environmentBlocked:
                "environment blocked executing mapped code (mmap of executable memory was refused, "
                + "or the system killed the worker — AMFI/taskgated; on arm64 the JIT entitlement "
                + "would be required; strict verify remains available)"
            case .specRejected(let detail):
                "verify spec rejected by the worker: \(detail) — the spec encodes the "
                + "270099-family ground truth and does not fit this image"
            case .specNotApplicable(let detail):
                "verify spec does not fit this image (\(detail)) — the spec is bound to one build "
                + "family and this image is outside it; behavioral verification does not apply "
                + "(strict byte-level verify remains valid)"
            case .archMismatch(let image, let host):
                "dylib slice is \(image) but this machine runs \(host) — behavioral verification "
                + "executes mapped code natively and cannot cross architectures"
            case .mismatch(let detail):
                "behavior mismatch: \(detail)"
            }
        }
    }

    enum ImageArch: String {
        case x86_64
        case arm64

        /// Host architecture. In a universal binary each slice sees its own
        /// compile-time arch, which equals the runtime arch — exactly what the
        /// worker needs (it executes mapped code natively, no cross-arch).
        static var host: ImageArch {
            #if arch(arm64)
            return .arm64
            #else
            return .x86_64
            #endif
        }

        static func cputypeArch(_ raw: UInt32) -> ImageArch? {
            switch raw {
            case 0x0100_000C: return .arm64
            case 0x0100_0007: return .x86_64
            default: return nil
            }
        }
    }

    struct VerifySpec: Codable {
        /// hex stub VA → "strlen" / "memcmp" (native replacements)
        let stubs: [String: String]
        /// [[hexVA, byteLen], ...] regions to zero before probing (magic statics)
        let zeroRegions: [[String]]
        /// [text, expectedOnPristine(0/1), ...]
        let probes: [[String]]

        enum CodingKeys: String, CodingKey {
            case stubs, probes
            case zeroRegions = "zero_regions"
        }
    }

    struct ProbeResult {
        let text: String
        let returned: Bool
        /// 该探针是否真实执行（worker 侧构造失败/超长跳过时 false——判定
        /// 面必须按文本对位而非 zip 位置对位，否则跳过造成错位比较）。
        var executed: Bool = true

        init(text: String, returned: Bool, executed: Bool = true) {
            self.text = text
            self.returned = returned
            self.executed = executed
        }
    }

    // MARK: - arm64 specifics (270100/270099 predicate ground truth)

    /// arm64 布局差异的集中地。桩形 = `adrp x16,<page>; ldr x16,[x16,#off]; br x16`
    /// （无 x64 的 ff25 PLT）；SSO 短串布局 = 数据在偏移 0、直接长度字节在 +0x17
    /// （与 x64 的 size<<1@0 + 数据@+1 不同——两架构字符串 ABI 不同源）。
    enum ARM64 {
        static let brX16: UInt32 = 0xD61F_0200

        /// 12B 桩 → 映射内 GOT 槽偏移；形态不符返回 nil（适用范围门的解码
        /// 半边：坏 spec 在 worker 侧 exit(4) 优雅跳过——静默跳过会留
        /// chained-fixup 原始值，调用即崩）。目标寄存器也必须是 x16：
        /// adrp 的 Rd 与 ldr 的 Rt 同检——非 x16 的同形态指令不是桩
        /// （防误匹配把无关 adrp+ldr 对当桩重定向）。
        static func stubSlotOffset(pcOffset: UInt64, w0: UInt32, w1: UInt32, w2: UInt32) -> Int? {
            guard (w0 >> 31) == 1, ((w0 >> 24) & 0x1F) == 0x10, (w0 & 0x1F) == 0x10 else { return nil }   // adrp x16
            guard ((w1 >> 22) & 0x3FF) == 0x3E5, ((w1 >> 5) & 0x1F) == 0x10, (w1 & 0x1F) == 0x10 else { return nil } // ldr x16,[x16,#imm]
            guard w2 == brX16 else { return nil }
            let immlo = (w0 >> 29) & 0x3
            let immhi = (w0 >> 5) & 0x7_FFFF
            var imm = Int64(immhi << 2 | immlo)
            if imm & (1 << 20) != 0 { imm -= (1 << 21) }
            let page = Int64(pcOffset & ~0xFFF) + (imm << 12)
            let slot = page + Int64((w1 >> 10) & 0xFFF) * 8
            return slot >= 0 ? Int(slot) : nil
        }

        static func stubSlotOffset(pcOffset: UInt64, bytes: [UInt8]) -> Int? {
            guard bytes.count >= 12 else { return nil }
            func word(_ o: Int) -> UInt32 {
                UInt32(bytes[o]) | UInt32(bytes[o+1]) << 8 | UInt32(bytes[o+2]) << 16 | UInt32(bytes[o+3]) << 24
            }
            return stubSlotOffset(pcOffset: pcOffset, w0: word(0), w1: word(4), w2: word(8))
        }

        /// arm64 探针 SSO：数据 @0、长度字节 @0x17（直接长度）。短串 only。
        /// 上限与 storage 绑定（24B：长度字节占 [0x17]，有效载荷 ≤23）——
        /// 此前守卫写 0x40，超长探针文本在此越界写崩 worker（x64 分支的
        /// <23 才是正确语义；中文 3B/汉字，8 个汉字即 24B 可达）。
        static func ssoProbe(_ text: String) -> [UInt8]? {
            let bytes = Array(text.utf8)
            var storage = [UInt8](repeating: 0, count: 24)
            guard bytes.count < storage.count else { return nil }
            for (i, byte) in bytes.enumerated() { storage[i] = byte }
            storage[0x17] = UInt8(bytes.count)
            return storage
        }

        /// parse 内 cbz 位点 -4 处的 BL → 谓词 VA（gen3 形态：
        /// `mov x0,x22; bl <pred>; cbz w0,<skip>`）。thin 镜像 VA==文件偏移。
        static func predicateVA(fileData: Data, site: UInt64) -> UInt64? {
            guard site >= 4, Int(site) <= fileData.count else { return nil }
            let word = fileData.withUnsafeBytes {
                $0.loadUnaligned(fromByteOffset: Int(site - 4), as: UInt32.self)
            }
            return blTargetVA(word: word, blVA: site - 4)
        }

        /// MachImage 形态（fat 装机件必须走这里）：VA 经段表换算到切片内
        /// 偏移。fat 容器里 arm64 切片起点 ≠ 0，直接拿原始文件字节按
        /// VA 索引会读错位置（首次实机验收前拦下的缺陷）。
        static func predicateVA(image: MachImage, site: UInt64) -> UInt64? {
            guard site >= 4, let word = image.word32(va: site - 4) else { return nil }
            return blTargetVA(word: word, blVA: site - 4)
        }

        /// BL word（小端已组装）→ 目标 VA；非 BL 返回 nil。
        static func blTargetVA(word: UInt32, blVA: UInt64) -> UInt64? {
            guard (word >> 26) == 0x25 else { return nil }   // BL: 100101
            var imm26 = Int32(bitPattern: word) & 0x3FF_FFFF
            if imm26 & (1 << 25) != 0 { imm26 -= (1 << 26) }
            let target = Int64(blVA) + Int64(imm26) * 4
            return target >= 0 ? UInt64(target) : nil
        }
    }

    // MARK: - Worker exit interpretation

    /// Worker 退出码 → 语义判定（纯函数，便于回归）。判定事实基础：
    /// - worker 由 Shell 直 exec（无 shell 包装），Darwin Foundation 对信号
    ///   死亡给的是**裸信号号**（SIGKILL→9/SIGSEGV→11，非 128+n；2026-09
    ///   实测四信号一致）——旧实现按 128+n 约定判读，`status > 128` 与
    ///   `status == 137` 两分支在直 exec 拓扑下均不可达，SIGKILL（AMFI/
    ///   taskgated 击杀，本仓两代先例）被误报成「函数摸了未建模状态」。
    /// - worker 自身只 exit 0/2/3/4/126：126 = mmap 拒绝 / harness 解析
    ///   strlen/memcmp 失败（环境门）；2 = 参数拒绝；3 = 探针目标 VA 越界
    ///   （wxkeep 数据 bug，防御位）；4 = **spec 不适用于此镜像**（stub 形态
    ///   不符或越界——spec 绑定单一构建家族，老构建上优雅跳过而非报错。
    ///   与 2/3 的关键差别：4 对所有架构都是预期内的「不适用」，父进程以
    ///   提示收场退出 0）。
    /// - 映射的目标函数不可能自杀 SIGKILL（导入调用已被重定向到原生桩）——
    ///   SIGKILL 只能来自环境；SIGSEGV/SIGBUS/SIGILL 才是真 crash。
    /// - 裸信号 4（SIGILL）与干净的 exit(4) 靠 `signalled` 区分：信号死亡
    ///   走上面的 signalled 分支，永不落进本 switch。
    static func interpretWorkerExit(_ status: Int32, signalled: Bool) -> VerifyError? {
        if signalled {
            return status == SIGKILL ? .environmentBlocked : .workerCrashed(signal: status)
        }
        switch status {
        case 0: return nil
        case 126: return .environmentBlocked
        case 129: return .environmentBlocked   // SIGBUS/SIGSEGV 捕获后的干净退出（诊断信息走 stderr 透传）
        case 137: return .environmentBlocked   // shell 包装拓扑防御位（128+SIGKILL）
        case 2: return .specRejected("malformed worker arguments")
        case 3: return .specRejected("probe target VA out of the mapped image's bounds")
        case 4: return .specNotApplicable("spec stub VAs don't decode as import stubs in this image")
        default: return .workerCrashed(signal: status)
        }
    }

    // MARK: - Probe-entry selection

    /// arm64 行为验证 worker 的崩溃是否属环境受限（良性）：CI macos-15 全绿，
    /// 真机（更新 macOS/新芯片）实测 SIGBUS——arm64 探针语义本就是「家族完整
    /// 性 + harness 自检」（补丁效果由 strict verify 字节级证明承担），崩溃
    /// 说明 harness 在该环境受限，不代表补丁坏。x64 的崩溃仍视为异常（那里
    /// 探针就是补丁函数本体）。
    static func arm64WorkerFailureIsBenign(_ error: VerifyError) -> Bool {
        switch error {
        case .workerCrashed, .environmentBlocked: return true
        default: return false
        }
    }

    /// x64 行为验证的探针条目：verify spec（stubs/zero/probe 语义）与
    /// revoke_x64 配方描述的是同一个函数（isRevokemsg 中性化——两者 asm
    /// 相同）。部分构建的 revoke 目标首个 x64 条目是 parse 入口 silent
    /// （`B801000000C3`，如 269629/269631/269578/579 及 3.x 旧代），按
    /// 配方 asm 匹配才能取到 spec 实际描述的位点。
    ///
    /// 无 asm 匹配返回 nil——旧实现的「回落首个条目」会把探针放到 spec
    /// 未描述的函数上：探的是别的代码，结果无意义，崩溃还误导排障方向
    /// （269631 实测链的一环）。调用方以「spec 不适用于该构建」优雅跳过。
    static func selectX64ProbeEntry(
        in entries: [Config.PatchEntry], recipeAsm: String?
    ) -> Config.PatchEntry? {
        guard let recipeAsm else { return nil }
        return entries.filter { $0.arch == .x86_64 }.first { $0.asm == recipeAsm }
    }

    // MARK: - Parent side

    /// 环境能力探针：以最小 blob（host 架构的一条 ret，va=0）真起一次
    /// worker。exit 0 = 可执行动态代码——arm64 走 MAP_JIT（非 hardened 进程
    /// 免 entitlement），x64 直接 RWX；失败即环境拒绝（hardened runtime 无
    /// JIT entitlement 等）。比读 nvram boot-args 诚实：测的是 worker 的实际
    /// 能力，而非引导参数长什么样。
    static func workerCanExecute(binary: URL) -> Bool {
        let work = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-rwxprobe-\(UUID().uuidString)")
        do {
            try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
            // 裸 blob（无 Mach-O 头）→ worker 走恒等映射路径。
            var data = Data(count: 0x100)
            if ImageArch.host == .arm64 {
                data.replaceSubrange(0..<4, with: [0xC0, 0x03, 0x5F, 0xD6])   // ret
            } else {
                data[0] = 0xC3                                                // ret
            }
            try data.write(to: work.appendingPathComponent("probe.bin"))
        } catch { return false }
        defer { try? FileManager.default.removeItem(at: work) }
        let result = Shell.run(binary.path, [
            "__verify-worker", work.appendingPathComponent("probe.bin").path,
            "0", "{}", "[]", "[[\"x\",\"1\"]]",
        ])
        return result.status == 0
    }

    /// Runs behavioral probes against `dylib` (thin or fat; fat slices are
    /// extracted via lipo). Returns one result per probe, in spec order.
    static func run(binary: URL, targetVA: UInt64, spec: VerifySpec,
                    executable: URL? = nil) throws -> [ProbeResult] {
        // Fat → the HOST-arch thin slice (the worker executes mapped code
        // natively — no cross-arch); thin images must match the host too.
        let head = (try? Data(contentsOf: binary, options: .alwaysMapped).prefix(8)) ?? Data()
        let imageArch: ImageArch
        var thin = binary
        var tempThin: URL?
        let magic = head.prefix(4)
        if magic.elementsEqual(Data([0xCA, 0xFE, 0xBA, 0xBF])) {
            // FAT64 误入 thin 判定会把 8 字节 fat 头当 blob 执行——显式拒绝
            throw VerifyError.archMismatch(image: "fat64 (FAT_MAGIC_64)", host: ImageArch.host.rawValue)
        }
        if magic.elementsEqual(Data([0xCA, 0xFE, 0xBA, 0xBE])) {
            let host = ImageArch.host
            let out = FileManager.default.temporaryDirectory
                .appendingPathComponent("wxkeep-verify-\(UUID().uuidString).\(host.rawValue)")
            let lipo = Shell.run("/usr/bin/lipo", ["-thin", host.rawValue, binary.path, "-output", out.path])
            guard lipo.status == 0 else { throw VerifyError.archMismatch(
                image: "fat (no \(host.rawValue) slice)", host: host.rawValue) }
            thin = out
            tempThin = out
            imageArch = host
        } else if head.count >= 8, let a = ImageArch.cputypeArch(
            UInt32(head[4]) | UInt32(head[5]) << 8 | UInt32(head[6]) << 16 | UInt32(head[7]) << 24) {
            imageArch = a
        } else {
            imageArch = ImageArch.host   // bare synthetic blobs (test fixtures)
        }
        if imageArch != ImageArch.host {
            throw VerifyError.archMismatch(image: imageArch.rawValue, host: ImageArch.host.rawValue)
        }
        defer { if let tempThin { try? FileManager.default.removeItem(at: tempThin) } }

        let stubsJSON = jsonString(spec.stubs) ?? "{}"
        let zerosJSON = jsonString(spec.zeroRegions) ?? "[]"
        let probesJSON = jsonString(spec.probes) ?? "[]"
        let exe = executable ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let result = Shell.run(exe.path, [
            "__verify-worker", thin.path, String(targetVA, radix: 16),
            stubsJSON, zerosJSON, probesJSON,
        ])
        if let failure = interpretWorkerExit(result.status, signalled: result.signalled) {
            // worker 的 stderr 是诊断面（SIGBUS/SIGSEGV 捕获信息、环境细节）
            // ——裸抛会把它们丢进虚空。specNotApplicable 是优雅跳过路径：
            // 细节以缩进行呈现（不带 worker: 告警前缀）。
            let stderr = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if case .specNotApplicable = failure {
                if !stderr.isEmpty { print("  ↳ \(stderr)") }
            } else if !stderr.isEmpty {
                print("worker: \(stderr)")
            }
            throw failure
        }
        return result.stdout.split(separator: "\n").compactMap { line in
            // probe|<text>|<0|1|skip>——每个 spec 探针恒出一行（构造失败也出
            // skip 行）：判定面按文本对位，位置 zip 在有跳过时会把结果 N 对
            // 到期望 N+1（假阴/假阳都出过）。
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "probe" else { return nil }
            return ProbeResult(text: String(parts[1]), returned: parts[2] == "1",
                               executed: parts[2] != "skip")
        }
    }

    private static func jsonString<T: Encodable>(_ value: T) -> String? {
        guard let data = try? JSONEncoder().encode(value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - 共享映射底座（verify worker 与 parse-oracle worker 同源）

    /// 分段忠实映射 + arm64 MAP_JIT 拆分 + W^X 态管理。与旧 workerMain
    /// 内联实现逐行等价（VerifierTests 双架构 e2e 锁定行为）：
    /// - 裸 blob（无 Mach-O 头）→ 恒等单区映射（测试 fixture 路径）
    /// - 镜像 → 段表解析；arm64 按 EXEC 前缀段拆「JIT + 普通 RW」双区
    /// - arm64 在 mmap 后即装懒修复处理器并 np(0) 开写（macOS 27 语义）
    /// - setup 写入由调用方执行；执行前必须 sealForExecution()（icache +
    ///   np(1) 回保护态）
    /// - mmap 拒绝时已写诊断信息并返回 nil（调用方 exit(126)——环境门）
    struct ExecMap {
        let mapped: UnsafeMutableRawPointer
        /// __TEXT vmaddr（dylib=0；PIE 主程序=0x1_0000_0000）
        let base: UInt64
        /// 映射总跨度（top - base；blob = 文件长度）
        let mappedSize: Int
        /// arm64 拆分路径下 JIT（可执行）子区；nil = 单区布局
        let jitSpan: (addr: UInt, size: Int)?
        /// 有内容的段（__PAGEZERO 类空段已剔除）；空 = 裸 blob
        let segs: [(vmaddr: UInt64, vmsize: UInt64, fileoff: Int, filesize: UInt64, exec: Bool)]
        /// 头字节判定的镜像架构（anon mmap 零填充——必须读文件字节）
        let isARM64: Bool

        /// 镜像内 VA → 映射地址（越界 nil）。
        func ptr(_ vmaddr: UInt64) -> UnsafeMutableRawPointer? {
            guard vmaddr >= base else { return nil }
            let off = Int(vmaddr - base)
            return off >= 0 && off < mappedSize ? mapped + off : nil
        }

        /// setup 写入收尾：icache 失效（arm64 手写可执行内存的文档化契约）
        /// + np(1) 回保护态（np(0) 写态 RW 无 X，执行即 SIGBUS——27 实证）。
        func sealForExecution() {
            #if arch(arm64)
            sys_icache_invalidate(mapped, jitSpan?.size ?? mappedSize)
            pthread_jit_write_protect_np(1)
            #endif
        }
    }

    /// Map the whole thin image RWX. Image base = __TEXT vmaddr: dylibs
    /// link at 0 (VA == file offset) but PIE main executables link at
    /// 0x100000000 — every spec VA must be rebased by it.
    ///
    /// Segment-faithful mapping: some images (PIE executables) have
    /// fileoff != vmaddr - base for later segments; copy each segment to
    /// its vmaddr slot so every spec VA indexes uniformly. anon memory is
    /// zero-filled, covering __bss tails beyond filesize.
    ///
    /// arm64: plain RWX mmap is refused by AMFI on stock machines (exit
    /// 126), and the unsigned-executable-memory entitlement is restricted
    /// — ad-hoc signatures don't earn it (CI-verified 2026-09-21). MAP_JIT
    /// is the entitlement-free official route for non-hardened processes;
    /// writes are bracketed by the per-thread W^X toggle.
    static func execMap(data: Data) -> ExecMap? {
        let base = data.withUnsafeBytes { raw -> UInt64 in
            // bare synthetic blobs (test fixtures) carry no Mach-O header
            guard raw.count >= 32,
                  raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self) == 0xFEEDFACF else { return 0 }
            let ncmds = raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self)
            var p = 32
            var minVM = UInt64.max
            for _ in 0..<ncmds {
                guard p + 72 <= raw.count else { break }
                let cmd = raw.loadUnaligned(fromByteOffset: p, as: UInt32.self)
                let cmdsize = Int(raw.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self))
                guard cmdsize > 0 else { break }
                if cmd == 0x19 {
                    let vmaddr = raw.loadUnaligned(fromByteOffset: p + 24, as: UInt64.self)
                    let fileoff = raw.loadUnaligned(fromByteOffset: p + 40, as: UInt64.self)
                    // __TEXT is the fileoff==0 CONTENT segment (PAGEZERO also
                    // sits at fileoff 0 with filesize 0 — exclude by content);
                    // its vmaddr is the base (0 for dylibs, 0x1_0000_0000 for PIE)
                    let filesize = raw.loadUnaligned(fromByteOffset: p + 48, as: UInt64.self)
                    if filesize > 0, fileoff == 0 { minVM = min(minVM, vmaddr) }
                }
                p += cmdsize
            }
            return minVM == .max ? 0 : minVM
        }
        #if arch(arm64)
        let mapFlags = MAP_PRIVATE | MAP_ANON | MAP_JIT
        // 写入走 np(0) 开写 + 懒修复处理器兜底（sigaction 安装处）——
        // macOS 27 实测 np 开关/回调语义随版本漂移，处理器是最终兜底
        #else
        let mapFlags = MAP_PRIVATE | MAP_ANON
        #endif
        var mappedSize = 0
        // Phase A（只读）：解析段表 + mmap（不触碰 JIT 区内存）。
        // initprot 一并捕获——arm64 拆分映射按「EXEC 前缀段」划分代码区。
        let segs: [(vmaddr: UInt64, vmsize: UInt64, fileoff: Int, filesize: UInt64, exec: Bool)] = data.withUnsafeBytes { raw -> [(vmaddr: UInt64, vmsize: UInt64, fileoff: Int, filesize: UInt64, exec: Bool)] in
            var segs: [(vmaddr: UInt64, vmsize: UInt64, fileoff: Int, filesize: UInt64, exec: Bool)] = []
            var p = 32
            // 111 轮修：base 闭包有 ≥32 门而这里没有——<20B 输入直接读 ncmds
            // 越界 trap（worker 崩溃被误分类）。
            guard raw.count >= 32 else { return segs }
            for _ in 0..<raw.loadUnaligned(fromByteOffset: 16, as: UInt32.self) {
                guard p + 72 <= raw.count else { break }
                let cmd = raw.loadUnaligned(fromByteOffset: p, as: UInt32.self)
                let cmdsize = Int(raw.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self))
                guard cmdsize > 0 else { break }
                if cmd == 0x19 {
                    let fs = raw.loadUnaligned(fromByteOffset: p + 48, as: UInt64.self)
                    // 病态段表防 trap（135 轮体检 P3-3，L3⑤ 家族）：fileoff/fs
                    // 超 Int 表示域的强转、vmaddr+vmsize 溢出（下方 top 计算）
                    // 都是进程崩溃面——损坏输入按「该段不存在」收敛，worker
                    // 走 blob/映射失败路径干净退出而不是 trap 死。
                    // fileoff+fs ≤ 文件长（136 轮评审 P1）：截断镜像（头+命令区
                    // 完整、尾部数据缺失——下载中断/磁盘满的典型形态）此前
                    // 会进段拷贝，Phase-B 的 memcpy 只按 mappedSize（段表声明）
                    // 钳位不看文件实长 → 源侧越界读 SIGSEGV，被父进程误报成
                    // workerCrashed「函数摸了未建模状态」。（fileoff、fs 均已
                    // ≤Int.max，两者之和不会 UInt64 溢出。）
                    let vmaddr = raw.loadUnaligned(fromByteOffset: p + 24, as: UInt64.self)
                    let vmsize = raw.loadUnaligned(fromByteOffset: p + 32, as: UInt64.self)
                    let fileoff = raw.loadUnaligned(fromByteOffset: p + 40, as: UInt64.self)
                    if fs > 0, fs <= UInt64(Int.max), fileoff <= UInt64(Int.max),
                       fileoff + fs <= UInt64(raw.count),
                       vmaddr <= UInt64.max - vmsize {   // skip __PAGEZERO-style contentless segments
                        segs.append((vmaddr,
                                     vmsize,
                                     Int(fileoff),
                                     fs,
                                     raw.loadUnaligned(fromByteOffset: p + 60, as: UInt32.self) & 0x4 != 0))   // initprot EXEC
                    }
                }
                p += cmdsize
            }
            return segs
        }
        let mapped: UnsafeMutableRawPointer
        let totalCount: Int
        /// arm64 拆分路径下 JIT（可执行）子区；nil = 单区布局（x64 / blob /
        /// 非 EXEC 前缀的罕见镜像）。icache 与兜底处理器的范围都用它。
        var jitSpan: (addr: UInt, size: Int)?
        if segs.isEmpty {
            mappedSize = data.count
            totalCount = data.count
            mapped = mmap(nil, data.count, PROT_READ | PROT_WRITE | PROT_EXEC, mapFlags, -1, 0)
            guard mapped != UnsafeMutableRawPointer(bitPattern: -1) else {
                FileHandle.standardError.write(Data("wxkeep-verify: mmap MAP_JIT 失败 errno=\(errno)（\(String(cString: strerror(errno)))）\n".utf8))
                return nil
            }
        } else {
            let top = segs.filter { $0.vmaddr >= base }.map { $0.vmaddr + $0.vmsize }.max() ?? 0
            // 病态段表（top-base 超 Int 表示域）按不可映射拒绝，不做会 trap
            // 的 UInt64→Int 强转（L3⑤ 家族：损坏输入必须干净拒绝）。
            guard top >= base, top - base <= UInt64(Int.max) else { return nil }
            let total = Int(top - base)
            mappedSize = total
            totalCount = total
            #if arch(arm64)
            // macOS 27 拆分映射（2026-10-14 /tmp/jitsplit 最小复现实证）：
            // W^X 升级为执行级——JIT 页写态（np(0)）RW 无 X，执行首条指令即
            // SIGBUS；保护态（np(1)）可执行但写被硬件 TPRO 拦截，且对 JIT 页
            // 的 mprotect RW/RWX 全部 EACCES。代码与数据同区即死锁：探针执行
            // 要保护态，magic-static 懒初始化（__cxa_guard 首次进入要写守卫
            // 位）要写态。拆法：EXEC 前缀段（__TEXT 族，Mach-O 惯例从 base
            // 起）= MAP_JIT；其余段 = 普通 RW 匿名映射 MAP_FIXED 紧贴其后
            // （MAP_FIXED+MAP_JIT 组合本身 EINVAL，顺序只能 JIT 先行；大区
            // 紧邻撞上既有映射的概率可忽略，worker 又是可弃子进程）。守卫
            // 写 / GOT 重定向全落普通 RW 页，np(1) 后执行只落在 JIT 页——
            // 两个约束同时满足。非 EXEC 前缀的罕见布局回落单区（≤15 行为，
            // 27 上按 129 诊断退出，不劣于修复前）。
            var split: UnsafeMutableRawPointer?
            var span: (addr: UInt, size: Int)?
            if let first = segs.first, first.vmaddr == base, first.exec,
               let jitEnd = segs.prefix(while: { $0.exec }).last.map({ $0.vmaddr + $0.vmsize }),
               jitEnd > base, jitEnd <= top, let jitSize = Int(exactly: jitEnd - base), jitSize > 0 {
                let jit: UnsafeMutableRawPointer = mmap(nil, jitSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0)
                if jit != UnsafeMutableRawPointer(bitPattern: -1) {
                    if jitSize < total {
                        let rest: UnsafeMutableRawPointer = mmap(jit + jitSize, total - jitSize, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0)
                        if rest != UnsafeMutableRawPointer(bitPattern: -1) {
                            split = jit
                            span = (UInt(bitPattern: jit), jitSize)
                        }
                    } else {
                        split = jit
                        span = (UInt(bitPattern: jit), jitSize)
                    }
                }
            }
            if let jit = split {
                mapped = jit
                jitSpan = span
            } else {
                mapped = mmap(nil, total, PROT_READ | PROT_WRITE | PROT_EXEC, mapFlags, -1, 0)
                guard mapped != UnsafeMutableRawPointer(bitPattern: -1) else {
                    FileHandle.standardError.write(Data("wxkeep-verify: mmap MAP_JIT 失败 errno=\(errno)（\(String(cString: strerror(errno)))）\n".utf8))
                    return nil
                }
            }
            #else
            mapped = mmap(nil, total, PROT_READ | PROT_WRITE | PROT_EXEC, mapFlags, -1, 0)
            guard mapped != UnsafeMutableRawPointer(bitPattern: -1) else {
                FileHandle.standardError.write(Data("wxkeep-verify: mmap 失败 errno=\(errno)（\(String(cString: strerror(errno)))）\n".utf8))
                return nil
            }
            #endif
        }
        #if arch(arm64)
        // macOS 27 兜底处理器（文件头说明）：np 开关失效、回调 API 被移除——
        // 故障落在 JIT 区内即 mprotect 授 RWX 重试；mprotect 被拒则打印 errno。
        // macOS ≤15 np 正常，处理器永不触发。拆分路径下范围只覆盖 JIT 子区
        // （数据页已是普通 RW，落在那儿的 fault 属未建模状态，如实上报）。
        workerJITRegionAddr = jitSpan?.addr ?? UInt(bitPattern: mapped)
        workerJITRegionSize = jitSpan?.size ?? totalCount
        // 无分配纪律配套（136 轮评审 P2）：诊断缓冲/静态前缀是 lazy 全局，
        // 首次访问即初始化（会 malloc）——必须在处理器可触发的任何 fault
        // **之前**完成初始化，否则「处理器内首次触摸全局」本身就重入分配
        // 器。此处（sigaction 安装前、单线程、分配安全）逐个预热。
        _ = workerDiagBuf
        _ = workerDiagDeniedPrefix
        _ = workerDiagOutsidePrefix
        _ = workerDiagFaultMid
        _ = workerDiagRegionMid
        _ = workerDiagPlusMid
        _ = workerDiagSigMid
        _ = workerDiagOutsideMid
        _ = workerDiagTail
        var act = sigaction()
        act.__sigaction_u.__sa_sigaction = workerJITFaultHandler
        act.sa_flags = SA_SIGINFO
        sigemptyset(&act.sa_mask)
        sigaction(SIGBUS, &act, nil)
        sigaction(SIGSEGV, &act, nil)
        pthread_jit_write_protect_np(0)   // ≤15 通道；27 上为 no-op，兜底靠处理器
        #endif
        // 架构从【文件字节】判定（ anon mmap 零填充，读 mapped 恒得 0——
        // v0.2.9 回调式重构踩坑，本机 270100 实测复现）。
        let isARM64 = data.withUnsafeBytes { raw -> Bool in
            raw.count >= 8 &&
            raw.loadUnaligned(fromByteOffset: 0, as: UInt32.self) == 0xFEED_FACF &&
            raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self) == 0x0100_000C
        }
        return ExecMap(mapped: mapped, base: base, mappedSize: mappedSize,
                       jitSpan: jitSpan, segs: segs, isARM64: isARM64)
    }

    // MARK: - Worker side (runs in the forked copy of this executable)

    /// Entry for `wxkeep __verify-worker <dylib> <va> <stubs> <zeros> <probes>`.
    /// Prints `probe|<text>|<0|1>` lines and exits 0; crashes on bad state.
    static func workerMain(_ args: [String]) -> Never {
        // （136 轮评审 P3）worker 入口的两枚 signal() 处理器已删——它们在
        // 下方 execMap 安装 sigaction（SIGBUS/SIGSEGV 双注册）的瞬间即被
        // 覆盖，生效窗只剩参数解析几行（该窗内 fault 属 worker 自身 bug，
        // 父进程按 signalled 判读本就成立）；且 write 长度是含 CJK 字面量
        // 的手抄数（120/76 ≠ 实际 UTF-8 字节数）——真触发会打印截断/带尾
        // 垃圾的诊断。JIT 故障的权威捕获 = execMap 的 workerJITFaultHandler。
        guard args.count >= 5,
              let data = try? Data(contentsOf: URL(fileURLWithPath: args[0])),
              let va = UInt64(args[1], radix: 16),
              let stubs = try? JSONDecoder().decode([String: String].self, from: Data(args[2].utf8)),
              let zeros = try? JSONDecoder().decode([[String]].self, from: Data(args[3].utf8)),
              let probes = try? JSONDecoder().decode([[String]].self, from: Data(args[4].utf8))
        else { exit(2) }

        // Map the whole thin image RWX. 映射机械（段表解析 + arm64 MAP_JIT
        // 拆分 + W^X 态管理）已抽取为共享底座 execMap（parse-oracle worker
        // 同源复用）；mmap 拒绝时 execMap 已写诊断信息——126 语义不变。
        guard let map = execMap(data: data) else { exit(126) }
        let mapped = map.mapped
        let base = map.base
        let mappedSize = map.mappedSize
        let isARM64 = map.isARM64

        // Phase B（全部 JIT 区写入）：段拷贝 + magic-static 清零 + GOT 重定向。
        // arm64：np(0) 开写 + 懒修复处理器兜底（macOS 27）；x64 无 MAP_JIT 直写。
        // 架构从头【文件字节】判定，不从 mapped 读：anon mmap 是零填充，
        // 段拷贝发生前读 mapped 恒得 0 → isARM64 恒 false → arm64 镜像全部
        // 误走 x64 ff25 解码 exit(4)（v0.2.9 回调式重构把拷贝挪进闭包后，
        // 头读取留在了调用点之前——本机 270100 实测复现）。
        let performSetupWrites: () -> Void = {
            data.withUnsafeBytes { raw in
                if map.segs.isEmpty {
                    memcpy(mapped, raw.baseAddress, data.count)
                } else {
                    for seg in map.segs where seg.vmaddr >= base {
                        let dst = Int(seg.vmaddr - base)
                        let src = raw.baseAddress! + seg.fileoff
                        let n = min(Int(seg.filesize), mappedSize - dst)
                        if n > 0, dst >= 0 { memcpy(mapped + dst, src, n) }
                    }
                }
            }
            // Zero magic-static regions to their runtime-start state.
            // Bound-checked: a bad spec must fail with a clear exit code, not
            // corrupt memory adjacent to the mapping before crashing.
                for region in zeros {
                    guard region.count == 2, let vaHex = UInt64(region[0], radix: 16),
                          let len = Int(region[1]), len > 0,
                          vaHex >= base, vaHex - base <= UInt64(Int.max),
                          Int(vaHex - base) + len <= mappedSize else { exit(4) }
                    memset(mapped + Int(vaHex - base), 0, len)
                }
            // Redirect import stubs to native harness functions.
            // x64: PLT `ff 25 <rel32>` → slot = stubVA + 6 + disp32.
            // arm64: `adrp x16/ldr x16,[x16,#imm]/br x16` → slot = page + imm*8.
            // Mapped image header cputype decides (same mapping serves both).
            //
            // 适用范围门：spec 的 stub VA 必须在本镜像里解码为真桩（形态 +
            // 越界）。spec 绑定单一构建家族（270099 族）——拿去探老构建时 VA
            // 落在无关字节上：旧实现形态不符静默 continue → GOT 槽留
            // chained-fixup 原始值 → 调用即 SIGSEGV 且被父进程误判读成
            // 「函数摸了未建模状态」（269631 pristine x64 实测）；arm64 侧更
            // 被良性化降级成「请回报系统版本」。统一 exit(4) =
            // specNotApplicable：父进程优雅跳过行为验证（所有架构一致——
            // 补丁效果由 strict verify 字节级证明承担）。
            // 原生桩替身，经 RTLD_DEFAULT 全局搜索解析一次（dlopen(nil) 句柄
            // 只搜主镜像——macOS 27 实测搜不到 libsystem 符号）。懒可选：无
            // 桩 spec（workerCanExecute 探针）不依赖符号存在；解析失败 =
            // harness 环境问题（126），静默跳过会让槽位留原始值、调用即崩且
            // 被误判读成 crash。
            let resolver = UnsafeMutableRawPointer(bitPattern: -2)   // RTLD_DEFAULT
            let strlenFn = dlsym(resolver, "strlen")
            let memcmpFn = dlsym(resolver, "memcmp")
            for (stubHex, kind) in stubs {
                // 111 轮修（契约对齐）：坏 hex 的 stubVA 此前静默 continue——
                // 槽位留 chained-fixup 原始值，调用即崩且被父进程误判
                // workerCrashed；未知 kind 被静默当 strlen——语义错误的返回值
                // 产出假 mismatch。两者都是 spec 数据问题，按旁注契约 exit(4)。
                guard let stubVA = UInt64(stubHex, radix: 16) else {
                    FileHandle.standardError.write(Data(
                        "wxkeep-verify: spec 桩 VA 非法 hex（\(stubHex)）——specNotApplicable\n".utf8))
                    exit(4)
                }
                guard kind == "memcmp" || kind == "strlen" else {
                    FileHandle.standardError.write(Data(
                        "wxkeep-verify: spec 桩 kind 未知（\(kind)）——specNotApplicable\n".utf8))
                    exit(4)
                }
                let fn = kind == "memcmp" ? memcmpFn : strlenFn
                guard let fn else {
                    FileHandle.standardError.write(Data(
                        "wxkeep-verify: harness 无法解析 \(kind == "memcmp" ? "memcmp" : "strlen")（dlsym RTLD_DEFAULT）——导入桩无法重定向\n".utf8))
                    exit(126)
                }
                // 越界/形态不符的 spec 桩 = spec 不适用于此镜像，exit(4) 优雅
                // 跳过；不能落到越界读：映射外读是 SIGSEGV、stubVA < base 的
                // UInt64 减法下溢是 Int 转换 trap（SIGILL）——两者都会被退出
                // 码判读误报成「函数摸了未建模状态」，把 spec 数据问题甩锅给
                // 镜像（㊶ 同类）。
                // 差值上溢（136 轮评审 P2）：`va >= base` 只防下溢，diff 超
                // Int.max 的 Int() 强转是 SIGTRAP——下方同样先 `<= UInt64(Int.max)`
                // 再转（与 L513 顶界纪律一致），spec 数据问题干净落 exit(4)。
                guard stubVA >= base, stubVA - base <= UInt64(Int.max) else { exit(4) }
                let stub = UnsafeRawPointer(mapped + Int(stubVA - base))
                let slotOffset: Int
                if isARM64 {
                    guard Int(stubVA - base) + 12 <= mappedSize else { exit(4) }
                    // loadUnaligned（135 轮体检 P3-4）：spec 桩 VA 是外部数据，
                    // 奇数 VA 的 load(as:) 是未对齐 UB——x64 分支同位点早已
                    // 逐字节组装（对齐纪律一致）。
                    guard let s = ARM64.stubSlotOffset(
                        pcOffset: stubVA - base,
                        w0: stub.loadUnaligned(fromByteOffset: 0, as: UInt32.self),
                        w1: stub.loadUnaligned(fromByteOffset: 4, as: UInt32.self),
                        w2: stub.loadUnaligned(fromByteOffset: 8, as: UInt32.self)) else {
                        FileHandle.standardError.write(Data(
                            "wxkeep-verify: spec 桩 0x\(String(stubVA, radix: 16)) 不是 adrp x16/ldr x16/br x16 形态——verify spec 不适用于此镜像\n".utf8))
                        exit(4)
                    }
                    slotOffset = s
                } else {
                    // ff25 + rel32 共 6B——形态检查前先判界，防越界读
                    guard Int(stubVA - base) + 6 <= mappedSize else { exit(4) }
                    guard stub.load(as: UInt8.self) == 0xFF,
                          stub.load(fromByteOffset: 1, as: UInt8.self) == 0x25 else {
                        FileHandle.standardError.write(Data(
                            "wxkeep-verify: spec 桩 0x\(String(stubVA, radix: 16)) 不是 `ff 25 <rel32>` 形态——verify spec 不适用于此镜像\n".utf8))
                        exit(4)
                    }
                    // swift load() enforces alignment — assemble the unaligned rel32 byte-wise
                    var dispValue: UInt32 = 0
                    for i in 0..<4 {
                        dispValue |= UInt32(stub.load(fromByteOffset: 2 + i, as: UInt8.self)) << (8 * i)
                    }
                    let disp = Int32(bitPattern: dispValue)
                    slotOffset = Int(stubVA - base) + 6 + Int(disp)
                }
                guard slotOffset >= 0, slotOffset + 8 <= mappedSize,
                      UInt(bitPattern: mapped + slotOffset) % 8 == 0 else { exit(4) }
                (mapped + slotOffset).assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = fn
            }
        }
        performSetupWrites()
        // macOS 27 执行语义（2026-10-14 最小探针实证 /tmp/jittest 模式对比）：
        // MAP_JIT 页在写态（np(0) 后）= RW 无 X，执行首条指令即 SIGBUS；
        // np(1) 关写回保护态 = RX 可执行。旧判断「np 开关在 27 上 no-op」
        // 不成立——开关一直有效，是写态可执行性被收紧。icache 失效是
        // arm64 手写可执行内存的文档化契约，一并补上（范围只覆盖 JIT 子区）。
        map.sealForExecution()

        // WeChat SSO string ABI: pass 24 CONTIGUOUS bytes. Array's own
        // withUnsafeMutableBytes yields the element buffer — never &array
        // (that is the array header: pointer+count, not the data).
        // 差值上溢（136 轮评审 P2 同族）：入口 VA 是外部数据，超顶界时
        // Int() 强转 SIGTRAP——先夹 Int.max 再转，干净落 exit(3)。
        guard va >= base, va - base <= UInt64(Int.max),
              Int(va - base) < mappedSize else { exit(3) }
        // 返回类型必须 UInt8 而非 Bool：Bool 契约假设 callee 写 0/1，但裸
        // ret（3.x objc3x 位点，87 轮）不写 w0——垃圾寄存器值当 Bool 是
        // UB（实测打印出 84219152 之类的值，破坏 probe|text|0/1 行契约，
        // 父进程解析失败）。UInt8 + !=0 归一双架构 ABI 等价，4.x 谓词的
        // 0/1 语义不变。
        let fn: @convention(c) (UnsafeMutableRawPointer) -> UInt8 =
            unsafeBitCast(mapped + Int(va - base), to: (@convention(c) (UnsafeMutableRawPointer) -> UInt8).self)

        var out = ""
        for probe in probes {
            guard let text = probe.first else { continue }
            var r: Bool? = nil
            if isARM64 {
                // arm64 SSO：数据 @0、长度字节 @0x17（直接长度）
                if var storage = ARM64.ssoProbe(text) {
                    r = storage.withUnsafeMutableBytes { raw in fn(raw.baseAddress!) != 0 }
                }
            } else {
                // x64 SSO：size<<1 @byte0（LSB=long 旗），短串数据 @+1。
                // Short-SSO probes only (<23 bytes); long-string construction is
                // deliberately unsupported (no current spec needs it).
                let bytes = Array(text.utf8)
                if bytes.count < 23 {
                    var storage = [UInt8](repeating: 0, count: 24)
                    storage[0] = UInt8(bytes.count << 1)
                    for (i, byte) in bytes.enumerated() { storage[1 + i] = byte }
                    r = storage.withUnsafeMutableBytes { raw in fn(raw.baseAddress!) != 0 }
                }
            }
            // 构造失败的探针也占一行（skip）——行数与 spec 恒对齐
            out += "probe|\(text)|\(r.map { $0 ? "1" : "0" } ?? "skip")\n"
        }
        FileHandle.standardOutput.write(out.data(using: .utf8)!)
        exit(0)
    }


    // MARK: - Verdict

    /// 探针结果按文本对位（worker 恒出一行/探针后行数虽齐，但任何历史/外
    /// 来 worker 输出少行时，位置 zip 会把结果 N 对到期望 N+1——假阴/假阳
    /// 双风险；文本键 + 缺行/未执行显式跳过，比较永远在同名探针间进行）。
    private static func alignedExpectations(
        results: [ProbeResult], spec: VerifySpec
    ) -> [(result: ProbeResult, expected: Bool?)] {
        let byText = Dictionary(results.map { ($0.text, $0) }, uniquingKeysWith: { first, _ in first })
        return spec.probes.compactMap { probe in
            guard let text = probe.first else { return nil }
            guard let result = byText[text] else { return nil }
            return (result, probe.count > 1 ? probe[1] == "1" : nil)
        }
    }

    /// arm64 语义：被探针的是 parse 内 cbz 的**谓词输入**（非补丁位点本身——
    /// 补丁是 cbz 分支翻转，谓词行为 pristine/patched 恒同）。本验证证明
    /// 「家族完整性 + 谓词输入路径 + harness 自检」；补丁有效性由 strict
    /// verify 的字节级证明承担（分支字节 = patch 态即生效，无条件直达）。
    static func verdictPredicate(
        results: [ProbeResult], spec: VerifySpec
    ) -> VerifyError? {
        for (result, expected) in alignedExpectations(results: results, spec: spec) {
            if let expected, result.executed, result.returned != expected {
                return .mismatch(detail: "revokemsg predicate(\"\(result.text)\") = "
                    + "\(result.returned ? 1 : 0), expected \(expected ? 1 : 0) — "
                    + "image doesn't match the family ground truth this spec encodes")
            }
        }
        return nil
    }

    /// Compares probe results against the expected behavior for the given
    /// on-disk state (pristine expects the spec's expecteds; patched expects
    /// every probe to return the neutralized value).
    static func verdict(
        results: [ProbeResult], spec: VerifySpec, state: Patcher.Inspection.State
    ) -> VerifyError? {
        // 反向对位：执行了的探针文本必须在 spec 内——文本对位把「错位比较」
        // 消掉后，「结果集混入 spec 外文本」成了新可见信号（worker/spec 漂移），
        // 同样按 mismatch 报而非静默忽略。
        let specTexts = Set(spec.probes.compactMap(\.first))
        if let extra = results.first(where: { $0.executed && !specTexts.contains($0.text) }) {
            return .mismatch(detail: "probe result \"\(extra.text)\" is not in the spec's probe set — worker/spec drift")
        }
        switch state {
        case .pristine:
            for (result, expected) in alignedExpectations(results: results, spec: spec) {
                if let expected, result.executed, result.returned != expected {
                    return .mismatch(detail: "pristine image: isRevokemsg(\"\(result.text)\") = \(result.returned ? 1 : 0), expected \(expected ? 1 : 0)")
                }
            }
        case .patched, .ambiguous:   // ambiguous: bytes hold asm (normalized entry) → patched behavior
            for (result, expected) in alignedExpectations(results: results, spec: spec) {
                if expected == true, result.executed, result.returned {
                    return .mismatch(detail: "patched image still classifies \"\(result.text)\" as revokemsg — patch ineffective")
                }
            }
        case .unknown:
            return .mismatch(detail: "patch point holds unknown bytes — verify against pristine/patched expectations is undefined")
        }
        return nil
    }
}
