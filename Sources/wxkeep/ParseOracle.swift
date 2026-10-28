import Foundation

/// L7 合成 parse oracle（V4-REQUIREMENTS §3，77 续㉜ 立项）：
/// 在进程外用迷你加载器调用**真实 parse 函数**（270100 arm64 @0x4bc4d34，
/// `parse(x0=msg struct, x1=变体串 XML, x2=ok*)`——drive25 调试器地面真值），
/// 以实弹捕获（var/wxarm/d*_parse_*.xml，gitignored 本机资产）为语料，
/// 观测输出 struct：
///   - newmsgid：u64 @struct+0x1C8（0x4bc5744 `str x0,[x19,#0x1c8]`，
///     0x4a7d960 数值提取后——唯一数值键/删除查找键 svrid）
///   - replacemsg：24B 变体串 @struct+0x1D0（0x4bc57dc `str q0,[x19,#0x1d0]`；
///     arm64 变体布局：长串 ptr@[0]/size@+8/cap|flag@+0x10，flag=[0x17] 符号负）
///   - ok：x2 指向字节，成功路径置 1；返回值 x0∈{0,1}
/// ⚠️ L7 第二轮实证：上两位点所在的嵌套提取块（0x4bc4fa8-0x4bc5604，
/// find `<revokemsg>` 子节点→newmsgid/replacemsg）在 270100 arm64 是
/// **零前驱死代码**（全镜像分支扫描）；0x4bc4d34 对嵌套语料的活路径只
/// 提取 type 属性（+0x1a8）与 sysmsg 直下子级。断言面待迁嵌套解析器
/// 0x4bd26a8（find "revokemsg" 子节点的活代码，引用索引实证）。
/// 断言矩阵（他人/自发 × 群/私）与变异负控在 ParseOracleTests——本文件只做
/// 机械：映射、宿主面构造、语料喂入、观测输出。
///
/// 与 __verify-worker 的关键差别：
/// - 谓词探针只需重定向 spec 列出的 2 个桩；parse 直接调 libc++
///   assign/copy-assign/operator delete，且内部分配器/字符串助手的传递
///   闭包会触达更多导入——**全桩重定向**：遍历镜像 __stubs（间接符号表
///   对名），dlsym 解析一个打一个，未解析的指向诊断陷阱（命中 exit(150)）。
/// - 栈哨兵 GOT（prologue `adrp;ldr x8,[x8,#imm];ldr x8,[x8]` 双重间接）
///   指向 worker 自备 canary——不依赖宿主 __stack_chk_guard 在位。
/// - 懒池在 __DATA bss（vmsize>filesize 尾区，如 0xa2ed000 池群），anon
///   映射零填充即运行时初始态，函数自跑懒初始化——无需 zero_regions。
///
/// 语料为 CI 不在场资产（空过，同 HotReloadTests 模式）；绑定 270100
/// arm64 家族（struct 偏移随家族，类比 verify spec 的家族绑定）。
enum ParseOracle {

    /// parse 输出 struct 的已知布局（270100 arm64 反汇编实证，77 续⑰键集全图）。
    enum Struct {
        static let newmsgidOffset = 0x1C8   // u64：唯一数值键
        static let replacemsgOffset = 0x1D0 // 24B 变体串：撤回提示原文
        static let size = 0x400             // 最大已知字段 +0x310+24；富余
    }

    struct RunOutcome: Equatable {
        let file: String      // 语料文件名（basename）
        let mode: String      // orig | zero | zmsgid
        let ret: UInt64       // parse 返回（0/1）
        let ok: UInt8         // x2 指向的 ok 字节
        let newmsgid: UInt64  // struct+0x1C8
        let replacemsg: Data  // struct+0x1D0 内容（变体串短/长两形态）
    }

    enum OracleError: Error, CustomStringConvertible {
        case archMismatch(image: String, host: String)
        case environmentBlocked(String)
        case workerCrashed(signal: Int32)
        case badWorkerOutput(String)
        case unresolvedImportHit(String)
        case emptyCorpus(String)

        var description: String {
            switch self {
            case .archMismatch(let image, let host):
                "parse oracle needs a thin arm64 image on an arm64 host (image=\(image), host=\(host))"
            case .environmentBlocked(let detail):
                "environment blocked the parse-oracle worker: \(detail)"
            case .workerCrashed(let sig):
                "parse-oracle worker crashed (signal \(sig)) — parse touched state we didn't model"
            case .badWorkerOutput(let detail):
                "parse-oracle worker emitted unparsable output: \(detail)"
            case .unresolvedImportHit(let detail):
                "parse hit an import the host could not resolve: \(detail)"
            case .emptyCorpus(let dir):
                "corpus directory has no *.xml files: \(dir)"
            }
        }
    }

    // MARK: - Parent side

    /// 一次性跑完语料目录（每个文件 × orig/zero/zmsgid 三模式），进程外执行
    /// （worker 崩溃只死子进程）。输出行：`run|<file>|<mode>|ret=|ok=|newmsgid=|rep=<hex>`。
    static func run(binary: URL, parseVA: UInt64, corpusDir: URL,
                    executable: URL? = nil) throws -> [RunOutcome] {
        guard Verifier.ImageArch.host == .arm64 else {
            throw OracleError.archMismatch(image: "any", host: "x86_64")
        }
        let head = (try? Data(contentsOf: binary, options: .alwaysMapped).prefix(8)) ?? Data()
        guard head.count >= 8,
              UInt32(head[4]) | UInt32(head[5]) << 8 | UInt32(head[6]) << 16 | UInt32(head[7]) << 24
              == 0x0100_000C else {
            throw OracleError.archMismatch(image: "not thin arm64", host: "arm64")
        }
        let exe = executable ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let result = Shell.run(exe.path, [
            "__parse-oracle-worker", binary.path, String(parseVA, radix: 16), corpusDir.path,
        ])
        if result.signalled {
            // 129 = worker 捕获 SIGBUS/SIGSEGV 后的干净退出诊断（裸信号不进这里）
            if result.status == SIGKILL { throw OracleError.environmentBlocked(result.stderr) }
            throw OracleError.workerCrashed(signal: result.status)
        }
        switch result.status {
        case 0: break
        case 126, 129: throw OracleError.environmentBlocked(result.stderr)
        case 150: throw OracleError.unresolvedImportHit(result.stderr)
        case 2, 3, 5: throw OracleError.badWorkerOutput("worker rejected arguments/env: \(result.stderr)")
        default: throw OracleError.workerCrashed(signal: result.status)
        }
        var outcomes: [RunOutcome] = []
        for line in result.stdout.split(separator: "\n") {
            guard line.hasPrefix("run|") else { continue }   // stubs|… 头行跳过
            // run|<file>|<mode>|ret=<n>|ok=<n>|newmsgid=<n>|rep=<hex>
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard parts.count == 7, parts[0] == "run",
                  let ret = UInt64(parts[3].dropFirst(4)),
                  let ok = UInt8(parts[4].dropFirst(3)),
                  let newmsgid = UInt64(parts[5].dropFirst(9)) else {
                throw OracleError.badWorkerOutput(String(line))
            }
            let hex = String(parts[6].dropFirst(4))
            let rep = Data(stride(from: 0, to: hex.count - 1, by: 2).compactMap {
                UInt8(hex[hex.index(hex.startIndex, offsetBy: $0)...hex.index(hex.startIndex, offsetBy: $0 + 1)], radix: 16)
            })
            outcomes.append(RunOutcome(file: String(parts[1]), mode: String(parts[2]),
                                       ret: ret, ok: ok, newmsgid: newmsgid, replacemsg: rep))
        }
        if outcomes.isEmpty { throw OracleError.emptyCorpus(corpusDir.path) }
        return outcomes
    }

    // MARK: - Worker side (runs in the forked copy of this executable)

    /// 未解析导入的陷阱：parse 触达宿主给不出的符号时，干净退出留名
    /// （150），而不是跳进 chained-fixup 原始值的 SIGSEGV。
    private static var unresolvedTrapPtr: UnsafeMutableRawPointer {
        let fn: @convention(c) () -> Void = parseOracleUnresolvedTrap
        return unsafeBitCast(fn, to: UnsafeMutableRawPointer.self)
    }

    /// 栈哨兵值。GOT 槽存的是 canary 的**地址**（消费代码双重装载
    /// `ldr x8,[slot]; ldr x8,[x8]`）；序言/尾章两次装载同一地址即自洽，
    /// 与宿主 __stack_chk_guard 符号无关。固定地址取自首元素指针。
    nonisolated(unsafe) static var canaryStorage: [UInt64] = [0x9E37_79B9_7F4A_7C15]
    private static var canaryAddress: UInt {
        canaryStorage.withUnsafeMutableBytes { UInt(bitPattern: $0.baseAddress!) }
    }

    /// Entry for `wxkeep __parse-oracle-worker <dylib> <parseVA-hex> <corpusDir>`。
    /// 输出 `stubs|resolved=<n>|unresolved=<m>` 首行 + 每语料×模式一行
    /// `run|...`，exit 0；退出码语义见 OracleError。
    static func workerMain(_ args: [String]) -> Never {
        #if arch(arm64)
        guard args.count >= 3,
              let data = try? Data(contentsOf: URL(fileURLWithPath: args[0])),
              let parseVA = UInt64(args[1], radix: 16) else { exit(2) }
        guard let map = Verifier.execMap(data: data) else { exit(126) }
        guard map.isARM64, let parse = map.ptr(parseVA) else { exit(3) }
        // execMap 装的是 setup 写态兜底处理器（JIT 区懒修复）；执行期故障
        // 需要 pc 诊断，setup 完成后覆盖 SEGV（SIGBUS 保留懒修复路径）。
        let segvHandler: @convention(c) (Int32, UnsafeMutablePointer<siginfo_t>?, UnsafeMutableRawPointer?) -> Void = { _, info, ctx in
            var pc: UInt = 0
            if let ctx, let mctx = ctx.assumingMemoryBound(to: ucontext_t.self).pointee.uc_mcontext {
                pc = UInt(mctx.pointee.__ss.__pc)
            }
            let line = "parse-oracle: SIGSEGV addr=\(hex(UInt(bitPattern: info?.pointee.si_addr))) pc=\(hex(pc))\n"
            _ = write(2, line, line.utf8.count)
            _exit(129)
        }
        var act = sigaction()
        act.__sigaction_u.__sa_sigaction = segvHandler
        act.sa_flags = SA_SIGINFO
        sigemptyset(&act.sa_mask)
        sigaction(SIGSEGV, &act, nil)

        // —— setup（JIT 区写态）：段拷贝 → chained fixups → 全桩重定向 → 哨兵槽 ——
        var resolved = 0, unresolved = 0
        copySegments(data: data, map: map)
        var fixupsApplied = 0
        if map.segs.isEmpty == false { fixupsApplied = applyChainedFixups(data: data, map: map) }
        redirectAllStubs(data: data, map: map, resolved: &resolved, unresolved: &unresolved)
        patchStackGuardSlot(map: map, fnVA: parseVA)
        // 0x9f6fe78（运行时等级，文件值 6）不需要模拟：全语料 A/B（写 0 vs
        // 保持 6）输出逐字节一致——0x5ca448c(4)/(3) 两处门只守"decode fail"
        // 日志路径，不影响提取语义（L7 第二轮实证）。
        // 调试面：patchsite <va-hex> 把 4B 指令换成 NOP（写态内、seal 前）
        if args.count >= 5, args[3] == "patchsite", let siteVA = UInt64(args[4], radix: 16),
           let site = map.ptr(siteVA) {
            site.assumingMemoryBound(to: UInt32.self).pointee = 0xD503_201F
            FileHandle.standardError.write(Data("parse-oracle: NOPped 0x\(String(siteVA, radix: 16))\n".utf8))
        }
        map.sealForExecution()
        wxkeep_oracle_marker(UInt(bitPattern: map.mapped))   // lldb 排障锚（见 Tests 排障文档）

        FileHandle.standardError.write(Data("parse-oracle: fixups=\(fixupsApplied) stubs=\(resolved)+\(unresolved)\n".utf8))
        // probe 模式（排障）：按 parse 前奏手工调 0x55a7c1c(对象构造) +
        // 0x4a7d6ac(变体串→树对象) + 0x55a3974/0x499c33c(找节点/在位门)。
        if args.count >= 4, args[3] == "countnew", let slot = map.ptr(0x9f6b6a0),
           let realNew = map.ptr(0x55aaa38) {
            oracleNewCount = 0
            oracleRealNew = realNew
            let tramp: @convention(c) (UInt) -> UnsafeMutableRawPointer? = { size in
                oracleNewCount += 1
                let fn: @convention(c) (UInt) -> UnsafeMutableRawPointer? =
                    unsafeBitCast(oracleRealNew, to: (@convention(c) (UInt) -> UnsafeMutableRawPointer?).self)
                return fn(size)
            }
            slot.assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee =
                unsafeBitCast(tramp, to: UnsafeMutableRawPointer.self)
            let files = ((try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: args[2]), includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension == "xml" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            for file in files.prefix(3) {
                guard let xml = try? Data(contentsOf: file) else { continue }
                let buf = malloc(xml.count + 1)!
                xml.copyBytes(to: buf.assumingMemoryBound(to: UInt8.self), count: xml.count)
                (buf + xml.count).assumingMemoryBound(to: UInt8.self).pointee = 0
                var vstr = [UInt8](repeating: 0, count: 24)
                vstr.replaceSubrange(0..<8, with: withUnsafeBytes(of: UInt(bitPattern: buf)) { Array($0) })
                vstr.replaceSubrange(8..<16, with: withUnsafeBytes(of: UInt64(xml.count)) { Array($0) })
                vstr.replaceSubrange(16..<24, with: withUnsafeBytes(of: UInt64(xml.count) | 1 << 63) { Array($0) })
                let obj = calloc(1, 0xC0)!
                let ctorFn: @convention(c) (UnsafeMutableRawPointer) -> Void =
                    unsafeBitCast(map.ptr(0x55a7c1c)!, to: (@convention(c) (UnsafeMutableRawPointer) -> Void).self)
                let convFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64 =
                    unsafeBitCast(map.ptr(0x4a7d6ac)!, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64).self)
                let before = oracleNewCount
                vstr.withUnsafeMutableBytes { raw in
                    ctorFn(obj)
                    _ = convFn(raw.baseAddress!, obj)
                }
                FileHandle.standardError.write(Data("countnew \(file.lastPathComponent): allocs=\(oracleNewCount - before)\n".utf8))
            }
        }
        // walktree：按 pugixml 布局走查树（doc 解引用 [tree+0]；子链 +0x20/
        // 兄弟链 +0x30；名字 ptr@[node+8] C 串）——地面真值，不经 0x55a3974。
        if args.count >= 4, args[3] == "walktree",
           let ctor = map.ptr(0x55a7c1c), let conv = map.ptr(0x4a7d6ac) {
            let files = ((try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: args[2]), includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension == "xml" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            let ctorFn: @convention(c) (UnsafeMutableRawPointer) -> Void =
                unsafeBitCast(ctor, to: (@convention(c) (UnsafeMutableRawPointer) -> Void).self)
            let convFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64 =
                unsafeBitCast(conv, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64).self)
            func cstrAt(_ p: UnsafeMutableRawPointer, _ off: Int) -> String {
                var ptr = p.load(fromByteOffset: off, as: UInt64.self)
                guard ptr > 0x10000 else { return "" }
                let cp = UnsafeMutableRawPointer(bitPattern: UInt(ptr))!
                var out = [UInt8](); var i = 0
                while i < 64 { let b = cp.load(fromByteOffset: i, as: UInt8.self); if b == 0 { break }; out.append(b); i += 1 }
                return String(bytes: out, encoding: .utf8) ?? "?"
            }
            func walk(_ node: UnsafeMutableRawPointer, _ depth: Int, _ out: inout String) {
                var child = node.load(fromByteOffset: 0x20, as: UInt64.self)
                var seen = 0
                while child > 0x10000, seen < 12 {
                    let c = UnsafeMutableRawPointer(bitPattern: UInt(child))!
                    out += String(repeating: " ", count: depth * 2) + "<" + cstrAt(c, 8)
                    let value = cstrAt(c, 0x10)
                    if !value.isEmpty { out += "=" + value }
                    out += "\n"
                    walk(c, depth + 1, &out)
                    child = c.load(fromByteOffset: 0x30, as: UInt64.self)
                    seen += 1
                }
            }
            for file in files.prefix(2) {
                guard let xml = try? Data(contentsOf: file) else { continue }
                let buf = malloc(xml.count + 1)!
                xml.copyBytes(to: buf.assumingMemoryBound(to: UInt8.self), count: xml.count)
                (buf + xml.count).assumingMemoryBound(to: UInt8.self).pointee = 0
                var vstr = [UInt8](repeating: 0, count: 24)
                vstr.replaceSubrange(0..<8, with: withUnsafeBytes(of: UInt(bitPattern: buf)) { Array($0) })
                vstr.replaceSubrange(8..<16, with: withUnsafeBytes(of: UInt64(xml.count)) { Array($0) })
                vstr.replaceSubrange(16..<24, with: withUnsafeBytes(of: UInt64(xml.count) | 1 << 63) { Array($0) })
                let obj = calloc(1, 0xC0)!
                var tree = ""
                vstr.withUnsafeMutableBytes { raw in
                    ctorFn(obj)
                    _ = convFn(raw.baseAddress!, obj)
                    let impl = obj.load(fromByteOffset: 0, as: UInt64.self)
                    if let doc = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: impl)), impl > 0x10000 {
                        walk(doc, 0, &tree)
                    } else { tree = "(no impl)" }
                }
                FileHandle.standardError.write(Data("walktree \(file.lastPathComponent):\n\(tree)\n".utf8))
            }
        }
        // probe2（排障）：sysmsg 层 find 逐键实探——名字回读 + 匹配节点身份
        if args.count >= 4, args[3] == "probe2",
           let ctor = map.ptr(0x55a7c1c), let conv = map.ptr(0x4a7d6ac), let find = map.ptr(0x55a3974) {
            let files = ((try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: args[2]), includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension == "xml" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            let ctorFn: @convention(c) (UnsafeMutableRawPointer) -> Void =
                unsafeBitCast(ctor, to: (@convention(c) (UnsafeMutableRawPointer) -> Void).self)
            let convFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64 =
                unsafeBitCast(conv, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64).self)
            let findFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutablePointer<CChar>) -> UnsafeMutableRawPointer? =
                unsafeBitCast(find, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutablePointer<CChar>) -> UnsafeMutableRawPointer?).self)
            func cstrAt(_ p: UnsafeMutableRawPointer, _ off: Int) -> String {
                let ptr = p.load(fromByteOffset: off, as: UInt64.self)
                guard ptr > 0x10000 else { return "" }
                let cp = UnsafeMutableRawPointer(bitPattern: UInt(ptr))!
                var out = [UInt8](); var i = 0
                while i < 64 { let b = cp.load(fromByteOffset: i, as: UInt8.self); if b == 0 { break }; out.append(b); i += 1 }
                return String(bytes: out, encoding: .utf8) ?? "?"
            }
            for file in files.prefix(2) {
                guard let xml = try? Data(contentsOf: file) else { continue }
                let buf = malloc(xml.count + 1)!
                xml.copyBytes(to: buf.assumingMemoryBound(to: UInt8.self), count: xml.count)
                (buf + xml.count).assumingMemoryBound(to: UInt8.self).pointee = 0
                var vstr = [UInt8](repeating: 0, count: 24)
                vstr.replaceSubrange(0..<8, with: withUnsafeBytes(of: UInt(bitPattern: buf)) { Array($0) })
                vstr.replaceSubrange(8..<16, with: withUnsafeBytes(of: UInt64(xml.count)) { Array($0) })
                vstr.replaceSubrange(16..<24, with: withUnsafeBytes(of: UInt64(xml.count) | 1 << 63) { Array($0) })
                let obj = calloc(1, 0xC0)!
                var line = "probe2 \(file.lastPathComponent):"
                vstr.withUnsafeMutableBytes { raw in
                    ctorFn(obj)
                    _ = convFn(raw.baseAddress!, obj)
                    line += " treeName=\(cstrAt(obj, 0x10).isEmpty ? "(none)" : "?")"
                    var sysSlot = UnsafeMutableRawPointer(bitPattern: 0)
                    "sysmsg".withCString { ks in
                        if let n = findFn(obj, UnsafeMutablePointer(mutating: ks)) { sysSlot = n }
                    }
                    line += " sysPtr=\(UInt(bitPattern: sysSlot))"
                    if let sys = sysSlot, UInt(bitPattern: sys) > 0x10000 {
                        line += " sysName=<\(cstrAt(sys, 8))>"
                        var holder = sys
                        for key in ["subtype", "revokemsg", "replacemsg", "newmsgid", "content", "session"] {
                            let hit: String = key.withCString { ks in
                                guard let n = findFn(&holder, UnsafeMutablePointer(mutating: ks)) else { return "-" }
                                return "<\(cstrAt(n, 8))>@\(String(UInt(bitPattern: n), radix: 16))"
                            }
                            line += " \(key)=\(hit)"
                        }
                    }
                }
                FileHandle.standardError.write(Data((line + "\n").utf8))
            }
        }
        if args.count >= 4, args[3] == "probe1",
           let ctor = map.ptr(0x55a7c1c), let conv = map.ptr(0x4a7d6ac), let find = map.ptr(0x55a3974),
           let present = map.ptr(0x499c33c) {
            let presentFn: @convention(c) (UnsafeMutableRawPointer) -> Int32 =
                unsafeBitCast(present, to: (@convention(c) (UnsafeMutableRawPointer) -> Int32).self)
            let files = ((try? FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: args[2]), includingPropertiesForKeys: nil)) ?? [])
                .filter { $0.pathExtension == "xml" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
            for file in files.prefix(3) {
                guard let xml = try? Data(contentsOf: file) else { continue }
                let buf = malloc(xml.count + 1)!
                xml.copyBytes(to: buf.assumingMemoryBound(to: UInt8.self), count: xml.count)
                (buf + xml.count).assumingMemoryBound(to: UInt8.self).pointee = 0
                var vstr = [UInt8](repeating: 0, count: 24)
                vstr.replaceSubrange(0..<8, with: withUnsafeBytes(of: UInt(bitPattern: buf)) { Array($0) })
                vstr.replaceSubrange(8..<16, with: withUnsafeBytes(of: UInt64(xml.count)) { Array($0) })
                vstr.replaceSubrange(16..<24, with: withUnsafeBytes(of: UInt64(xml.count) | 1 << 63) { Array($0) })
                let obj = calloc(1, 0xC0)!   // 0x55a7d68 写到 +0x88——0x40 是 probe1 踩堆的原因
                let ctorFn: @convention(c) (UnsafeMutableRawPointer) -> Void =
                    unsafeBitCast(ctor, to: (@convention(c) (UnsafeMutableRawPointer) -> Void).self)
                let convFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64 =
                    unsafeBitCast(conv, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer) -> UInt64).self)
                let findFn: @convention(c) (UnsafeMutableRawPointer, UnsafeMutablePointer<CChar>) -> UnsafeMutableRawPointer? =
                    unsafeBitCast(find, to: (@convention(c) (UnsafeMutableRawPointer, UnsafeMutablePointer<CChar>) -> UnsafeMutableRawPointer?).self)
                vstr.withUnsafeMutableBytes { raw in
                    ctorFn(obj)
                    let w0 = convFn(raw.baseAddress!, obj)
                    var line = "probe1 \(file.lastPathComponent): conv_ret=\(w0 & 1)"
                    do { var d = [UInt8](); for i in 0..<0xC0 { d.append(obj.load(fromByteOffset: i, as: UInt8.self)) }
                         line += " obj=" + d.map { String(format: "%02x", $0) }.joined().prefix(96)
                         let p10 = obj.load(fromByteOffset: 0x10, as: UInt64.self)
                         if let p = UnsafeRawPointer(bitPattern: UInt(truncatingIfNeeded: p10)), p10 > 0x10000 {
                             var t = [UInt8](); for i in 0..<64 { t.append(p.load(fromByteOffset: i, as: UInt8.self)) }
                             let printable = t.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." }
                             line += " p10=" + String(printable) } }
                    for key in ["sysmsg", "revokemsg", "newmsgid", "replacemsg", "content", "a", "b", "inner"] {
                        line += " " + key.withCString { ks -> String in
                            guard let n = findFn(obj, UnsafeMutablePointer(mutating: ks)) else { return "-" }
                            var holder = n
                            let pv = withUnsafeMutableBytes(of: &holder) { presentFn($0.baseAddress!) }
                            return pv != 0 ? "Y(p=\(pv))" : "N0"
                        }
                    }
                    // 两级：sysmsg 节点的子级（parse 的真正查找面）
                    if let sys = findFn(obj, UnsafeMutablePointer(mutating: "sysmsg")), sys != obj {
                        var sysSlot = sys
                        line += " ||children-of-sysmsg:"
                        for key in ["revokemsg", "newmsgid", "replacemsg", "session", "content"] {
                            line += " " + key.withCString { ks -> String in
                                let n = withUnsafeMutableBytes(of: &sysSlot) { findFn($0.baseAddress!, UnsafeMutablePointer(mutating: ks)) }
                                return n != nil ? "Y" : "-"
                            }
                        }
                    }
                    FileHandle.standardError.write(Data((line + "\n").utf8))
                }
            }
        }
        var out = "stubs|resolved=\(resolved)|unresolved=\(unresolved)|fixups=\(fixupsApplied)\n"
        let files = ((try? FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: args[2]), includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "xml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        guard !files.isEmpty else {
            FileHandle.standardError.write(Data("parse-oracle: corpus dir empty: \(args[2])\n".utf8))
            exit(5)
        }
        for file in files {
            guard let xml = try? Data(contentsOf: file) else { continue }
            for mode in ["orig", "zero", "zmsgid"] {
                var bytes = xml
                if mode == "zero" { zeroTagDigits(&bytes, tag: "<newmsgid>") }
                if mode == "zmsgid" { zeroTagDigits(&bytes, tag: "<msgid>") }
                out += runOnce(parse: parse, file: file.lastPathComponent, mode: mode, xml: bytes)
            }
        }
        // 分派比较器键池（0xa2b1ad8 起，懒初始化后可读）——语料跑完后 dump
        do {
            var dump = ""
            if let poolBase = map.ptr(0xa2b1ad8) {
                for row in 0..<10 {
                    var line = ""
                    for col in 0..<16 {
                        let b = poolBase.load(fromByteOffset: row * 16 + col, as: UInt8.self)
                        line += (32...126).contains(b) ? String(UnicodeScalar(b)) : (b == 0 ? "·" : "?")
                    }
                    dump += "0x\(String(0xa2b1ad8 + row * 16, radix: 16)): \(line)\n"
                }
            }
            FileHandle.standardError.write(Data(("pool:\n" + dump).utf8))
        }
        FileHandle.standardOutput.write(out.data(using: .utf8)!)
        exit(0)
        #else
        FileHandle.standardError.write(Data("parse-oracle: arm64-only worker\n".utf8))
        exit(2)
        #endif
    }

    #if arch(arm64)
    /// 单次 parse 调用：零初始化 struct（libc++ 串零=合法空串；变体串
    /// flag@+0x17=0=短串安全——两层构造面都不需要显式构造器）+ 变体串
    /// 输入 + ok 字节。观测返回值/ok/newmsgid/replacemsg。
    ///
    /// 输出串的堆缓冲**故意不释放**：libc++ 串两代布局的判长位不同，按
    /// 猜测 free 错指针比泄漏危险得多；worker 是可弃子进程，exit 收官。
    private static func runOnce(parse: UnsafeMutableRawPointer, file: String,
                                mode: String, xml: Data) -> String {
        typealias ParseFn = @convention(c) (UnsafeMutableRawPointer, UnsafeMutableRawPointer,
                                            UnsafeMutableRawPointer) -> UInt64
        let fn = unsafeBitCast(parse, to: ParseFn.self)
        // 变体串（arm64）：ptr@0 / size@+8 / cap|flag@+0x10（bit63 = 长串旗）。
        // NUL 结尾兜底：0x4a7d6ac 找 't' 的字符扫描可能不按 size 截断。
        let buf = malloc(xml.count + 1)!
        xml.copyBytes(to: buf.assumingMemoryBound(to: UInt8.self), count: xml.count)
        (buf + xml.count).assumingMemoryBound(to: UInt8.self).pointee = 0
        var vstr = [UInt8](repeating: 0, count: 24)
        vstr.replaceSubrange(0..<8, with: withUnsafeBytes(of: UInt(bitPattern: buf)) { Array($0) })
        vstr.replaceSubrange(8..<16, with: withUnsafeBytes(of: UInt64(xml.count)) { Array($0) })
        vstr.replaceSubrange(16..<24, with: withUnsafeBytes(of: UInt64(xml.count) | 1 << 63) { Array($0) })

        let msg = calloc(1, Struct.size)!
        // 调用方契约（77 续㉞ 实证）：+0x1c4 subtype 必须预填 1（消息已被
        // 上游路由为 revokemsg——parse 的 0x216e90 门 = (subtype==1)）。
        // 零值=未分类 → parse 走特殊类型字符串链（qy_revoke_msg/sysmsgtemplate
        // /revokehistoryinjoinroommsg/mmchatroomtopmsg/SendMsgFailed/
        // delchatroommember/paymsg——运行时键池 dump 全量实证，无 revokemsg
        // 本尊）→ 全 miss → 兜底路径 exit 0。
        msg.assumingMemoryBound(to: UInt32.self).advanced(by: 0x1c4 / 4).pointee = 1
        let okPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        okPtr.pointee = 0
        defer { free(buf); free(msg); okPtr.deallocate() }

        let ret = vstr.withUnsafeMutableBytes { raw -> UInt64 in
            fn(msg, raw.baseAddress!, UnsafeMutableRawPointer(okPtr))
        }
        let newmsgid = msg.assumingMemoryBound(to: UInt64.self).advanced(by: Struct.newmsgidOffset / 8).pointee
        let rep = readVariantString(msg, base: Struct.replacemsgOffset)
        if getenv("WXORACLE_DEBUG") != nil {
            // +0x1a8 = libc++ string 原始 24B dump（布局新旧不明，直接看字节）
            var raw = [UInt8]()
            for i in 0..<24 { raw.append(msg.load(fromByteOffset: 0x1a8 + i, as: UInt8.self)) }
            let hx = raw.map { String(format: "%02x", $0) }.joined(separator: " ")
            FileHandle.standardError.write(Data("oracle: +0x1a8 raw=\(hx)\n".utf8))
            FileHandle.standardError.write(Data("oracle: +0x1c4 subtype=\(msg.load(fromByteOffset: 0x1c4, as: UInt32.self))\n".utf8))
            // 变体串字段群（arm 落点巡检）：+0x1e8/+0x218/+0x230/+0x2c8/+0x2e0/+0x310
            for off in [0x1e8, 0x218, 0x230, 0x288, 0x2c8, 0x2e0, 0x310] {
                var s = ""
                if off == 0x288 {
                    s = String(msg.load(fromByteOffset: off, as: UInt32.self))
                } else {
                    let flag = Int8(bitPattern: msg.load(fromByteOffset: off + 0x17, as: UInt8.self))
                    if flag < 0 {
                        let ptr = msg.load(fromByteOffset: off, as: UInt64.self)
                        let size = msg.load(fromByteOffset: off + 8, as: UInt64.self)
                        if ptr > 0x10000, size <= 1 << 14, let p = UnsafeRawPointer(bitPattern: UInt(truncatingIfNeeded: ptr)) {
                            s = String(data: Data(bytes: p, count: Int(size)), encoding: .utf8) ?? "<bin>"
                        } else { s = "<ptr?>" }
                    } else {
                        let len = Int(msg.load(fromByteOffset: off + 0x17, as: UInt8.self))
                        if len > 0, len < 24 {
                            var b = [UInt8](); for i in 0..<len { b.append(msg.load(fromByteOffset: off + i, as: UInt8.self)) }
                            s = String(bytes: b, encoding: .utf8) ?? "<bin>"
                        }
                    }
                }
                if !s.isEmpty { FileHandle.standardError.write(Data("oracle: +0x\(String(off, radix: 16)) = \(s)\n".utf8)) }
            }
        }
        let hex = rep.map { String(format: "%02x", $0) }.joined()
        return "run|\(file)|\(mode)|ret=\(ret)|ok=\(okPtr.pointee)|newmsgid=\(newmsgid)|rep=\(hex)\n"
    }

    /// 变体串读取：flag=[base+0x17] 符号负=长串（ptr@[base]、size@[base+8]）；
    /// 短串数据 inline@base、直接长度字节 @[base+0x17]（41,334 位点共读
    /// 直方图 + 0x4a7d6ac `ldrsb [x0,#0x17]` 形态实证）。
    private static func readVariantString(_ obj: UnsafeMutableRawPointer, base: Int) -> Data {
        let flag = Int8(bitPattern: obj.load(fromByteOffset: base + 0x17, as: UInt8.self))
        if flag < 0 {
            let ptr = obj.load(fromByteOffset: base, as: UInt64.self)
            let size = obj.load(fromByteOffset: base + 8, as: UInt64.self)
            guard ptr > 0x10000, size <= 1 << 20 else { return Data() }
            guard let p = UnsafeRawPointer(bitPattern: UInt(ptr)) else { return Data() }
            return Data(bytes: p, count: Int(size))
        }
        let len = Int(obj.load(fromByteOffset: base + 0x17, as: UInt8.self))
        return Data(bytes: obj + base, count: len)
    }

    /// <tag> 数字等长清零（'1'-'9' → '0'）——runtime.m zero_tag_digits 的
    /// 同语义移植（keep/zero 门的 XML 改写）；非数字即停，等长保证 XML
    /// 结构与其余字节不动。测试层负控也用它构造变异体。
    static func zeroTagDigits(_ buf: inout Data, tag: String) {
        let tagBytes = Array(tag.utf8)
        guard let first = buf.range(of: Data(tagBytes)) else { return }
        var i = first.upperBound
        while i < buf.count, buf[i] != UInt8(ascii: "<") {
            if buf[i] >= UInt8(ascii: "1"), buf[i] <= UInt8(ascii: "9") {
                buf[i] = UInt8(ascii: "0")
            } else if buf[i] != UInt8(ascii: "0") {
                break
            }
            i += 1
        }
    }

    // MARK: 映射 setup（JIT 写态内执行）

    /// dyld 语义的 chained fixups 应用（L7 实证补齐的一步）：谓词探针从不
    /// 摸 fixup 指针所以迷你加载器一直没做；parse 会解引用 __DATA_CONST/
    /// __DATA 里的指针常量（vtable/懒池目标/静态串指针），原始值是
    /// ARM64E 链式编码（首跑故障地址 0x3000_0005AAA38 = target 0x5aaa38
    /// + diversity 0x3000 位域，即未应用的 rebase 条目）。
    ///
    /// 结构（本镜像实测）：header 7×u32 → imports 表 u32[count]{lib:8,
    /// weak:1, name_offset:23(=v>>9)}×2381 → 串池；starts_in_image →
    /// 每 EXEC 外段 {page_size=0x4000, ptr_fmt=6(ARM64E), page_start[]}。
    /// 链条目 u64：bit63=1 bind（ordinal:16 → imports 表 **0 基下标** →
    /// 宿主符号——第一轮曾按 1 基解 `names[ordinal-1]`，全体错绑字母序
    /// 邻居（strcmp→strchr），树构造器子级随堆地址彩票丢弃，L7 第二轮
    /// 以槽 2086 调用形状实证修正），bit63=0 rebase
    /// （target:32 → mapped+target-base）；next:11(bits51-61,×4)，0=链尾。
    /// 返回应用条数。宿主解析不出的 bind 原样保留（GUI 框架符号不在
    /// parse 路径上；rebase 全可应用——目标恒在镜像内）。
    private static func applyChainedFixups(data: Data, map: Verifier.ExecMap) -> Int {
        data.withUnsafeBytes { raw -> Int in
            func u32(_ o: Int) -> UInt32 { raw.loadUnaligned(fromByteOffset: o, as: UInt32.self) }
            func u64(_ o: Int) -> UInt64 { raw.loadUnaligned(fromByteOffset: o, as: UInt64.self) }
            // LC_DYLD_CHAINED_FIXUPS
            var fixoff = -1, fixlen = 0
            var p = 32
            let ncmds = Int(u32(16))
            for _ in 0..<ncmds {
                guard p + 8 <= raw.count else { break }
                let cmd = u32(p), cmdsize = Int(u32(p + 4))
                guard cmdsize > 0 else { break }
                if cmd == 0x8000_0034 { fixoff = Int(u32(p + 8)); fixlen = Int(u32(p + 12)) }
                p += cmdsize
            }
            guard fixoff >= 0, fixoff + 28 <= raw.count else { return 0 }
            let startsOff = Int(u32(fixoff + 4))
            let importsOff = Int(u32(fixoff + 8))
            let symbolsOff = Int(u32(fixoff + 12))
            let importsCount = Int(u32(fixoff + 16))
            guard importsCount > 0, importsOff + 4 * importsCount <= fixlen else { return 0 }
            // imports 名字表：{lib:8, weak:1, name_offset:23}
            var names: [String] = []
            names.reserveCapacity(importsCount)
            for i in 0..<importsCount {
                let v = u32(fixoff + importsOff + 4 * i)
                let from = fixoff + symbolsOff + Int(v >> 9)
                guard from < raw.count else { names.append(""); continue }
                var end = from
                while end < raw.count, raw.loadUnaligned(fromByteOffset: end, as: UInt8.self) != 0 { end += 1 }
                var s = [UInt8]()
                for j in from..<end { s.append(raw.loadUnaligned(fromByteOffset: j, as: UInt8.self)) }
                names.append(String(bytes: s, encoding: .utf8) ?? "")
            }
            // starts_in_image → 段链表
            guard startsOff + 4 <= fixlen else { return 0 }
            let segCount = Int(u32(fixoff + startsOff))
            guard segCount > 0, segCount <= 16 else { return 0 }
            var applied = 0
            for si in 0..<segCount {
                let rel = Int(u32(fixoff + startsOff + 4 + 4 * si))
                guard rel != 0 else { continue }
                let b = fixoff + startsOff + rel
                guard b + 22 <= fixoff + fixlen else { continue }
                let pageSize = Int(u32(b + 4) & 0xFFFF)   // u16 page_size
                let ptrFormat = Int(u32(b + 4) >> 16)      // u16 pointer_format
                let segmentOffset = u64(b + 8)
                let pageCount = Int(u32(b + 20) & 0xFFFF)  // u16 page_count（b+22 起是 page_start[]）
                guard ptrFormat == 6, pageSize > 0, pageCount > 0 else { continue }
                for pi in 0..<pageCount {
                    let ps = Int(u32(b + 22 + 2 * pi) & 0xFFFF)   // u16 page_start
                    if ps == 0xFFFF { continue }
                    var entryVA = segmentOffset + UInt64(pi * pageSize) + UInt64(ps)
                    while true {
                        let off = Int(entryVA - map.base)
                        guard entryVA >= map.base, off >= 0, off + 8 <= map.mappedSize else { break }
                        let v = map.mapped.assumingMemoryBound(to: UInt64.self)[off / 8]
                        let next = (v >> 51) & 0x7FF
                        if v >> 63 == 1 {   // bind
                            // ordinal 是 imports 数组的 0 基下标（L7 第二轮实证：
                            // 槽 2086 的调用形状 f(key,name)→cmp 结果只匹配
                            // names[2086]=_strcmp；差一会绑到字母序邻居
                            // _strchr——树构造器子级彩票的根源）
                            let ordinal = Int(v & 0xFFFF)
                            if ordinal < names.count,
                               let fn = resolveHostSymbol(names[ordinal]) {
                                (map.mapped + off).assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = fn
                                applied += 1
                            }
                        } else {           // rebase
                            let target = v & 0xFFFF_FFFF
                            let value = UInt(bitPattern: map.mapped) + UInt(target) - UInt(map.base)
                            map.mapped.assumingMemoryBound(to: UInt64.self)[off / 8] = UInt64(value)
                            applied += 1
                        }
                        if next == 0 { break }
                        entryVA += UInt64(next) * 4
                    }
                }
            }
            return applied
        }
    }

    /// 段拷贝（与 verify worker 的 performSetupWrites 同语义）。
    private static func copySegments(data: Data, map: Verifier.ExecMap) {
        data.withUnsafeBytes { raw in
            if map.segs.isEmpty {
                memcpy(map.mapped, raw.baseAddress, data.count)
            } else {
                for seg in map.segs where seg.vmaddr >= map.base {
                    let dst = Int(seg.vmaddr - map.base)
                    let src = raw.baseAddress! + seg.fileoff
                    let n = min(Int(seg.filesize), map.mappedSize - dst)
                    if n > 0, dst >= 0 { memcpy(map.mapped + dst, src, n) }
                }
            }
        }
    }

    /// 全桩重定向：__stubs × 间接符号表 → dlsym 宿主实现 → GOT 槽逐个
    /// 覆写。未解析 → 诊断陷阱（命中 exit(150)）。这一步把 parse 的传递
    /// 导入闭包（内部分配器→malloc、字符串助手→memcpy、libc++ assign/
    /// delete 等）一次性兜住，无需手工枚举闭包。
    private static func redirectAllStubs(data: Data, map: Verifier.ExecMap,
                                         resolved: inout Int, unresolved: inout Int) {
        let trap = unresolvedTrapPtr
        for (stubVA, name) in stubEntries(data: data) ?? [] {
            guard let stub = map.ptr(stubVA),
                  let slot = Verifier.ARM64.stubSlotOffset(
                    pcOffset: stubVA - map.base,
                    w0: stub.load(as: UInt32.self),
                    w1: stub.load(fromByteOffset: 4, as: UInt32.self),
                    w2: stub.load(fromByteOffset: 8, as: UInt32.self)) else { continue }
            guard slot >= 0, slot + 8 <= map.mappedSize,
                  UInt(bitPattern: map.mapped + slot) % 8 == 0 else { continue }
            if let fn = resolveHostSymbol(name) {
                resolved += 1
                (map.mapped + slot).assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = fn
            } else {
                unresolved += 1
                (map.mapped + slot).assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = trap
            }
        }
    }

    /// 宿主符号解析：RTLD_DEFAULT → libc++ → libc++abi（C++ 运行时符号在
    /// 纯 Swift 宿主可能未装载，显式 dlopen 兜底）。Mach-O 符号名带一个
    /// 前导下划线，dlsym 名剥且仅剥一个（C++ mangling 前缀不受影响）。
    private static func resolveHostSymbol(_ mangledWithUnderscore: String) -> UnsafeMutableRawPointer? {
        let name = String(mangledWithUnderscore.dropFirst())
        if let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) { return p }  // RTLD_DEFAULT
        for lib in ["/usr/lib/libc++.1.dylib", "/usr/lib/libc++abi.dylib"] {
            if let h = dlopen(lib, RTLD_LAZY), let p = dlsym(h, name) { return p }
        }
        return nil
    }

    /// __stubs 条目 (VA, 符号名)：LC_SEGMENT_64 定位 __TEXT/__stubs 节 +
    /// LC_SYMTAB / LC_DYSYMTAB 间接表对名。读【文件字节】（与 JIT 区解耦）。
    private static func stubEntries(data: Data) -> [(UInt64, String)]? {
        data.withUnsafeBytes { raw -> [(UInt64, String)]? in
            func u32(_ o: Int) -> UInt32 { raw.loadUnaligned(fromByteOffset: o, as: UInt32.self) }
            func u64(_ o: Int) -> UInt64 { raw.loadUnaligned(fromByteOffset: o, as: UInt64.self) }
            func byte(_ o: Int) -> UInt8 { raw.loadUnaligned(fromByteOffset: o, as: UInt8.self) }
            func cstr(_ from: Int, _ bound: Int) -> String? {
                var end = from
                while end < bound, end < raw.count, byte(end) != 0 { end += 1 }
                guard end > from else { return nil }
                var s = [UInt8](); s.reserveCapacity(end - from)
                for i in from..<end { s.append(byte(i)) }
                return String(bytes: s, encoding: .utf8)
            }
            guard raw.count >= 32, u32(0) == 0xFEEDFACF, u32(4) == 0x0100_000C else { return nil }
            let ncmds = Int(u32(16))
            var p = 32
            var stubsAddr: UInt64?, stubsSize: UInt64?
            var symoff = 0, nsyms = 0, stroff = 0, strsize = 0
            var indirectOff = 0, indirectCount = 0
            for _ in 0..<ncmds {
                guard p + 8 <= raw.count else { break }
                let cmd = u32(p)
                let cmdsize = Int(u32(p + 4))
                guard cmdsize > 0 else { break }
                switch cmd {
                case 0x19:   // LC_SEGMENT_64
                    let segName = cstr(p + 8, p + 24)
                    let nsects = Int(u32(p + 64))
                    var q = p + 72
                    for _ in 0..<nsects {
                        guard q + 80 <= p + cmdsize, q + 80 <= raw.count else { break }
                        if segName == "__TEXT", cstr(q, q + 16) == "__stubs" {
                            stubsAddr = u64(q + 32)
                            stubsSize = u64(q + 40)
                        }
                        q += 80
                    }
                case 0x2:   // LC_SYMTAB
                    symoff = Int(u32(p + 8)); nsyms = Int(u32(p + 12))
                    stroff = Int(u32(p + 16)); strsize = Int(u32(p + 20))
                case 0xB:   // LC_DYSYMTAB
                    indirectOff = Int(u32(p + 56)); indirectCount = Int(u32(p + 60))
                default: break
                }
                p += cmdsize
            }
            guard let addr = stubsAddr, let size = stubsSize,
                  nsyms > 0, indirectCount > 0 else { return nil }
            var out: [(UInt64, String)] = []
            for i in 0..<Int(size) / 12 {
                let idxPos = indirectOff + 4 * i
                guard idxPos + 4 <= raw.count else { break }
                let idx = u32(idxPos)
                // INDIRECT_SYMBOL_ABS / LOCAL 标记位：无外部名
                guard idx & 0xC000_0000 == 0, Int(idx) < nsyms else { continue }
                let sym = symoff + 16 * Int(idx)
                guard sym + 16 <= raw.count else { continue }
                guard let name = cstr(stroff + Int(u32(sym)), stroff + strsize), !name.isEmpty else { continue }
                out.append((addr + UInt64(12 * i), name))
            }
            return out
        }
    }

    /// 栈哨兵 GOT：目标函数序言找 `adrp xN,<page>; ldr xN,[xN,#imm];
    /// ldr xM,[xN]` 三连（哨兵装载唯一形态——槽存 canary 地址、二次装载
    /// 取值）。槽值指向 worker 自备 canary。找不到即无哨兵，跳过。
    private static func patchStackGuardSlot(map: Verifier.ExecMap, fnVA: UInt64) {
        guard let fn = map.ptr(fnVA) else { return }
        func adrp(_ w: UInt32, _ pc: UInt64) -> (rd: UInt32, page: UInt64)? {
            guard (w >> 31) == 1, (w >> 24) & 0x1F == 0x10 else { return nil }
            let immlo = UInt64((w >> 29) & 0x3)
            let immhi = UInt64((w >> 5) & 0x7_FFFF)
            var imm = (immhi << 2) | immlo
            if imm & (1 << 20) != 0 { imm -= 1 << 21 }
            return (w & 0x1F, (pc & ~0xFFF) &+ (imm << 12))
        }
        func ldrImm12(_ w: UInt32) -> (rn: UInt32, rt: UInt32, imm: UInt64)? {
            guard w >> 22 == 0x3E5 else { return nil }   // ldr x-, [x-, #imm12*8]
            return ((w >> 5) & 0x1F, w & 0x1F, UInt64((w >> 10) & 0xFFF))
        }
        for off in stride(from: 0, to: 0x80 - 8, by: 4) {
            guard let a = adrp(fn.load(fromByteOffset: off, as: UInt32.self), fnVA + UInt64(off)),
                  let l1 = ldrImm12(fn.load(fromByteOffset: off + 4, as: UInt32.self)),
                  l1.rn == a.rd else { continue }
            let l2 = fn.load(fromByteOffset: off + 8, as: UInt32.self)
            // ldr xM,[xN]（imm12=0）
            guard let l3 = ldrImm12(l2), l3.rn == a.rd, l3.imm == 0 else { continue }
            let slot = a.page + l1.imm * 8
            guard let p = map.ptr(slot), UInt(bitPattern: p) % 8 == 0 else { return }
            p.assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee =
                UnsafeMutableRawPointer(bitPattern: canaryAddress)
            return
        }
    }
    #endif
}

/// 文件级函数（C 函数指针只能取自顶层 func/字面闭包）：未解析导入陷阱。
private func parseOracleUnresolvedTrap() {
    _ = write(2, "parse-oracle: hit an import unresolved in this host process (count on stubs line)\n", 80)
    _exit(150)
}

/// lldb 排障锚：断点此符号，x0 = 映射基址（12 个 fail 位点 = base+0x4bc4da0
/// /dfc/5014/5194/51a8/56ac/5738/5878/5ae8/5b38/5b84/5d08）。
@_cdecl("wxkeep_oracle_marker")
func wxkeep_oracle_marker(_ base: UInt) {
    // no-op —— lldb 断点用
}

private func hex(_ v: UInt) -> String { String(v, radix: 16) }

// countnew 探针的蹦床全局（无捕获闭包可作 C 函数指针）
nonisolated(unsafe) var oracleNewCount = 0
nonisolated(unsafe) var oracleRealNew: UnsafeMutableRawPointer?
