import ArgumentParser
import CommonCrypto
import CryptoKit
import Foundation

// MARK: - SQLCipher 经典几何加密核（SHA512/256000，页 4096/reserve 80）
// 几何与验证公式源自 sqlcipher 4.5.6 crypto.c 源读 + 2026-10-29 全库实测（ROADMAP 77 续㊶）。

enum SQLCipherGeometry {
    static let pageSize = 4096
    static let plainHeader = Array("SQLite format 3\u{0}".utf8)

    /// salt^0x3a = HMAC 派生盐（mac_salt）
    static func macSalt(_ salt: [UInt8]) -> [UInt8] {
        salt.map { $0 ^ 0x3a }
    }

    static func pbkdf2SHA512(password: [UInt8], salt: [UInt8], rounds: Int, outLen: Int = 32) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: outLen)
        let status = password.withUnsafeBufferPointer { pwBuf in
            salt.withUnsafeBufferPointer { saltBuf in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    UnsafeRawPointer(pwBuf.baseAddress!).assumingMemoryBound(to: CChar.self), pwBuf.count,
                    saltBuf.baseAddress, saltBuf.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                    UInt32(rounds),
                    &out, outLen)
            }
        }
        precondition(status == kCCSuccess, "CCKeyDerivationPBKDF failed: \(status)")
        return out
    }

    /// DB 密钥 = PBKDF2-SHA512(secret, file[0:16], 256000, 32B)
    static func deriveKey(secret: [UInt8], salt: [UInt8], rounds: Int = 256_000) -> [UInt8] {
        pbkdf2SHA512(password: secret, salt: salt, rounds: rounds)
    }

    /// 页 HMAC 密钥 = PBKDF2-SHA512(key, salt^0x3a, 2, 32B)
    static func macKey(key: [UInt8], salt: [UInt8]) -> [UInt8] {
        pbkdf2SHA512(password: key, salt: macSalt(salt), rounds: 2)
    }

    static func hmacSHA512(key: [UInt8], message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA512>.authenticationCode(
            for: message, using: SymmetricKey(data: key)))
    }

    /// 页 1 验证：HMAC-SHA512(macKey, page[16:4032]+LE32(1)) == page[4032:4096]。
    /// 明文库（头 16B == "SQLite format 3\0"）返回 false。
    static func verifyPage1(page: [UInt8], key: [UInt8]) -> Bool {
        guard page.count >= pageSize else { return false }
        if Array(page[0..<16]) == plainHeader { return false }
        let salt = Array(page[0..<16])
        let mac = hmacSHA512(
            key: macKey(key: key, salt: salt),
            message: Array(page[16..<4032]) + [1, 0, 0, 0])
        return mac == Array(page[4032..<4096])
    }

    static func saltOfPage1(page: [UInt8]) -> [UInt8] {
        Array(page.prefix(16))
    }

    /// 打开经典几何库所需的 PRAGMA 前缀（raw key 形态 x'..' 跳 KDF）
    static let pragmaPreamble =
        "PRAGMA cipher_page_size = 4096; PRAGMA cipher_hmac_algorithm = HMAC_SHA512; PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"
}

// MARK: - 字节/十六进制

extension Array where Element == UInt8 {
    init?(hexString: String) {
        let chars = Array(hexString.lowercased().utf8)
        guard chars.count % 2 == 0, !chars.isEmpty else { return nil }
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        var out = [UInt8](); out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

// MARK: - 密钥库

struct DbKeysStore: Codable, Equatable {
    var secrets: [String] = []          // 账号级 master secret（hex，32B）
    var dbs: [String: String] = [:]     // "账号/库文件名"（新）或裸库文件名（旧）→ raw key（hex）

    /// 键位规则（111 轮多账号修复）：微信每账号目录结构相同、库文件同名
    /// （账号 A/B 各有一个 message_0.db）——裸 basename 键在多账号下会让
    /// B 库撞上 A 的钥。新键位 = "account/basename"；旧裸键保留回落（单
    /// 账号时代存量库无迁移负担）。**每个候选键都验页 HMAC**——验不中
    /// 即不是本库的钥（盐不同），绝不误用，然后走 secrets 现场派生。
    static func dbKey(basename: String, account: String) -> String {
        account.isEmpty ? basename : "\(account)/\(basename)"
    }

    /// 存储钥优先（限定位 → 裸位，逐个验页），其次用 secrets 按盐派生并回验
    func keyFor(basename: String, account: String = "", salt: [UInt8], page: [UInt8]) -> [UInt8]? {
        var candidates = [Self.dbKey(basename: basename, account: account)]
        if !account.isEmpty { candidates.append(basename) }   // 旧库裸键回落
        for name in candidates {
            if let hex = dbs[name], let key = [UInt8](hexString: hex),
               SQLCipherGeometry.verifyPage1(page: page, key: key) {
                return key
            }
        }
        for secretHex in secrets {
            guard let secret = [UInt8](hexString: secretHex) else { continue }
            let key = SQLCipherGeometry.deriveKey(secret: secret, salt: salt)
            if SQLCipherGeometry.verifyPage1(page: page, key: key) {
                return key
            }
        }
        return nil
    }

    /// 派生并晋升入库（限定位）。已在限定位（或裸位——keyFor 命中）时不
    /// 重复写；钥来自 secrets 现场派生时入限定位（含旧裸键的隐式迁移）。
    ///
    /// 失效键刷新（136 轮评审 P3）：限定位在场但**验页不过**（盐轮换——
    /// 微信重登重新加密库）时，旧行为 `dbs[qualified] == nil` 门使失效键
    /// 永不更新：check 仍绿（keyFor 落到 secrets 现场派生救场）但 store
    /// 永远躺着失效键；此后 secrets 一被裁（dbs 已 populated 后看似冗余），
    /// 全部轮换库变 RED 并被指向重跑 capture。刷新键与初次晋升同门——
    /// 都经页 HMAC 验证，无误伤面。
    mutating func promote(basename: String, account: String = "", salt: [UInt8], page: [UInt8]) -> Bool {
        let qualified = Self.dbKey(basename: basename, account: account)
        if let existing = dbs[qualified],
           let key = [UInt8](hexString: existing),
           SQLCipherGeometry.verifyPage1(page: page, key: key) {
            return false   // 现键有效：不重复写（原语义）
        }
        guard let key = keyFor(basename: basename, account: account, salt: salt, page: page) else { return false }
        dbs[qualified] = key.hexString
        return true
    }
}

enum DbKeysFiles {
    static var defaultStoreURL: URL {
        if let p = ProcessInfo.processInfo.environment["WXKEEP_DBKEYS"] {
            return URL(fileURLWithPath: p)
        }
        let cwdStore = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("var/dbkeys/keys.json")
        if FileManager.default.fileExists(atPath: cwdStore.path) { return cwdStore }
        return Config.userDataURL.appendingPathComponent("dbkeys.json")
    }

    static func loadStore(url: URL?) -> DbKeysStore {
        let target = url ?? defaultStoreURL
        guard let data = try? Data(contentsOf: target),
              let store = try? JSONDecoder().decode(DbKeysStore.self, from: data)
        else { return DbKeysStore() }
        return store
    }

    static func saveStore(_ store: DbKeysStore, url: URL?) throws {
        let target = url ?? defaultStoreURL
        try FileManager.default.createDirectory(
            at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try enc.encode(store)
        try SafeWrite.overwrite(data, to: target)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: target.path)
    }
}

// MARK: - 微信库枚举

enum WeChatDBFinder {
    /// 微信库根：家目录锚 RealUser——sudo dbkeys/recover 时读真实用户的
    /// 微信数据（NSHomeDirectory 在 root 下指 /var/root，必然「未找到账号」）。
    static var xwechatRoot: URL {
        RealUser.homeURL()
            .appendingPathComponent("Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files")
    }

    static func accounts() -> [String] {
        let root = xwechatRoot
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root.path) else { return [] }
        return names.filter { name in
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: root.appendingPathComponent(name).path, isDirectory: &isDir) && isDir.boolValue
        }.sorted()
    }

    /// 账号目录下全部 *.db（递归）；`live: true` 只取 db_storage 活库（排除 Backup 副本）
    static func encryptedDBs(account: String, live: Bool = false) -> [URL] {
        let base = xwechatRoot.appendingPathComponent(account)
        guard let en = FileManager.default.enumerator(
            at: base, includingPropertiesForKeys: nil) else { return [] }
        var out: [URL] = []
        for case let url as URL in en {
            guard url.pathExtension == "db" else { continue }
            if live && !url.path.contains("/db_storage/") { continue }
            out.append(url)
        }
        return out.sorted { $0.path < $1.path }
    }

    static func page1(of url: URL) -> [UInt8]? {
        guard let fh = try? FileHandle(forReadingFrom: url) else { return nil }
        // defer 收句柄（136 轮评审 P3）：此前 close 只在 guard 双条件全过
        // （读成功）后到达——read 抛错路径句柄已开未关；audit/recover 逐库
        // 枚举面 + I/O 故障（并发删除/权限翻转）时可积累 fd。
        defer { try? fh.close() }
        guard let data = try? fh.read(upToCount: SQLCipherGeometry.pageSize) else { return nil }
        guard data.count >= 64 else { return nil }
        return [UInt8](data)
    }

    static func isPlain(_ page: [UInt8]) -> Bool {
        Array(page.prefix(16)) == SQLCipherGeometry.plainHeader
    }
}

// MARK: - zstd（dlopen 可选：audit 分类用；缺席时自动退化）

enum Zstd {
    nonisolated(unsafe) private static var cachedHandle: UnsafeMutableRawPointer?

    static var available: Bool { handle() != nil }

    private static func handle() -> UnsafeMutableRawPointer? {
        if cachedHandle != nil { return cachedHandle }
        let paths = ["/opt/homebrew/lib/libzstd.dylib", "/usr/local/lib/libzstd.dylib", "libzstd.dylib"]
        for p in paths {
            if let h = dlopen(p, RTLD_LAZY) {
                cachedHandle = h
                return h
            }
        }
        return nil
    }

    /// 解压 zstd 帧；非 zstd 输入原样返回；失败返回 nil
    static func decompress(_ raw: Data) -> Data? {
        guard raw.starts(with: [0x28, 0xB5, 0x2F, 0xFD]) else { return raw }
        typealias ZSTDDecompressFn = @convention(c) (UnsafeMutableRawPointer?, Int, UnsafeRawPointer?, Int) -> Int
        guard let lib = handle(),
              let sym = dlsym(lib, "ZSTD_decompress") else { return nil }
        let fn = unsafeBitCast(sym, to: ZSTDDecompressFn.self)
        let cap = max(raw.count * 16, 1 << 20)
        let out = UnsafeMutableRawPointer.allocate(byteCount: cap, alignment: 16)
        defer { out.deallocate() }
        let n = raw.withUnsafeBytes { buf -> Int in
            fn(out, cap, buf.baseAddress, buf.count)
        }
        guard n > 0 else { return nil }
        return Data(bytes: out, count: n)
    }
}

// MARK: - 撤回灰条分类（永不打印消息内容，只出形态标签）

enum RevokeTipClassifier {
    enum Form: String, CaseIterable {
        case xmlRevoke = "xml"      // <sysmsg type="revokemsg">（含 re-edit 记账）
        case selfRevoke = "self"    // 你撤回了一条消息
        case otherRevoke = "other"  // "昵称" 撤回了一条消息
        case otherSystem = "system" // 其余系统行（入群/退群等）
    }

    static func classify(_ body: Data) -> Form {
        guard let text = String(data: body, encoding: .utf8) else { return .otherSystem }
        if text.contains("<sysmsg type=\"revokemsg\">") { return .xmlRevoke }
        if text.contains("撤回") {
            return text.hasPrefix("你") ? .selfRevoke : .otherRevoke
        }
        return .otherSystem
    }
}

// MARK: - dbkeys 命令组

extension Wxkeep {
    struct DbKeysCommand: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "dbkeys",
            abstract: "WeChat 数据库密钥仪器：check 验钥 / capture 捕获 / audit 撤回审计 / recover 撤回原文复原",
            subcommands: [Check.self, Capture.self, Audit.self, Recover.self])

        // MARK: check

        struct Check: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "对全部加密库逐个跑页 HMAC 验证（绿=钥仍有效）")

            @Option(name: .long, help: "密钥库路径（默认 $WXKEEP_DBKEYS → ./var/dbkeys/keys.json → 用户数据目录）")
            var keys: String?

            mutating func run() throws {
                let storeURL = PathUtil.expandTilde(keys).map { URL(fileURLWithPath: $0) }
                var store = DbKeysFiles.loadStore(url: storeURL)
                let accounts = WeChatDBFinder.accounts()
                guard !accounts.isEmpty else { throw ValidationError("未找到 xwechat_files 账号目录") }
                var green = 0, plain = 0, changed = false
                var red: [String] = []
                for account in accounts {
                    for url in WeChatDBFinder.encryptedDBs(account: account, live: true) {
                        guard let page = WeChatDBFinder.page1(of: url) else { continue }
                        if WeChatDBFinder.isPlain(page) { plain += 1; continue }
                        let salt = SQLCipherGeometry.saltOfPage1(page: page)
                        // 111 轮多账号修复：check 与 audit/recover 同口径（keyFor
                        /// 验中即用 + secrets 回落），不再因裸 basename 撞键误报 RED
                        var ok = false
                        if store.promote(basename: url.lastPathComponent, account: account,
                                         salt: salt, page: page) {
                            ok = true
                            changed = true
                        } else if store.keyFor(basename: url.lastPathComponent, account: account,
                                               salt: salt, page: page) != nil {
                            ok = true
                        }
                        if ok { green += 1 } else { red.append(url.path) }
                    }
                }
                if changed { try DbKeysFiles.saveStore(store, url: storeURL) }
                print("green=\(green) plain=\(plain) red=\(red.count)\(changed ? "（派生钥已晋升入库）" : "")")
                for path in red.prefix(10) { print("  RED \(path)") }
                if !red.isEmpty {
                    print("密钥缺失/失效——运行 `wxkeep dbkeys capture` 重新捕获"
                        + "（需微信已 `wxkeep patch` 并重新扫码登录，最长等 7 分钟）")
                }
                if !red.isEmpty { throw ExitCode(1) }
            }
        }

        // MARK: capture

        struct Capture: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "重启微信于 lldb 断点捕获 CCKeyDerivationPBKDF，登录后自动派生+验证+入库")

            @Option(name: .long, help: "等待登录秒数")
            var wait: Int = 420
            @Option(name: .long, help: "密钥库路径")
            var keys: String?

            mutating func run() throws {
                let wechatExe = "/Applications/WeChat.app/Contents/MacOS/WeChat"
                guard FileManager.default.fileExists(atPath: wechatExe) else {
                    throw ValidationError("未找到 \(wechatExe)")
                }
                guard Self.entitleHasGetTaskAllow(exe: wechatExe) else {
                    throw ValidationError("微信二进制无 get-task-allow：先 `wxkeep patch`（重签带该 entitlement）再 capture")
                }
                // 宿主原生架构门（136 轮评审 P3）：lldb 脚本锚 arm64 寄存器
                //（x1..x6 + `$x6 > 32000` 轮数条件）——Intel 宿主上被调试的
                // 微信也是 x86_64，寄存器名恒不命中 → 必然超时，报「确认已
                // 登录后重试」把工具局限误报成用户操作问题，重试死循环。
                // 判**宿主**而非编译切片：Rosetta x64 wxkeep 调试 arm64 微信
                // 时目标寄存器仍是 x 族，照常可用。诚实拒绝（x64 寄存器映射
                // 待 Intel 真机实证后再补，不猜 ABI）。
                if Doctor.nativeArch() == "x86_64" {
                    throw ValidationError("dbkeys capture 的 lldb 断点脚本锚 arm64 寄存器，"
                        + "本机原生架构是 x86_64——当前不支持；请在 Apple Silicon 机器上运行。")
                }
                let storeURL = PathUtil.expandTilde(keys).map { URL(fileURLWithPath: $0) }
                let hitsPath = NSTemporaryDirectory() + "wxkeep-pbkdf-hits.jsonl"
                try? FileManager.default.removeItem(atPath: hitsPath)
                // 124 轮体检 P2 修：hits 文件含 PBKDF 主密钥明文（= 全部聊天库
                // 解密材料），此前 0644 残留 $TMPDIR 直到下次 capture。两侧收口：
                // 脚本侧 O_CREAT 0600（见 captureScript）；本侧无论成败 run 结束
                // 即删（promote 已入库 keys.json(0600)，hits 无后续读者）。
                defer { try? FileManager.default.removeItem(atPath: hitsPath) }
                let scriptPath = NSTemporaryDirectory() + "wxkeep_capture_lldb.py"
                try Self.captureScript(hitsPath: hitsPath)
                    .write(to: URL(fileURLWithPath: scriptPath), atomically: true, encoding: .utf8)
                print("· 结束现有微信进程…")
                let pkill = Process()
                pkill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                pkill.arguments = ["-TERM", "-x", "WeChat"]
                if let _ = try? pkill.run() { pkill.waitUntilExit() }
                Thread.sleep(forTimeInterval: 2)
                let logPath = NSTemporaryDirectory() + "wxkeep-capture-lldb.log"
                FileManager.default.createFile(atPath: logPath, contents: nil)
                guard let log = FileHandle(forWritingAtPath: logPath) else {
                    throw ValidationError("无法创建 \(logPath)")
                }
                defer { try? log.close() }
                let lldb = Process()
                lldb.executableURL = URL(fileURLWithPath: "/usr/bin/lldb")
                lldb.arguments = [
                    "-b",
                    "-o", "command script import \(scriptPath)",
                    "-o", "command script add -f wxkeep_capture_lldb.hkstart hkstart",
                    "-o", "hkstart",
                    "-o", "process launch",
                    "-o", "continue",
                    wechatExe,
                ]
                lldb.standardOutput = log
                lldb.standardError = log
                try lldb.run()
                print("· 微信已由 lldb 托管启动（日志 \(logPath)）——请扫码登录；登录开库时自动捕获（最长等 \(wait)s）")
                let deadline = Date().addingTimeInterval(TimeInterval(wait))
                var hits: [CaptureHit] = []
                while Date() < deadline {
                    Thread.sleep(forTimeInterval: 3)
                    hits = CaptureHit.parse(file: hitsPath)
                    if hits.count >= 8 { break }   // 开库风暴一次 30+，8 即可判定
                }
                let opens = hits.filter { $0.rounds == 256_000 || $0.rounds == 64_000 || $0.rounds == 4_000 }
                guard !opens.isEmpty else {
                    print("超时未捕获开库级 KDF 调用——确认已登录后重试；lldb 日志尾部：")
                    if let data = FileManager.default.contents(atPath: logPath),
                       let text = String(data: data.suffix(800), encoding: .utf8) { print(text) }
                    throw ExitCode(1)
                }
                print("· 捕获 KDF 调用 \(hits.count) 次（开库级 \(opens.count)）")
                var store = DbKeysFiles.loadStore(url: storeURL)
                var secrets = Set(store.secrets)
                for h in opens where !h.pw.isEmpty { secrets.insert(h.pw) }
                store.secrets = secrets.sorted()
                var green = 0, red = 0
                for account in WeChatDBFinder.accounts() {
                    for url in WeChatDBFinder.encryptedDBs(account: account, live: true) {
                        guard let page = WeChatDBFinder.page1(of: url), !WeChatDBFinder.isPlain(page) else { continue }
                        if store.promote(basename: url.lastPathComponent,
                                         salt: SQLCipherGeometry.saltOfPage1(page: page),
                                         page: page) {
                            green += 1
                        } else {
                            red += 1
                        }
                    }
                }
                try DbKeysFiles.saveStore(store, url: storeURL)
                print("· 派生验证 green=\(green) red=\(red)；密钥库已更新：\((storeURL ?? DbKeysFiles.defaultStoreURL).path)")
                print("· 注意：微信现由 lldb 托管；要回归常态请正常重启微信一次")
                if green == 0 { throw ExitCode(1) }
            }

            static func entitleHasGetTaskAllow(exe: String) -> Bool {
                let cs = Process()
                cs.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
                cs.arguments = ["-d", "--entitlements", ":-", exe]
                let pipe = Pipe()
                cs.standardOutput = pipe
                cs.standardError = Pipe()
                do { try cs.run() } catch { return false }
                // 先读后等（135 轮体检 P3）：输出超管道缓冲（64KB）时
                // waitUntilExit 在前 = 子进程写阻塞 + 父进程等退出 = 死锁
                //（runSQL 同文件已是正确序，形态对齐）。
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                cs.waitUntilExit()
                return String(data: data, encoding: .utf8)?.contains("get-task-allow") == true
            }

            static func captureScript(hitsPath: String) -> String {
                """
                import lldb, time, json, os
                FH = None
                def _log(o):
                    global FH
                    if FH is None:
                        # 0600（124 轮体检 P2）：内容是主密钥明文，不得全局可读
                        FH = os.fdopen(os.open(\(String(reflecting: hitsPath)),
                                                os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600),
                                       "a", buffering=1)
                    FH.write(json.dumps(o) + "\\n")
                def bp_callback(frame, bp_loc, d):
                    try:
                        r = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
                        pw, pwlen = r("x1"), r("x2")
                        salt, saltlen = r("x3"), r("x4")
                        prf, rounds = r("x5"), r("x6")
                        proc = frame.GetThread().GetProcess()
                        err = lldb.SBError()
                        pw_b = (proc.ReadMemory(pw, min(pwlen, 256), err) or b"") if 0 < pwlen <= 256 else b""
                        salt_b = (proc.ReadMemory(salt, min(saltlen, 64), err) or b"") if 0 < saltlen <= 64 else b""
                        _log({"ts": time.time(), "prf": prf, "rounds": rounds, "pw": pw_b.hex(), "salt": salt_b.hex()})
                    except Exception as e:
                        _log({"error": repr(e)})
                    return False
                def hkstart(debugger, command, exe_ctx, internal_dict):
                    bp = debugger.GetSelectedTarget().BreakpointCreateByName("CCKeyDerivationPBKDF")
                    bp.SetCondition("$x6 > 32000")
                    bp.SetScriptCallbackFunction(__name__ + ".bp_callback")
                    print("wxkeep capture: armed, locations=%d" % bp.GetNumLocations(), flush=True)
                """
            }
        }

        // MARK: audit

        struct Audit: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "撤回灰条审计：库内撤回真身盘点 + 补丁有效性数据面（--since 后新灰条应为 0）")

            @Option(name: .long, help: "只统计此时刻（ISO8601 或 yyyy-MM-dd HH:mm）之后的灰条")
            var since: String?
            @Option(name: .long, help: "展示最近 N 条灰条的位置（不含内容）")
            var latest: Int = 0
            @Option(name: .long, help: "sqlcipher 可执行路径（默认 brew/PATH 探测）")
            var sqlcipher: String?
            @Option(name: .long, help: "密钥库路径（默认 $WXKEEP_DBKEYS → ./var/dbkeys/keys.json → 用户数据目录）")
            var keys: String?
            @Flag(name: .long, help: "跳过灰条分类（zstd 缺席时自动退化）")
            var noClassify = false

            mutating func run() throws {
                guard let exe = Self.resolveSQLCipher(explicit: sqlcipher) else {
                    throw ValidationError("未找到 sqlcipher（brew install sqlcipher 或 --sqlcipher 指定）")
                }
                let store = DbKeysFiles.loadStore(
                    url: PathUtil.expandTilde(keys).map { URL(fileURLWithPath: $0) })
                let sinceTS = try Self.parseTimestamp(since)
                // 门可判性前置拒（136 轮评审 P2）：--since 的判据是 [other]
                // 分类计数，--no-classify 关闭分类 = 无证据可判。此前空 rows
                // 恒打「数据面 PASS」+ exit 0——vacuous 绿骗过机器门。组合
                // 本身矛盾，运行前即拒（免跑全库后才发现门不可判）。
                if noClassify, sinceTS != nil {
                    throw ValidationError("--since 数据面门与 --no-classify 不可并用："
                        + "门判据是他撤模板灰条（[other] 分类计数），关闭分类即无证据可判。"
                        + "去掉 --no-classify，或去掉 --since 只看原始计数。")
                }
                let needRows = latest > 0 || sinceTS != nil
                var total: [RevokeTipClassifier.Form: Int] = [:]
                var unknownForm = 0
                var plainDBs = 0
                var rows: [(ts: Int, chat: String, db: String, form: RevokeTipClassifier.Form)] = []
                let accounts = WeChatDBFinder.accounts()
                guard !accounts.isEmpty else { throw ValidationError("未找到 xwechat_files 账号目录") }
                for account in accounts {
                    let dbs = WeChatDBFinder.encryptedDBs(account: account, live: true)
                        .filter { url in
                            let n = url.lastPathComponent
                            return n.hasPrefix("message_") && !n.contains("fts")
                                && !n.contains("biz") && !n.contains("resource")
                        }
                    for db in dbs {
                        guard let page = WeChatDBFinder.page1(of: db) else { continue }
                        // 明文库披露（136 轮评审 P3，check 有 plain 计数/audit 无
                        // 的口径不一致收口）：不进统计但如实报数。
                        if WeChatDBFinder.isPlain(page) { plainDBs += 1; continue }
                        let salt = SQLCipherGeometry.saltOfPage1(page: page)
                        guard let key = store.keyFor(basename: db.lastPathComponent, account: account, salt: salt, page: page) else {
                            throw ValidationError("密钥不可用：\(db.lastPathComponent) — 先 `wxkeep dbkeys check` / `capture`")
                        }
                        let tables = try Self.listMsgTables(db: db, exe: exe, key: key)
                        let names = try Self.nameMap(db: db, exe: exe, key: key)
                        for chunk in tables.chunked(into: 400) {
                            for line in try Self.queryTips(db: db, exe: exe, key: key, tables: chunk, since: sinceTS) {
                                let parts = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
                                guard parts.count == 4 else { continue }
                                let table = String(parts[0])
                                let ts = Int(parts[2]) ?? 0
                                let hexBody = String(parts[3])
                                if noClassify {
                                    unknownForm += 1
                                    continue
                                }
                                guard let raw = Self.hexData(hexBody), let body = Zstd.decompress(raw) else {
                                    unknownForm += 1
                                    continue
                                }
                                let form = RevokeTipClassifier.classify(body)
                                total[form, default: 0] += 1
                                if needRows {
                                    rows.append((ts, names[table] ?? table, db.lastPathComponent, form))
                                }
                            }
                        }
                    }
                }
                let zstdNote = noClassify ? "，--no-classify" : (Zstd.available ? "" : "，zstd 缺席退化")
                let sysCount = total[.otherSystem, default: 0]
                print("撤回灰条：xml=\(total[.xmlRevoke, default: 0]) self=\(total[.selfRevoke, default: 0]) other=\(total[.otherRevoke, default: 0])（其余系统行=\(sysCount)，未分类=\(unknownForm)\(zstdNote)）")
                if plainDBs > 0 {
                    print("ℹ︎ 明文库跳过 \(plainDBs) 库——其灰条不在上述统计与 --since 门内（check 的 plain 计数同口径）")
                }
                // 111 轮修：--latest 负值会让 prefix/suffix 触发 _precondition 崩溃——
                // 夹到 ≥0（负语义上等价于 0：不导出）
                for row in rows.sorted(by: { $0.ts > $1.ts }).prefix(max(latest, 0)) {
                    print("  \(row.ts > 0 ? Self.fmt(row.ts) : "?") [\(row.form.rawValue)] \(row.chat) (\(row.db))")
                }
                if let sinceTS {
                    // 门语义（2026-10-29 XML 取证轮定案）：只有 [other]（模板文案
                    // 灰条=消费端命中腿产物）是保护失败证据。[xml] 是无 newmsgid
                    // 的轻量通知形态（content 预览+revoketime，天生 lookup-miss
                    // 独立落库——补丁态无关，广告群日更）；[self] 是自发撤回记账
                    // （R3 原生行为，v1 不触碰发起侧）。两者计入 FAIL 会让门误报。
                    // 可判性门（136 轮评审 P2）：零已分类行 + 有未分类行 = 全量
                    // 证据缺失（zstd 缺席机器上 4.x 灰条体全解不开）——fail==0
                    // 不构成「无他撤灰条」的证据，拒打 PASS（此前 vacuous 绿）。
                    let classifiedTotal = total.values.reduce(0, +)
                    guard Self.gateAdmissible(classifiedTotal: classifiedTotal, unknownForm: unknownForm) else {
                        print("--since \(since!) 门不可判：\(unknownForm) 条灰条全部未分类"
                              + "（zstd \(Zstd.available ? "在场但" : "缺席，")无一可解）——"
                              + "无分类证据即无 PASS 可言；装齐 zstd 后重跑")
                        throw ExitCode(1)
                    }
                    let g = Self.gateCounts(rows: rows, since: sinceTS)
                    print("--since \(since!) 他撤模板灰条=\(g.fail)"
                          + (g.xml + g.selfCnt == 0 ? "" : "（另：lite 通知 xml=\(g.xml)"
                              + " self=\(g.selfCnt)"
                              + "——非保护失败证据，见 DbKeys 注）")
                          + " → \(g.fail == 0 ? "补丁有效（数据面 PASS）" : "补丁后有他撤灰条落库（数据面 FAIL）")")
                    if g.fail != 0 { throw ExitCode(1) }
                }
            }

            /// --since 门计数（独立成函数供回归测试钉死语义）：
            /// fail=[other]（他撤模板灰条=唯一保护失败证据）；
            /// xml=[xml]（lite 通知）；selfCnt=[self]（自发撤回记账）。
            static func gateCounts(
                rows: [(ts: Int, chat: String, db: String, form: RevokeTipClassifier.Form)],
                since: Int
            ) -> (fail: Int, xml: Int, selfCnt: Int) {
                var fail = 0, xml = 0, selfCnt = 0
                for r in rows where r.ts >= since {
                    switch r.form {
                    case .otherRevoke: fail += 1
                    case .xmlRevoke: xml += 1
                    case .selfRevoke: selfCnt += 1
                    case .otherSystem: break
                    }
                }
                return (fail, xml, selfCnt)
            }

            /// `--since` 门的可判性（136 轮评审 P2）：判据 = [other] 分类计数，
            /// 「窗口内零他撤灰条」只有在分类确实发生过（classifiedTotal>0）
            /// 或库里压根没有灰条（unknownForm==0）时才是证据。零已分类 +
            /// 有未分类 = 全量证据缺失（zstd 缺席机器上 4.x 灰条体全解不开）
            /// ——此前空 rows 恒打「数据面 PASS」+ exit 0，机器门被 vacuous
            /// 绿骗过。纯函数供回归测试钉死三分支。
            static func gateAdmissible(classifiedTotal: Int, unknownForm: Int) -> Bool {
                classifiedTotal > 0 || unknownForm == 0
            }

            static func resolveSQLCipher(explicit: String?) -> String? {
                if let explicit {
                    let expanded = PathUtil.expandTilde(explicit)
                    if FileManager.default.isExecutableFile(atPath: expanded) { return expanded }
                }
                for c in ["/opt/homebrew/opt/sqlcipher/bin/sqlcipher",
                          "/opt/homebrew/bin/sqlcipher",
                          "/usr/local/opt/sqlcipher/bin/sqlcipher",
                          "/usr/local/bin/sqlcipher"] where FileManager.default.isExecutableFile(atPath: c) {
                    return c
                }
                if let path = ProcessInfo.processInfo.environment["PATH"] {
                    for dir in path.split(separator: ":") {
                        let p = URL(fileURLWithPath: String(dir)).appendingPathComponent("sqlcipher").path
                        if FileManager.default.isExecutableFile(atPath: p) { return p }
                    }
                }
                return nil
            }

            static func parseTimestamp(_ text: String?) throws -> Int? {
                guard let text else { return nil }
                if let d = ISO8601DateFormatter().date(from: text) { return Int(d.timeIntervalSince1970) }
                // 123 轮体检 P3：ISO8601DateFormatter 只收带时区的 internet 形，
                // 用户自然输入的 `2026-11-02T10:00`（本地无时区）此前报
                // 「无法解析」——补 T 分隔的本地形态。
                let f = DateFormatter()
                f.timeZone = .current
                for fmt in ["yyyy-MM-dd HH:mm", "yyyy-MM-dd'T'HH:mm"] {
                    f.dateFormat = fmt
                    if let d = f.date(from: text) { return Int(d.timeIntervalSince1970) }
                }
                if let n = Int(text) { return n }
                throw ValidationError("无法解析时间：\(text)（支持 ISO8601 带时区 / 本地 2026-11-02 10:00 或 2026-11-02T10:00 / epoch 秒）")
            }

            static func fmt(_ ts: Int) -> String {
                let f = DateFormatter()
                f.dateFormat = "MM-dd HH:mm:ss"
                f.timeZone = .current
                return f.string(from: Date(timeIntervalSince1970: TimeInterval(ts)))
            }

            static func hexData(_ hex: String) -> Data? {
                guard !hex.isEmpty, let bytes = [UInt8](hexString: hex) else { return nil }
                return Data(bytes)
            }

            /// sqlcipher 批查询。**退出码/stderr 全检**（102 轮修）：此前
            /// `catch { return [] }` + 忽略 terminationStatus 会让一切查询
            /// 失败（CLI 版本差异/-readonly 不支持/SQL 错）静默伪装成「全
            /// 零统计」——audit 的 --since 门打出假 PASS。stderr 落临时文件
            /// 而非 Pipe（没人读的管道 >64KB 会写阻塞死锁，Shell.run 同款
            /// 教训），错误尾部并入抛错信息。
            static func runSQL(_ exe: String, db: URL, key: [UInt8], statements: String) throws -> [String] {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: exe)
                p.arguments = ["-readonly", db.path]
                let inPipe = Pipe(), outPipe = Pipe()
                p.standardInput = inPipe
                p.standardOutput = outPipe
                let errFile = FileManager.default.temporaryDirectory
                    .appendingPathComponent("wxkeep-sqlcerr-\(UUID().uuidString)")
                guard FileManager.default.createFile(atPath: errFile.path, contents: nil),
                      let errHandle = FileHandle(forWritingAtPath: errFile.path) else {
                    throw ValidationError("无法创建 stderr 临时文件：\(errFile.path)")
                }
                defer { try? FileManager.default.removeItem(at: errFile) }
                p.standardError = errHandle
                do { try p.run() } catch {
                    try? errHandle.close()
                    throw ValidationError("sqlcipher 无法启动（\(exe)）：\(error.localizedDescription)")
                }
                let sql = "PRAGMA key = \"x'\(key.hexString)'\"; \(SQLCipherGeometry.pragmaPreamble); \(statements)\n"
                inPipe.fileHandleForWriting.write(sql.data(using: .utf8)!)
                try? inPipe.fileHandleForWriting.close()
                let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                try? errHandle.close()
                if p.terminationStatus != 0 {
                    let tail = ((try? String(contentsOf: errFile, encoding: .utf8)) ?? "")
                        .split(separator: "\n", omittingEmptySubsequences: true)
                        .suffix(3).joined(separator: " | ")
                    throw ValidationError("sqlcipher 退出码 \(p.terminationStatus)（\(db.lastPathComponent)）：\(tail)")
                }
                return (String(data: data, encoding: .utf8) ?? "")
                    .split(separator: "\n", omittingEmptySubsequences: true)
                    .filter { $0 != "ok" }
                    .map(String.init)
            }

            static func listMsgTables(db: URL, exe: String, key: [UInt8]) throws -> [String] {
                try runSQL(exe, db: db, key: key,
                       statements: "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg\\_%' ESCAPE '\\';")
            }

            static func nameMap(db: URL, exe: String, key: [UInt8]) throws -> [String: String] {
                var out: [String: String] = [:]
                for line in try runSQL(exe, db: db, key: key, statements: "SELECT user_name FROM Name2Id;") {
                    guard let data = line.data(using: .utf8) else { continue }
                    let digest = Insecure.MD5.hash(data: data).map { String(format: "%02x", $0) }.joined()
                    out["Msg_" + digest] = line
                }
                return out
            }

            static func queryTips(db: URL, exe: String, key: [UInt8], tables: [String], since: Int?) throws -> [String] {
                guard !tables.isEmpty else { return [] }
                // 表名白名单（124 轮体检 P3 防御纵深）：表名来自用户库的
                // sqlite_master，虽然连接只读、影响域有限，仍不裸拼——在役
                // 消息表恒为 Msg_<16 进制摘要>，白名单外的表名整体跳过。
                let legit = tables.filter { t in
                    t.count >= 5 && t.count <= 68 && t.hasPrefix("Msg_")
                        && t.dropFirst(4).allSatisfy { $0.isHexDigit }
                }
                guard !legit.isEmpty else { return [] }
                let selects = legit.map { t in
                    "SELECT '\(t)', local_id, create_time, hex(coalesce(message_content,'')) FROM \"\(t)\" WHERE local_type=10000"
                }.joined(separator: " UNION ALL ")
                let sqlText = since.map {
                    "SELECT * FROM (\(selects)) WHERE create_time >= \($0) ORDER BY create_time;"
                } ?? "SELECT * FROM (\(selects)) ORDER BY create_time;"
                return try runSQL(exe, db: db, key: key, statements: sqlText)
            }
        }
    }
}

// MARK: - 捕获记录解析

struct CaptureHit {
    let rounds: Int
    let prf: Int
    let pw: String
    let salt: String

    static func parse(file path: String) -> [CaptureHit] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var out: [CaptureHit] = []
        for line in text.split(separator: "\n") {
            guard let data = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rounds = obj["rounds"] as? Int
            else { continue }
            out.append(CaptureHit(
                rounds: rounds,
                prf: obj["prf"] as? Int ?? 0,
                pw: obj["pw"] as? String ?? "",
                salt: obj["salt"] as? String ?? ""))
        }
        return out
    }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
