import ArgumentParser
import Foundation

// MARK: - 撤回原文复原纯逻辑（ROADMAP 80 轮：原地覆写不触发 FTS 同步，原文残留 content 表）

/// FTS content 表文档判定与查询批切分（独立成纯函数供回归测试钉死）
enum RevokeRecovery {
    struct RecoveredRecord: Codable, Equatable {
        var chat: String
        var name: String?      // 会话显示名（contact.db 解析；缺省=chat）
        var time: Int          // 原消息 create_time（灰条行原地保留）
        var form: String       // self / other
        var localId: Int
        var db: String
        var length: Int        // 复原文本 UTF-8 字节数
        var text: String
    }

    /// FTS 文档是否为灰条文本（被同步覆盖）——实测 synced=0，此分支仅为防御
    static func isTipDocument(_ text: String) -> Bool {
        text.contains("撤回了一条消息") || text.contains("<sysmsg")
    }

    /// 会话显示名解析（contact.db 字段 fallback：备注 > 昵称 > 微信号 > 原始 ID）
    static func displayName(remark: String, nickName: String, alias: String, username: String) -> String {
        for c in [remark, nickName, alias] where !c.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return c
        }
        return username
    }

    /// Markdown 报告渲染：会话分组（最近活跃在前），会话内时间升序，原文 blockquote
    static func renderMarkdown(records: [RecoveredRecord], generatedAt: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.timeZone = .current
        var out = "# 撤回原文复原报告\n\n"
        out += "- 生成：\(f.string(from: generatedAt))\n"
        out += "- 记录：\(records.count) 条 / 会话：\(Set(records.map(\.chat)).count) 个\n\n"
        let byChat = Dictionary(grouping: records) { $0.chat }
        for (chat, group) in byChat.sorted(by: { ($0.value.map(\.time).max() ?? 0) > ($1.value.map(\.time).max() ?? 0) }) {
            let name = group.compactMap(\.name).first ?? chat
            out += "## \(name)\n\n`\(chat)` · \(group.count) 条\n\n"
            for r in group.sorted(by: { $0.time < $1.time }) {
                let who = r.form == "self" ? "我撤回" : "对方撤回"
                out += "### \(r.time > 0 ? f.string(from: Date(timeIntervalSince1970: TimeInterval(r.time))) : "时间未知") · \(who)\n\n"
                for line in r.text.split(separator: "\n", omittingEmptySubsequences: false) {
                    out += "> \(line)\n"
                }
                out += "\n"
            }
        }
        return out
    }

    /// FTS 文档解码（content 表 c0 为明文 UTF-8，非 zstd）
    static func decodeDocument(_ hex: String) -> String? {
        guard !hex.isEmpty, let data = [UInt8](hexString: hex) else { return nil }
        return String(bytes: data, encoding: .utf8)
    }

    /// 会话×local_id 反查项 → WHERE 条件批（OR 连接），每批总 IN 项数 ≤ cap。
    /// 批化动机：content 表无 (c4,c1) 索引，逐会话查询=全表扫描 ×4 分片 ×会话数；
    /// 批化把扫描次数从 4×会话数压到 4×批数。
    static func ftsQueryBatches(
        _ sessions: [(sid: Int, lids: [Int])], cap: Int = 500
    ) -> [String] {
        var out: [String] = []
        var groups: [String] = []
        var terms = 0
        for s in sessions where !s.lids.isEmpty {
            var offset = 0
            while offset < s.lids.count {
                let take = min(cap - terms, s.lids.count - offset)
                if take <= 0 {
                    out.append(groups.joined(separator: " OR "))
                    groups = []; terms = 0
                    continue
                }
                let slice = s.lids[offset..<offset + take]
                groups.append("c4=\(s.sid) AND c1 IN (\(slice.map(String.init).joined(separator: ",")))")
                terms += take
                offset += take
            }
        }
        if !groups.isEmpty { out.append(groups.joined(separator: " OR ")) }
        return out
    }
}

// MARK: - recover 命令

extension Wxkeep.DbKeysCommand {
    struct Recover: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "撤回原文复原：灰条行反查 FTS 全文索引导出被撤回的原始文本（历史全量可用）")

        @Option(name: .long, help: "只复原此时刻之后的灰条（ISO8601 / yyyy-MM-dd HH:mm / epoch 秒）")
        var since: String?
        @Option(name: .long, help: "只复原会话名含此子串的灰条（wxid / 群 ID）")
        var chat: String?
        @Option(name: .long, help: "输出格式：jsonl（默认，机器可读）或 markdown（按会话分组的阅读报告）")
        var format: OutputFormat = .jsonl
        @Option(name: .long, help: "输出路径（默认用户数据目录 recovered/recovered.jsonl 或 .md，0600）")
        var output: String?
        @Option(name: .long, help: "sqlcipher 可执行路径（默认 brew/PATH 探测）")
        var sqlcipher: String?
        @Option(name: .long, help: "终端预览最近 N 条（只出会话/时间/长度，不出内容）")
        var latest: Int = 0
        @Flag(name: .long, help: "把复原原文直接打印到终端（默认只写文件）")
        var stdout = false

        enum OutputFormat: String, CaseIterable, ExpressibleByArgument {
            case jsonl, markdown
        }

        mutating func run() throws {
            guard let exe = Audit.resolveSQLCipher(explicit: sqlcipher) else {
                throw CleanExit.message("未找到 sqlcipher（brew install sqlcipher 或 --sqlcipher 指定）")
            }
            let store = DbKeysFiles.loadStore(url: nil)
            let sinceTS = try Audit.parseTimestamp(since)
            let accounts = WeChatDBFinder.accounts()
            guard !accounts.isEmpty else { throw CleanExit.message("未找到 xwechat_files 账号目录") }

            // 1. FTS session 映射（username → rowid）
            var ftsUser2Sid: [String: Int] = [:]
            var ftsKeyed: [String: (url: URL, key: [UInt8])] = [:]
            for account in accounts {
                guard let fts = WeChatDBFinder.encryptedDBs(account: account, live: true)
                    .first(where: { $0.lastPathComponent == "message_fts.db" }) else { continue }
                guard let page = WeChatDBFinder.page1(of: fts), !WeChatDBFinder.isPlain(page) else { continue }
                let salt = SQLCipherGeometry.saltOfPage1(page: page)
                guard let key = store.keyFor(basename: fts.lastPathComponent, salt: salt, page: page) else { continue }
                ftsKeyed[account] = (fts, key)
                for line in Audit.runSQL(exe, db: fts, key: key,
                                         statements: "SELECT rowid, username FROM name2id;") {
                    let p = line.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false)
                    guard p.count == 2, let sid = Int(p[0]) else { continue }
                    ftsUser2Sid[String(p[1])] = sid
                }
            }
            guard !ftsUser2Sid.isEmpty else {
                throw CleanExit.message("FTS name2id 不可用——先 `wxkeep dbkeys check` 确认密钥")
            }
            print("· FTS 会话映射 \(ftsUser2Sid.count) 项")

            // 2. 灰条收集（原地覆写形态：self/other；xml=78 轮已裁非洞原消息并存，不适用复原）
            struct Tip {
                var username: String
                var sid: Int?
                var localId: Int
                var ts: Int
                var form: RevokeTipClassifier.Form
                var db: String
            }
            var tips: [Tip] = []
            var unknownForm = 0
            for account in accounts {
                let dbs = WeChatDBFinder.encryptedDBs(account: account, live: true)
                    .filter { url in
                        let n = url.lastPathComponent
                        return n.hasPrefix("message_") && !n.contains("fts")
                            && !n.contains("biz") && !n.contains("resource")
                    }
                for db in dbs {
                    guard let page = WeChatDBFinder.page1(of: db), !WeChatDBFinder.isPlain(page) else { continue }
                    let salt = SQLCipherGeometry.saltOfPage1(page: page)
                    guard let key = store.keyFor(basename: db.lastPathComponent, salt: salt, page: page) else {
                        throw CleanExit.message("密钥不可用：\(db.lastPathComponent) — 先 `wxkeep dbkeys check` / `capture`")
                    }
                    let tables = Audit.listMsgTables(db: db, exe: exe, key: key)
                    let names = Audit.nameMap(db: db, exe: exe, key: key)
                    var dbTips = 0
                    for chunk in tables.chunked(into: 400) {
                        for line in Audit.queryTips(db: db, exe: exe, key: key, tables: chunk, since: sinceTS) {
                            let parts = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
                            guard parts.count == 4 else { continue }
                            guard let raw = Audit.hexData(String(parts[3])),
                                  let body = Zstd.decompress(raw) else {
                                unknownForm += 1
                                continue
                            }
                            let form = RevokeTipClassifier.classify(body)
                            guard form == .selfRevoke || form == .otherRevoke else { continue }
                            let username = names[String(parts[0])] ?? String(parts[0])
                            if let chat, !username.contains(chat) { continue }
                            let ts = Int(parts[2]) ?? 0
                            tips.append(Tip(username: username, sid: ftsUser2Sid[username],
                                            localId: Int(parts[1]) ?? 0, ts: ts, form: form,
                                            db: db.lastPathComponent))
                            dbTips += 1
                        }
                    }
                    if dbTips > 0 { print("· \(db.lastPathComponent)：灰条 \(dbTips) 条") }
                }
            }
            print("· 原地覆写灰条（复原候选）\(tips.count) 条（未分类 \(unknownForm)）")

            // 3. FTS 反查（按会话分组批化 ×4 分片）
            var bySid: [(sid: Int, lids: [Int])] = []
            var grouped = Dictionary(grouping: tips.filter { $0.sid != nil }) { $0.sid! }
            for (sid, group) in grouped {
                bySid.append((sid, group.map(\.localId)))
            }
            bySid.sort { $0.sid < $1.sid }
            let batches = RevokeRecovery.ftsQueryBatches(bySid)
            var docs: [Int: [Int: String]] = [:]   // sid → localId → hex(c0)
            var shardNote = ""
            let ftsList = ftsKeyed.values.sorted { $0.url.path < $1.url.path }
            for shard in 0...3 {
                var sawRows = false
                for fts in ftsList {
                    for (i, term) in batches.enumerated() {
                        let sql = "SELECT c4, c1, hex(coalesce(c0,'')) FROM message_fts_v4_\(shard)_content WHERE \(term);"
                        for line in Audit.runSQL(exe, db: fts.url, key: fts.key, statements: sql) {
                            let p = line.split(separator: "|", maxSplits: 2, omittingEmptySubsequences: false)
                            guard p.count == 3, let sid = Int(p[0]), let lid = Int(p[1]) else { continue }
                            if docs[sid] == nil { docs[sid] = [:] }
                            if docs[sid]?[lid] == nil { docs[sid]?[lid] = String(p[2]) }
                            sawRows = true
                        }
                        if i % 40 == 39 { print("·   分片\(shard) 反查 \(i + 1)/\(batches.count) 批") }
                    }
                }
                shardNote += sawRows ? "S\(shard)✓ " : "S\(shard)· "
            }
            print("· FTS 命中分片：\(shardNote)")

            // 4. 会话显示名解析（contact.db：备注 > 昵称 > 微信号）
            var displayNames: [String: String] = [:]
            for account in accounts {
                guard let contact = WeChatDBFinder.encryptedDBs(account: account, live: true)
                    .first(where: { $0.lastPathComponent == "contact.db" }) else { continue }
                guard let page = WeChatDBFinder.page1(of: contact), !WeChatDBFinder.isPlain(page) else { continue }
                let salt = SQLCipherGeometry.saltOfPage1(page: page)
                guard let key = store.keyFor(basename: contact.lastPathComponent, salt: salt, page: page) else { continue }
                for line in Audit.runSQL(exe, db: contact, key: key,
                                         statements: "SELECT username, coalesce(remark,''), coalesce(nick_name,''), coalesce(alias,'') FROM contact;") {
                    let p = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
                    guard p.count == 4 else { continue }
                    let username = String(p[0])
                    displayNames[username] = RevokeRecovery.displayName(
                        remark: String(p[1]), nickName: String(p[2]),
                        alias: String(p[3]), username: username)
                }
            }
            print("· 会话名映射 \(displayNames.count) 项")

            // 5. 复原判定与导出
            var records: [RevokeRecovery.RecoveredRecord] = []
            var absent = 0, synced = 0, undecodable = 0
            for t in tips {
                guard let sid = t.sid, let hex = docs[sid]?[t.localId] else { absent += 1; continue }
                guard let text = RevokeRecovery.decodeDocument(hex) else { undecodable += 1; continue }
                if RevokeRecovery.isTipDocument(text) { synced += 1; continue }
                let resolved = displayNames[t.username]
                records.append(RevokeRecovery.RecoveredRecord(
                    chat: t.username, name: (resolved != nil && resolved != t.username) ? resolved : nil,
                    time: t.ts, form: t.form.rawValue,
                    localId: t.localId, db: t.db, length: text.utf8.count, text: text))
            }
            records.sort { $0.time < $1.time }
            let named = records.filter { $0.name != nil }.count

            let ext = format == .markdown ? "md" : "jsonl"
            let outURL = output.map { URL(fileURLWithPath: $0) }
                ?? Config.userDataURL.appendingPathComponent("recovered/recovered.\(ext)")
            try FileManager.default.createDirectory(
                at: outURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let payload: Data
            switch format {
            case .jsonl:
                let enc = JSONEncoder()
                enc.outputFormatting = [.sortedKeys]
                var data = Data()
                for r in records {
                    data.append(try enc.encode(r))
                    data.append(Data("\n".utf8))
                }
                payload = data
            case .markdown:
                payload = Data(RevokeRecovery.renderMarkdown(records: records, generatedAt: Date()).utf8)
            }
            try SafeWrite.overwrite(payload, to: outURL)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outURL.path)

            print("复原结果：成功=\(records.count)（含显示名 \(named)）无 FTS 文档（非文本原文为主）=\(absent) 文档不可解码=\(undecodable) 被同步覆盖=\(synced)")
            print("输出：\(outURL.path)（0600，含聊天内容——注意保管，勿入仓库）")
            for r in records.suffix(latest).reversed() {
                let label = r.name ?? r.chat
                print("  \(r.time > 0 ? Audit.fmt(r.time) : "?") [\(r.form)] \(label) (\(r.length)B)")
            }
            if stdout {
                for r in records {
                    print("---- \(Audit.fmt(max(r.time, 0))) [\(r.form)] \(r.name ?? r.chat)")
                    print(r.text)
                }
            }
        }
    }
}
