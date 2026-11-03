import Foundation

/// per-site 补丁审计清单（125 轮 V5 深度轮）——「写了什么、在哪、依据哪条
/// catalog/recipe 出处」的逐位点台账，落 userData/wxkeep.audit.json。
///
/// 与既有两本账的分工：
/// - PatchJournal（WAL 意图日志）回答「事务是否收口」——begin/complete 之间
///   的残留是中断证据；
/// - Manifest（Ed25519 数据供应链签名）回答「config/signatures 是否被改」；
/// - 本清单回答「字节层最终写了哪些位点」——第三方拿 pristine + patched +
///   本文件三件套即可**零信任离线复算**（tools/audit_patch.py），不需要
///   wxkeep 本身在环。
///
/// 语义边界（如实）：
/// - 只记本事务实际写入的位点（`written` outcome）；变体切换的还原臂
///   （restoreTargets）不接 auditSink，不产生账目——审计语义 =「与 pristine
///   的最终差异」，还原臂的位点回到 pristine 不构成差异；
/// - 重签只动 __LINKEDIT 签名元数据，不在本清单语义内（audit_patch.py 对
///   __LINKEDIT 差异单列报告，不计入位点外写入）；
/// - `before` 是写前实读字节（asm 跨度）——从 pristine 打 = 原始字节；变体
///   切换 = 上一变体的补丁字节（离线复算时按 expected 变体族对照）。
///
/// 生命周期：patch 事务成功（含重签确认）后写入；restore 到 pristine 成功
/// 后清除（幂等无抛——与 PatchJournal.complete 同哲学：账本层的失败最坏是
/// doctor 多报一行，不得让已成功的字节事务报错）。
enum PatchAudit {
    struct Site: Codable, Equatable {
        /// bundle 相对路径（与 record.app 配对解析到具体二进制）。
        let binary: String
        let arch: String
        let identifier: String
        /// hex VA（catalog 口径，与 Config.PatchEntry.addr 同形）。
        let va: String
        /// 写前实读字节（asm 跨度），hex。
        let before: String
        /// 写入字节（asm），hex。
        let after: String
        /// catalog/recipe 出处（Config.PatchEntry.source 透传）。
        let source: String?
    }

    struct Record: Codable, Equatable {
        let v: Int           // schema 版本（字段演进用）
        let build: String
        let variant: String?
        let app: String      // 账目作用的 app bundle 路径（跨 app 不越权对账）
        let completedAt: String
        let sites: [Site]
    }

    static let fileName = "wxkeep.audit.json"

    /// 落点与 PatchJournal 同域（userData：root 写 / 用户读不受 /Applications
    /// 权限影响；`userData` 仅测试注入，与 PatchJournal.url 同缝）。
    static func url(userData: URL? = nil) -> URL {
        (userData ?? Config.userDataURL).appendingPathComponent(fileName)
    }

    static func write(record: Record, userData: URL? = nil) throws {
        try SafeWrite.overwrite(try JSONEncoder().encode(record), to: url(userData: userData))
    }

    /// restore 成功收口：清账（幂等无抛）。
    static func clear(userData: URL? = nil) {
        try? FileManager.default.removeItem(at: url(userData: userData))
    }

    /// 账本合并（126 轮 B6：`--only`/部分重跑的覆盖语义曾丢 alreadyPatched
    /// 位点——「先 --only update 再全量」会把 update 位点挤出账本 = 离线
    /// 复算假红 + doctor 对账面残缺）。规则：
    /// - 旧账 app 或 build 不匹配（微信自更新/跨 app）→ 丢弃旧账（其字节
    ///   已随更新消失，留键 = 假 stale；跨 app 与 journal 同哲学：新事务
    ///   的意图即当前事实）；
    /// - 匹配 → 先按 (binary,arch,va) 删除本次**还原**的键（undo 臂撤回的
    ///   位点 bytes==pristine，留键 = doctor 假 stale），再 upsert 本次
    ///   **写入**的键（先删后增：归一化共享位点「还原后重写」安全）。
    /// 输出按键稳定排序（离线复算/测试可复现）。
    static func mergedRecord(previous: Record?, build: String, variant: String?,
                             app: String, written: [Site], restored: [Site]) -> Record {
        let now = ISO8601DateFormatter().string(from: Date())
        func key(_ s: Site) -> String { "\(s.binary)|\(s.arch)|\(s.va)" }
        guard let prev = previous, prev.app == app, prev.build == build else {
            return Record(v: 1, build: build, variant: variant, app: app,
                          completedAt: now, sites: written.sorted { key($0) < key($1) })
        }
        let restoredKeys = Set(restored.map(key))
        var byKey: [String: Site] = [:]
        for s in prev.sites where !restoredKeys.contains(key(s)) {
            byKey[key(s)] = s
        }
        for s in written { byKey[key(s)] = s }
        let sites = byKey.values.sorted { key($0) < key($1) }
        return Record(v: 1, build: build, variant: variant, app: app,
                      completedAt: now, sites: sites)
    }

    /// doctor / 离线审计读取。文件在但不可解码 → (true, nil)：在场本身就是
    /// 「有一笔未对账写入」的证据（与 PatchJournal.pending 同判读哲学——
    /// 坏 JSON 不能把检测静默吞掉）。
    static func pending(userData: URL? = nil) -> (exists: Bool, record: Record?) {
        let target = url(userData: userData)
        guard FileManager.default.fileExists(atPath: target.path) else {
            return (false, nil)
        }
        guard let data = try? Data(contentsOf: target),
              let record = try? JSONDecoder().decode(Record.self, from: data) else {
            return (true, nil)
        }
        return (true, record)
    }
}
