import Foundation

/// 写入事务的 write-ahead intent journal（数据库 WAL 思想）。
///
/// 事务边界 = 一次 CLI `patch` / `restore` 调用（字节写入 + 重签是一个
/// 原子语义单元）。`begin` 在引擎获得任何写入机会**之前**落盘，`complete`
/// 只在事务确认成功后调用。进程在窗口内被杀（SIGKILL/断电——catch 型
/// 恢复重签覆盖不到的路径）→ journal 残留 → `doctor` 把「中断事故」从
/// 「mixed 态」里分辨出来，给出精确恢复指引（restore 幂等，永远安全）。
///
/// 写入走 SafeWrite（原子 + 权限保留）：撕裂的 journal 等于没有 journal，
/// 检测能力本身不能有崩溃窗口。`sudo wxkeep patch` 以 root 写入，
/// doctor 以普通用户**只读**——0644 默认权限即可（SafeWrite 语义）。
enum PatchJournal {
    enum Kind: String, Codable { case patch, restore, runtimeInstall, runtimeRemove }

    struct Record: Codable, Equatable {
        let v: Int           // schema 版本（未来字段演进用）
        let kind: Kind
        let build: String
        let variant: String? // patch 专用；restore 为 nil
        let app: String      // 事务作用的 app bundle 路径——doctor 只对同 app 精确指路
        let startedAt: String
        let pid: Int
    }

    static let fileName = "patch.journal.json"

    /// journal 落点：用户数据目录（bundle 外——与主可执行备份同域，
    /// root 写 / 用户读都不受 /Applications 权限影响）。
    /// `userData` 仅测试注入（与 Backup.backupDirectory 同款缝）。
    static func url(userData: URL? = nil) -> URL {
        (userData ?? Config.userDataURL).appendingPathComponent(fileName)
    }

    /// 事务开始：在引擎可能写盘之前调用。原子覆写（上一轮残留同时被
    /// 覆盖——新事务的意图即当前事实）。
    static func begin(kind: Kind, build: String, variant: String?, app: String, userData: URL? = nil) throws {
        let record = Record(
            v: 1, kind: kind, build: build, variant: variant, app: app,
            startedAt: ISO8601DateFormatter().string(from: Date()),
            pid: Int(ProcessInfo.processInfo.processIdentifier))
        let data = try JSONEncoder().encode(record)
        try SafeWrite.overwrite(data, to: url(userData: userData))
    }

    /// 事务确认成功：移除 journal。幂等、无抛（清除失败不得让成功的
    /// patch 报错——最坏情况是下次 doctor 多提示一次，由下次成功事务
    /// 或 restore 收口）。
    static func complete(userData: URL? = nil) {
        try? FileManager.default.removeItem(at: url(userData: userData))
    }

    /// 读取残留事务。文件在但不可解码 → exists=true / record=nil：
    /// journal 在场本身就是「有未确认事务」的证据，坏 JSON（外部篡改/
    /// 磁盘故障）不能把 doctor 的检测静默吞掉。
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
