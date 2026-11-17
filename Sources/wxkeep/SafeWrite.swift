import Foundation

/// 对既有文件（特别是可执行文件）的整体覆写：原子替换 + 权限保留。
///
/// 两个翻车模式，各对应一个参数：
/// - **撕裂写**：非原子 `Data.write(to:)` 是原位 truncate+write——中途
///   崩溃/断电留下半文件。对 wechat 主可执行这就是「微信无法启动」，备份
///   虽在但需要用户手工恢复。`.atomic` 走 temp+rename，rename 原子。
/// - **权限丢失**：`.atomic` 的替换文件是默认权限（0644）——原文件的
///   可执行位不随 rename 存活。覆写前快照 posixPermissions、覆写后回写，
///   否则「修好了撕裂写、引入了无执行位」——同一个症状（启动不了）换了个来源。
///
/// 局部偏移写（Patcher 的 FileHandle 定点补丁）不适用此路：定点写不搬
/// 全文件，撕裂面天然只有补丁字节自身，由备份 + verify-after-write 承担。
enum SafeWrite {
    /// Atomic overwrite of `url`, restoring the original file's posix
    /// permissions afterward. Missing file → created with default perms.
    /// 权限回写失败如实抛出（110 轮修）：`try?` 吞掉 = 「修好了撕裂写、
    /// 引入了无执行位」——正是本类型头注释自称要防的症状；调用方
    /// （journal/备份链）都承接 throws。
    ///
    /// `sync`（135 轮体检 P3-6）：写后 fsync 一次（文件数据级）。WAL 的
    /// 「意图先于写入持久」前提要求 journal 落盘真正持久——无 fsync 时
    /// journal 收口（删除）与补丁字节的落盘顺序在断电下不受控。journal
    /// 是小文件，代价趋零；340MB 级二进制不走此参（V6 §6 已登记边界）。
    /// fsync 失败如实抛（调用方都承接 throws）。
    static func overwrite(_ data: Data, to url: URL, sync: Bool = false,
                          permissions: Int? = nil) throws {
        let fm = FileManager.default
        let perms = permissions ?? ((try? fm.attributesOfItem(atPath: url.path)[.posixPermissions]) as? NSNumber)?
            .intValue
        // 142 P2（机密件面）：显式 permissions 走「权限先于 rename」——旧序
        // （atomic rename → setAttributes）在 rename 与 chmod 之间进程死亡时
        // 把机密留 0644（dbkeys.json = 全部聊天库解密密钥；124 轮 hits 文件
        // 同课已修、本文件当时漏改）。唯一名临时件：撕裂面只伤 tmp。
        if let perms, permissions != nil {
            let tmp = url.deletingLastPathComponent()
                .appendingPathComponent(".wxkeep-ov-\(UUID().uuidString)")
            try data.write(to: tmp, options: .atomic)
            try fm.setAttributes([.posixPermissions: perms], ofItemAtPath: tmp.path)
            if sync { try fsyncDeep(tmp) }
            guard rename(tmp.path, url.path) == 0 else {
                try? fm.removeItem(at: tmp)
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno),
                              userInfo: [NSLocalizedDescriptionKey:
                                "rename → \(url.path) 失败: \(String(cString: strerror(errno)))"])
            }
            return
        }
        try data.write(to: url, options: .atomic)
        if let perms {
            try fm.setAttributes([.posixPermissions: perms], ofItemAtPath: url.path)
        }
        if sync { try fsyncDeep(url) }
    }

    /// 142 P3：F_FULLFSYNC（macOS fsync 不刷盘缓存）+ 父目录 entry 刷盘
    /// ——journal「意图先于写入持久」前提的 Durability 收口。F_FULLFSYNC
    /// 不可用（异常内核）回落 fsync；父目录刷盘 best-effort。
    private static func fsyncDeep(_ url: URL) throws {
        let fh = try FileHandle(forWritingTo: url)
        defer { try? fh.close() }
        if fcntl(fh.fileDescriptor, F_FULLFSYNC) != 0 {
            try fh.synchronize()
        }
        let dirfd = open(url.deletingLastPathComponent().path, O_RDONLY)
        if dirfd >= 0 {
            _ = fcntl(dirfd, F_FULLFSYNC)
            close(dirfd)
        }
    }
}
