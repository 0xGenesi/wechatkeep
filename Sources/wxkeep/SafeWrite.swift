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
    static func overwrite(_ data: Data, to url: URL) throws {
        let fm = FileManager.default
        let perms = ((try? fm.attributesOfItem(atPath: url.path)[.posixPermissions]) as? NSNumber)?
            .intValue
        try data.write(to: url, options: .atomic)
        if let perms {
            try? fm.setAttributes([.posixPermissions: perms], ofItemAtPath: url.path)
        }
    }
}
