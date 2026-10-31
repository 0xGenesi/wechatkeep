import Foundation

/// sudo 语境的「真实用户」锚定。
///
/// Foundation 的家目录解析按进程 euid——`sudo wxkeep patch` 下
/// urls(for:)/NSHomeDirectory()/homeDirectoryForCurrentUser 全部落
/// /var/root。而本工具的日常形态恰恰是 sudo 写 /Applications（doctor
/// 的指引也是这么给的）：journal/备份/hooks 表/tip 配置/update-data
/// 安装位若跟着 euid 走 root 家，普通用户随后跑 doctor/status 一片盲
/// （WAL 检测链在最需要它的 sudo 补丁流上断裂，98 轮双路径面教训的
/// euid 维度补全）。defaults 写侧已有 launchctl asuser 委托
/// （UpdateGuard/PrivacyGuard），文件路径面在此对齐。
enum RealUser {
    /// 真实登录用户的家目录：root 且带 SUDO_USER 时取 passwd 记录的
    /// 家目录；其余（普通用户／无 SUDO_USER 的 root）按进程当前家目录
    /// 原样（行为与既有路径无差）。
    static func homeURL() -> URL {
        if geteuid() == 0,
           let sudoUser = getenv("SUDO_USER"),
           let pw = getpwnam(sudoUser),
           let dir = pw.pointee.pw_dir, dir.pointee != 0 {
            let path = String(cString: dir)
            if path.hasPrefix("/") {
                return URL(fileURLWithPath: path, isDirectory: true)
            }
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    /// root 写用户空间后把所有权交还真实用户。必要性在 Group 容器位：
    /// dylib 以微信用户身份回写 marker——root 属主目录会让它的写被拒，
    /// `runtime status` 的证据链断（fires/zero 永远空）。非 root 直跑
    /// 无操作；chown 失败静默（后续用户写失败时报错路径仍真实）。
    static func chownToRealUser(_ url: URL) {
        guard geteuid() == 0, let raw = getenv("SUDO_USER") else { return }
        let sudoUser = String(cString: raw)
        guard !sudoUser.isEmpty else { return }
        _ = Shell.run("/usr/bin/chown", ["-R", sudoUser, url.path])
    }
}

/// 路径小工具：引号传入的 `~/…` 不展开是 CLI 常见坑（shell 只对未引号
/// 形式展开）。--app/--config/--signatures 已各自处理（100 轮），此处
/// 提供单点实现供其余选项（--dylib/--sqlcipher/--keys/--output/--dir）
/// 收敛，语义与 `(s as NSString).expandingTildeInPath` 一致。
enum PathUtil {
    static func expandTilde(_ s: String) -> String {
        (s as NSString).expandingTildeInPath
    }

    static func expandTilde(_ s: String?) -> String? {
        s.map { ($0 as NSString).expandingTildeInPath }
    }
}
