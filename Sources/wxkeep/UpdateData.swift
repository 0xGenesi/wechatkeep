import Foundation

/// `wxkeep update-data` — OTA 拉取最新补丁数据（学 fzlzjerry，校验升级为 Ed25519 清单）。
///
/// 数据链：仓库 master 的 config/signatures + CI 签署的 manifest → 本命令
/// 下载到临时目录 → Manifest.verify 必须 .verified（签名+哈希双重）→ 原子安装到
/// 用户级数据目录（Config 搜索路径优先于随包数据）。新构建适配 day-0 生效，
/// 用户无需 brew upgrade 工具本体。
enum UpdateData {
    static let remoteBase = "https://raw.githubusercontent.com/0xGenesi/wechatkeep/master/"
    static let payload = ["config.json", "signatures.json", "manifest.json", "manifest.sig"]

    enum UpdateError: Error, CustomStringConvertible {
        case network(String)
        case notVerified(String)
        case install(String)

        var description: String {
            switch self {
            case .network(let d): return "下载失败：\(d)（检查网络后重试）"
            case .notVerified(let d): return "远端数据未通过签名校验，拒绝安装：\(d)"
            case .install(let d): return "安装失败：\(d)"
            }
        }
    }

    /// 同步拉取+校验+安装。返回 (新目录, 安装前后 catalog 构建数对比)。
    @discardableResult
    static func run(print: (String) -> Void = { Swift.print($0) }) throws -> URL {
        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("wxkeep-update-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workDir) }

        // 1. 下载四件套
        var failures: [String] = []
        var completed: Set<String> = []
        let lock = NSLock()   // URLSession 回调并发到达——共享数组/集合需加锁
        let group = DispatchGroup()
        for rel in payload {
            group.enter()
            let task = URLSession.shared.dataTask(with: URL(string: remoteBase + rel)!) { data, resp, _ in
                defer { group.leave() }
                guard let http = resp as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty else {
                    lock.lock(); failures.append(rel); lock.unlock(); return
                }
                try? data.write(to: workDir.appendingPathComponent(rel))
                lock.lock(); completed.insert(rel); lock.unlock()
            }
            task.resume()
        }
        // 30s 上限：超时后 completed 检查把未完成文件如实报「下载超时」，
        // 不会误报成签名校验失败（残缺文件）。
        _ = group.wait(timeout: .now() + 30)
        if !failures.isEmpty {
            throw UpdateError.network(failures.joined(separator: ", "))
        }
        // 超时未完成的下载如实报网络错误——否则残缺文件会被下面误报成「签名校验失败」
        let missing = payload.filter { !completed.contains($0) }
        if !missing.isEmpty {
            throw UpdateError.network("下载超时（30s）：" + missing.joined(separator: ", "))
        }

        // 2. 签名+哈希双重校验（硬门：不是 .verified 一律拒装）
        switch Manifest.verify(directory: workDir) {
        case .verified: break
        case .legacy: throw UpdateError.notVerified("远端缺 manifest（发布流水线异常）")
        case .invalid(let r): throw UpdateError.notVerified(r)
        }

        // 3. 信息对比（新旧 catalog 规模——只数本次会被替换/安装的**签名目录**
        //    本体，不含 config.local.json 合并条目；否则旧值虚高、增量失真）
        let oldCount = installedCatalogBuildCount()
        let newCount = (try? Config(data: Data(contentsOf: workDir.appendingPathComponent("config.json")),
                                    origin: "remote"))?.versions.count

        // 4. 安装（staging + 逐文件原子 rename + 失败全量回滚）：四件套逐
        // 个 copy 原来有半个安装窗——中途崩会留下「新 config + 旧 manifest」
        // 混合目录，Manifest.verify 判 .invalid 双向硬拒（工具不可用直到
        // 下次 update-data 成功，无网机器就此瘫痪）。改为先全部暂存到目标
        // 目录（同卷 rename 原子），再逐文件换位；中途失败把已换位的旧文
        // 件放回去——旧校验过的完整集存活到新集完全就位。
        let dest = Config.userDataURL
        do {
            try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
            try installStaged(from: workDir, to: dest, payload: payload)
        } catch {
            throw UpdateError.install(error.localizedDescription)
        }

        print("✓ 已安装最新补丁数据 → \(dest.path)")
        if let o = oldCount, let n = newCount {
            print("  catalog 构建：\(o) → \(n)\(n > o ? "（+\(n - o)）" : "")")
        }
        print("  下一步：wxkeep versions / wxkeep doctor 查看新构建支持")
        return dest
    }

    /// update-data 安装目标位上现存目录的构建数（仅签名 config.json 本体，
    /// 不合并 config.local.json——与远端 newCount 同口径）。无目录 = nil。
    static func installedCatalogBuildCount(candidates: [URL]? = nil) -> Int? {
        let urls = candidates ?? [
            Config.userDataURL.appendingPathComponent("config.json"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath + "/config.json"),
        ]
        for url in urls where FileManager.default.fileExists(atPath: url.path) {
            if let data = try? Data(contentsOf: url),
               let config = try? Config(data: data, origin: url.path) {
                return config.versions.count
            }
            return nil   // 存在但不可解析：如实报「读不出」而非跳到下一个
        }
        return nil
    }

    // MARK: - staging 换位安装

    struct StagedItem {
        let stage: URL
        let final: URL
        let backup: URL      // 旧文件换位暂存（final 原不存在时 backup 也不存在）
    }

    /// 四件套两阶段换位：阶段一把全部 payload 拷进 dest 同卷暂存名（此时
    /// 既有安装集一字未动）；阶段二 applySwaps 逐文件 rename 换位。
    static func installStaged(from workDir: URL, to dest: URL,
                              payload: [String] = UpdateData.payload) throws {
        var staged: [StagedItem] = []
        do {
            for rel in payload {
                let final = dest.appendingPathComponent(rel)
                let stage = dest.appendingPathComponent(".staging-" + rel)
                if FileManager.default.fileExists(atPath: stage.path) {
                    try FileManager.default.removeItem(at: stage)
                }
                try FileManager.default.copyItem(at: workDir.appendingPathComponent(rel), to: stage)
                staged.append(StagedItem(
                    stage: stage, final: final,
                    backup: dest.appendingPathComponent(".bak-" + rel)))
            }
        } catch {
            for item in staged { try? FileManager.default.removeItem(at: item.stage) }
            throw error
        }
        try applySwaps(staged)
    }

    /// 换位阶段：逐文件 rename（同卷原子，换位窗=单文件 rename 微秒级）。
    /// 任何一步失败：已换位的回滚到旧文件、当前文件若已移入 backup 也放
    /// 回——目录停在「完整旧集」。internal 供测试直接驱动回滚路径。
    static func applySwaps(_ staged: [StagedItem]) throws {
        var swapped: [(StagedItem, hadOld: Bool)] = []
        do {
            for item in staged {
                var hadOld = false
                if FileManager.default.fileExists(atPath: item.final.path) {
                    if FileManager.default.fileExists(atPath: item.backup.path) {
                        try FileManager.default.removeItem(at: item.backup)
                    }
                    try FileManager.default.moveItem(at: item.final, to: item.backup)
                    hadOld = true
                }
                do {
                    try FileManager.default.moveItem(at: item.stage, to: item.final)
                    swapped.append((item, hadOld))
                } catch {
                    // 换位失败：旧文件还在 backup 位，先放回去再抛
                    if hadOld {
                        try? FileManager.default.moveItem(at: item.backup, to: item.final)
                    }
                    throw error
                }
            }
        } catch {
            // 回滚全部已换位文件；换位失败的当前文件已在上面处理
            for (item, hadOld) in swapped.reversed() {
                if hadOld {
                    if FileManager.default.fileExists(atPath: item.final.path) {
                        try? FileManager.default.removeItem(at: item.final)
                    }
                    try? FileManager.default.moveItem(at: item.backup, to: item.final)
                } else {
                    try? FileManager.default.removeItem(at: item.final)
                }
            }
            throw error
        }
        // 成功：清暂存备份
        for (item, _) in swapped {
            try? FileManager.default.removeItem(at: item.backup)
        }
    }
}
