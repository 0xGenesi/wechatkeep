# 生态与安全态势（2026-11-07 全网调研）

> 以专家身份对竞品格局、macOS 安全演进、合规风险做的一轮全网核实。所有 GitHub 事实经 API 直接核对；本文取代 [related-tools-analysis.md](related-tools-analysis.md) 的生态快照（该文档保留为 2026-09/10 历史记录）。

## 1. 微信 macOS 版本动态

- 官网仍主推 4.2.0；**zsbai/wechat-versions 最新归档 4.2.0.17（2026-11-05）**——腾讯在同名 dmg 上以 **1-3 天频率静默换血**（4.2.0.9 → .12 → .16 → .17）。4.1.15 线终止于 4.1.15.55（2026-10 中旬）。
- 版本↔构建映射推断：4.2.0.17 ≈ 270352（本地 11-04 已派生入目）。
- **启示**：4.2.0 线仍在高频滚动，watcher/auto-derive 管道是生命线；按「每 2-3 天一个新 270xxx」的节奏做 day-0 压力预期。

## 2. 同类项目格局（2026-11-07 核实）

| 项目 | 状态 | 覆盖 | 备注 |
|---|---|---|---|
| **本仓 wechatkeep** | 活跃（135 轮） | **4.2.0 线唯一覆盖**（270340+）+ 3.x 16 构建 | 双架构 |
| sunnyyoung/WeChatTweak | **2026-02 起停更** | 3.4x 时代 | 已放弃 dylib 注入、转字节补丁引擎（config.json 与本仓同构） |
| zengtianli/WeChatTweak | 活跃（11-03 push） | 4.1.15 家族（至 270135） | 字节派最活跃 fork；配 GUI WeChatUnrevoke |
| fzlzjerry/wechat-antirecall | 活跃（10-20 push） | 270135（arm64 only） | 增值面：抢红包提醒/撤回日志/关键词/窗口隐私 |
| X1a0He/X1a0HeWeChatPlugin | 活跃（11-06 push） | 270090（注入派） | 注入路线龙头；macOS 27 实测可用 |
| Verlintas/ExtraWeChat | 新（10-27 建） | 270135（arm64 only） | 「补丁副本 + 免 root + SIP 不动」差异化 |
| vvanglro / 0wnerDied / lerry903 等 | 停更 | — | 已落后 |

- **竞争结论**：4.2.0 线（270340+）截至 2026-11-07 仅本仓覆盖，独占窗口约 1-2 周量级。
- tanranv5 账号下已无微信相关仓库（旧线索失效，README 致谢保留为历史贡献记录）。

## 3. macOS 安全演进（对本项目的影响）

- **Rosetta 2 时间线**：macOS 26.4 起 Intel 应用弹警告；**macOS 27 是最后一个完整支持 Rosetta 2 的版本；macOS 28（2027 秋）终结**（仅留旧游戏豁免）。27.0 升级时移除已装 Rosetta，**27.2 起改为保留**（2026-10-26 Apple 发行说明）。
- **启示**：x64（Rosetta）测试与补丁投入的自然寿命 = 2027 秋；27.x 对安装期字节补丁/重签无新增障碍（本机 27.0/27.0.1 全链在役实证）。
- 27 的管控新面（MDM 启动白名单 / TCC 数据库直读禁止 / `tccutil list`）不影响本工具的代码对象操作面。
- frida 17.26.1（2026-11-06）正常发版含 macOS 资产——注入生态在 27 上未系统性失效。

## 4. 微信 4.x 逆向公开研究

- **UnluckyNinja/wechat-decrypt**（MIT，含 macOS）= PyWxDump 方法论的 4.x 迁移：SQLCipher 4（AES-256-CBC + HMAC-SHA512，PBKDF2-SHA512 256,000 迭代，page 4096 / reserve 80），WCDB 进程内存缓存派生 raw key（形态 `x'<64hex key><32hex salt>'`），macOS 用 Mach VM 扫描器（sudo + ad-hoc 重签前提——恰被本工具补丁流程满足）。**参数与本仓 SQLCipher 密钥战役（断点捕获法）实测完全一致**，交叉验证成立。
- 4.x 撤回流程无新的成体系公开文章；公开知识仍散落在各工具仓库提交记录。

## 5. Windows 侧

- **zetaloop/BetterWX**（1.27k★，Unlicense）：v2.1.1（2026-10-27）支持 Windows 微信 4.2.0.9——追踪节奏一周内；生态有 BetterWX-UI、**JasonJarvan/BetterWX-Auto（微信自更新后自动重生补丁）**——与本仓 watcher/auto-PR 同构，其「release 以微信版本号命名」的发行惯例可借鉴。
- ksust/WeChatWindowsHook 仓库已不可达（2026-11-07 核实；不在 DMCA 名单，删除原因未核实）。

## 6. 合规与供应链风险（最重要的一节）

- **PyWxDump**：2025-10-20 收微信官方律师函后删库（9.6k★）。
- **腾讯 GitHub DMCA 战役**（`github/dmca/2026/01/2026-01-08-tencent.md`，原文已核）：以 **DMCA §1201 反规避** 投诉；Exhibit A 列 **29 个仓库，全部是数据库解密/导出/备份类**（wechat-dump-rs、SharpWxDump、WechatBakTool、wechat-decipher-macos 等）；**防撤回补丁类工具无一在列**；因 fork 网 >100，共 4,195 仓库被处理。执行后果不一：有的 HTTP 451、有的作者自删、nalzok/wechat-decipher-macos 至今在线（被列名 ≠ 必被强删）。
- 2025-04 起微信 App 内对「聊天记录管理工具」有警告与打击（SCMP 报道）。无 2026 年针对 macOS 防撤回用户的大规模封号报道（最后确认 2026-11-07）。
- **本仓对策**（已落地）：防撤回补丁面不在当前打击名单，保持；dbkeys/recover 与被下架工具功能重叠——**保持本机自用定位、不做批量导出 UI**（README 已写明）；仓库保持 git 多 remote 迁移预案（参照 wechat-clean 收通知后 1 个工作日删除的时限）。

## 更新纪律

本文是时点快照，竞品状态随时间必然漂移。下一轮全量刷新建议触发条件：微信 4.3 出现 / 本仓竞品出现 4.2.0 线覆盖 / macOS 28 beta 发布（Rosetta 收尾确认）。
