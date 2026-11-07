# WeChatKeep (wxkeep)

[![CI](https://github.com/0xGenesi/wechatkeep/actions/workflows/ci.yml/badge.svg)](https://github.com/0xgenesi/wechatkeep/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey.svg)](#从源码构建)

macOS 微信 3.x/4.x 防撤回工具链，**Apple Silicon + Intel 双架构**，覆盖 123 个构建（4.x 全线 + 3.x 主程序时代 16 构建）。

> 撤回的消息留在聊天里 · 字节级安全补丁 · 每一步写盘都可逆、可审计、可验证

## 功能一览

| 功能 | 命令 | 说明 |
|---|---|---|
| **防撤回** | `sudo wxkeep patch` | 撤回的消息保留在聊天里（silent）；私聊同时保留撤回提示（keeptip）。x64 群聊提示为已知限制 |
| **行为验证** | `wxkeep verify` | 把补丁函数拉出进程直接调用，机器证明补丁有效——无需人工撤回测试 |
| **更新防护** | 随 patch 附带 | 二进制级屏蔽（XAppUpdateManager 8 点）+ 偏好层三开关兜底 |
| **隐私加固** | `wxkeep privacy-guard` | 遥测/诊断/埋点上报最小化 |
| **多开** | `wxkeep clone create` | 独立数据目录的第二/第 N 个微信，与构建号无关 |
| **体检** | `wxkeep doctor` | 补丁状态 + 崩溃报告扫描 + 精确下一步命令 |
| **撤回复原** | `wxkeep dbkeys recover` | 从全文索引（FTS）导出被撤回消息的原文（约半数可复原） |
| **运行时组件**（可选） | `wxkeep runtime install` | 自定义撤回提示文案 · 30 秒热生效 · 通用 keeptip |

## 安装

```bash
# brew 7+ 首次使用第三方 tap 需一次性放行（brew 7.0.11 起默认不信任）：
brew trust 0xGenesi/tap
brew install 0xGenesi/tap/wxkeep   # v0.2.16 起从源码构建（需 Command Line Tools，约几分钟）
wxkeep update-data                 # 拉取最新补丁数据（day-0 跟进新微信构建）
```

或从源码构建：

```bash
git clone https://github.com/0xGenesi/wechatkeep && cd wechatkeep
swift build -c release             # 产出 .build/release/wxkeep（含 wxprobe 探针与 runtime dylib）
```

## 快速上手

```bash
wxkeep doctor          # 先体检：看当前状态与精确下一步
sudo wxkeep patch      # 打补丁（备份→打点→重签→验证，附带更新防护+隐私加固）
wxkeep verify          # 行为级证明补丁生效
wxkeep restore         # 全量还原（幂等，随时可退）
wxkeep versions        # 本机构建号与兼容目录
wxkeep locate          # 未知新构建号：签名配方自动定位

wxkeep clone create    # 多开（list / launch N / remove N）
wxkeep update-guard --action status   # 更新防护状态
wxkeep privacy-guard --action status  # 隐私加固状态
```

## 支持版本

完整双架构清单见 [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)（由 `tools/gen_matrix.py` 自动生成，123 个构建号）。

- **4.x**：4.1.13 全线、4.1.15 全家族、4.2.0 线（270340-270352）——revoke/keeptip/update 三面双架构
- **3.x**（3.5.5-3.8.10.17，16 构建）：silent/keeptip/update 三面双架构（行为差异见[已知限制](#已知限制)）
- **未收录的新构建**：`wxkeep patch` 自动跑签名配方定位（配方代不变时 day-0 可用），或显式 `wxkeep locate [--append]`

## 撤回原文复原

撤回发生时，微信把消息库里的原文原地覆写为灰条提示——但全文索引（FTS）里往往仍留着原文：

```bash
brew install sqlcipher            # 前置
sudo wxkeep patch                 # capture 需要调试权限（get-task-allow）
wxkeep dbkeys capture             # 捕获数据库密钥（会重启微信并要求重新登录）
wxkeep dbkeys recover             # 导出被撤回原文（jsonl，0600 权限）
wxkeep dbkeys audit               # 撤回审计：按会话/联系人统计
```

多账号自动隔离；密钥只落本机（0600）。已知边界：`capture` 固定目标 `/Applications/WeChat.app`；本工具定位为本机自用的撤回审计/复原，不做批量导出面。

## 运行时组件（可选）

在字节补丁之上注入支持 dylib，提供字节补丁给不了的能力：

```bash
wxkeep runtime install   # 注入（要求微信退出）
wxkeep runtime tip '"⚠️" 撤回了一条消息'   # 自定义文案（{from} 占位符可用）
wxkeep runtime status    # 状态与证据计数（fires/hits/zero）
wxkeep runtime hooks     # 只刷新地址表（免退出免重签）
wxkeep runtime remove    # 完整移除（幂等）
```

| 键 | 说明 |
|---|---|
| `tip_text` | 自定义撤回提示文案。须保持官方骨架 `"<X>" 撤回了一条消息`（CLI 强制校验）；`{from}` 展开为撤回者昵称；超长自动放弃保原文。**≤30 秒热生效**，无需重启微信 |
| `keep_message` | **默认 true**：解析前清零撤回 XML 的 `<newmsgid>`——原消息保留 + 提示正常显示，无需 keeptip 字节补丁 |
| `rewrite_self` | 默认 false：自发撤回（「你撤回」）保持原生行为 |
| `clone_message` | 实验特性（默认 false）：消息行克隆共存，详见 [docs/V3-CHARTER.md](docs/V3-CHARTER.md) |

安全设计：hook 按构建 UUID + 入口字节 + 函数布局指纹三重门匹配，未知构建零作用；配置双容器双写，不一致时 `runtime status` 告警。机制细节见 [docs/RUNTIME-DESIGN.md](docs/RUNTIME-DESIGN.md)。

## 安全模型

写入路径七道防线，任何一环失败宁可不写：

```
expected 原始字节门 → 全量写前预检 → WAL journal → 自动备份
    → 幂等 restore → entitlements 保留重签 → strict verify + 行为级验证
```

| 机制 | 一句话 |
|---|---|
| expected 字节门 | 写入前逐点校验原始字节，接受 pristine/已打补丁两态；错版零写入 |
| 全量预检 | 所有位点先验后写，杜绝半套补丁 |
| 崩溃一致性 | 写前 journal（fsync）+ 恢复重签 + 启动清扫；SIGKILL/断电后 `doctor` 精确判读并指路 |
| 自动备份 | 每次写入前落带时间戳备份（大小校验，保留 3 代） |
| 幂等 restore | `expected[0]` 恒为原始字节；不可恢复则整体不动 |
| 重签流水线 | entitlements 快照 → 嵌套先签 → 根浅签 → 漂移恢复 → 复封 → strict verify |
| 供应链 | 补丁数据 Ed25519 清单签名 + 隔离区（无溯源条目拒写）+ `update-data` 验签 OTA |

深度证据体系（崩溃点穷举矩阵 / 指令级结构证明 / per-site 审计对账 / 确定性孪生）见 [docs/FMEA.md](docs/FMEA.md) 与 [docs/V7-DEPTH.md](docs/V7-DEPTH.md)；第三方可离线复算：`tools/audit_patch.py`。

## 从源码构建

要求：macOS 13+，Swift 6 工具链（Xcode 或 Command Line Tools）。

```bash
swift build -c release
swift test                    # 337 项（含真 codesign 集成、模糊/变异测试、崩溃一致性深度门）
WXKEEP_REAL_DYLIB=/path/to/pristine/wechat.dylib swift test   # + 真实 dylib 全链路
```

## 诚实的限制

| 限制 | 详情 |
|---|---|
| keeptip 群聊提示（x64） | 群聊提示文本由服务端下发，字节路线无法改写——全生态皆然；silent 双架构全可用 |
| 3.x 行为差异 | 静态裸 ret 无法区分自发/他发撤回（自己撤回时自己的视图也保留原文）；拍一拍撤回同样被保留。多开无需补丁（3.x 无单实例锁，`open -n` 原生可用） |
| 更新防护（偏好层） | 微信 4.1.13+ 启动时会把 `SUEnableAutomaticChecks/SUAutomaticallyUpdate` 改回「开」；`SUSendProfileInfo` 可长期存活。二进制级 8 点不受影响，被改回时 doctor 明确提示 |
| 74 个隔离条目（28 构建） | 缺 expected 溯源字节，官方 CDN 与社区归档全量穷尽无存档=永久缺口；隔离门按设计拒写，涉及时官方 dmg 重装 |
| 部分 CDN 缺口构建 | 270087/270092、4.1.13.1-.4/.12-.49 段、4.1.14 整线官方从未归档（269602 已由历史条目覆盖） |
| runtime 地址表实机验收 | M-R2 parse 直挂已实机验证（270100）；其余家族行为同构派生（序言门全过，未单独实机验收） |
| dbkeys capture | 固定目标 `/Applications/WeChat.app`（自定义安装位/克隆容器暂不支持） |

## 贡献

- 新构建适配优先自动：CI 流水线每日盯官方新版本 → 自动跑配方 → 开 PR（人工审核合入）
- 手动适配 SOP 与每代签名逆向记录：[docs/MAINTAINING.md](docs/MAINTAINING.md)
- 补丁数据 AGPL-3.0 继承；条目级溯源（`source` 字段）必须保留

## 文档

| 文档 | 内容 |
|---|---|
| [docs/README.md](docs/README.md) | **文档索引**（现行契约 / 方法论 / 历史档案导航） |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | 123 构建双架构兼容矩阵（自动生成） |
| [docs/MAINTAINING.md](docs/MAINTAINING.md) | 维护 SOP：新构建适配、发版、审计方法 |
| [docs/FMEA.md](docs/FMEA.md) | 故障模式登记册：每行 = 模式 × 防线 × 检出 × 测试 |
| [docs/RUNTIME-DESIGN.md](docs/RUNTIME-DESIGN.md) | 运行时组件设计：hook 谱系、身份门、安装链 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 迭代全史（135 轮）与优先级队列 |
| [docs/ECOSYSTEM.md](docs/ECOSYSTEM.md) | 生态与安全态势（2026-11 全网调研） |

## 致谢

- [sunnyyoung/WeChatTweak](https://github.com/sunnyyoung/WeChatTweak) — 开创（AGPL-3.0）
- [zengtianli/WeChatTweak](https://github.com/zengtianli/WeChatTweak) — 安全设计（expected 门/doctor 契约/重签流水线）与 arm64 catalog
- [tanranv5/WeChatTweak](https://github.com/tanranv5/WeChatTweak) — x86_64 catalog 与适配方法论
- [fzlzjerry/wechat-antirecall](https://github.com/fzlzjerry/wechat-antirecall) — MAINTAINING 审计方法论
- [zsbai/wechat-versions](https://github.com/zsbai/wechat-versions) — 版本归档（追踪流水线数据源）
- [vvanglro/WeChatTweak](https://github.com/vvanglro/WeChatTweak) `feat/wechat-269602-keeptip` — 269602 arm64 条目

AGPL-3.0。仅供学习研究，请遵守微信服务条款；使用后果自负。
