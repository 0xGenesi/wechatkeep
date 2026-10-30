# WeChatKeep (wxkeep)

macOS 微信 4.x **双架构（Apple Silicon + Intel x86_64）**防撤回工具链。

安全第一：**expected 原始字节门 → 全量写前预检 → 自动备份 → 幂等 restore → entitlements 保留重签 → strict verify → 行为级验证**，任何一环失败宁可不写。

## 安装

```bash
brew install 0xGenesi/tap/wxkeep
wxkeep update-data   # 拉取最新补丁数据（brew 安装的 catalog 随发版冻结；此命令 day-0 跟进新构建）
```

或从 [Releases](https://github.com/0xGenesi/wechatkeep/releases) 下载单文件（universal，约 2.4MB）。

## 功能

- **防撤回**（silent / keeptip 双架构）——撤回的消息留在聊天里；keeptip 在私聊保留撤回提示（x64 群聊提示为已知限制；旧实验变体 keeptip2 已废弃移除）。覆盖 4.1.13 全线（269573-269632 已知构建）+ 4.1.15 全家族（270084-270100 公开段 + 270133-270135＝4.1.15.53-.55，2026-10-14 派生轮）双架构
- **行为验证**——`verify` 拉补丁函数出进程直接调用，机器证明有效（x64 探针=补丁后的 isRevokemsg 本体；arm64 探针=喂值给 cbz 分支的独立谓词，家族完整性+输入路径自检，补丁效果由 strict verify 字节级证明承担）
- **更新防护**（偏好层，best-effort）——`SUEnableAutomaticChecks/SUAutomaticallyUpdate/SUSendProfileInfo` 三开关（patch 时自动附带）。诚实边界：微信 4.1.13+ 启动时会把前两键改回「开」（社区+本机实证），`SUSendProfileInfo` 可长期存活；被改回时 `doctor`/`update-guard status` 会明确提示。**二进制级 update 目标**（XAppUpdateManager 四方法+访问器对全套 8 点，双架构同构覆盖 4.1.13 全线 + 4.1.15 全家族；270100 真机行为验证；269602 为纯 C++ 更新器时代，双架构周期工人→ret 单点）
- **隐私加固**——遥测/诊断/埋点上报最小化（`privacy-guard`）
- **多开（克隆式）**——独立数据目录的第二/第 N 个微信，与构建号无关（`clone create`）
- **体检**——`doctor` 含 AMFI 观察级提示与精确修复指引
- **运行时组件（可选，默认不装）**——`runtime install` 注入支持 dylib：自定义撤回提示文案（支持 `{from}` 占位符；自发撤回默认不改写，`rewrite_self` 可开）。hook 地址表走 runtime.json 数据通道，新构建 day-0 生效

## 快速上手

```bash
wxkeep doctor          # 体检：AMFI/taskgated 杀机预测 + 补丁状态 + 精确下一步命令
sudo wxkeep patch      # 打补丁（自动备份→打点→重签→strict verify，附带更新防护+隐私加固）
wxkeep verify          # ★ 行为级证明：拉补丁函数出进程直接调用（无需真机撤回测试）
wxkeep restore         # 全量还原（幂等）
wxkeep versions        # 已装构建号 + catalog
wxkeep locate          # 未知构建号：签名配方自动定位

wxkeep clone create    # 多开：创建独立数据的第二微信
wxkeep clone list      #   列出 / launch 1 启动 / remove 1 删除
wxkeep privacy-guard --action status  # 隐私：查看遥测/上报状态
wxkeep update-guard --action status   # 更新防护状态
```

## 运行时组件（可选）

在字节补丁之上注入支持 dylib，提供**自定义撤回提示文案**（字节补丁给不了的运行时能力）：

```bash
wxkeep runtime install   # 注入（要求微信退出；brew 安装自带 dylib，源码用户先 swift build -c release）
wxkeep runtime status    # 状态：注入/dylib/地址表/文案/hook 武装 + fires/hits/zero 证据计数
wxkeep runtime hooks     # 只刷新地址表（免退出免重签；微信下次启动生效）
wxkeep runtime tip '"⚠️" 撤回了一条消息'   # 设置文案（骨架/长度校验；省略参数=查看当前）
wxkeep runtime remove    # 完整移除（幂等）
```

文案配置在微信 App Group 容器内（`~/Library/Group Containers/5A4RE8SF68.com.tencent.xinWeChat/wxkeep/runtime.json`，XML plist）：
| 键 | 说明 |
|---|---|
| `tip_text` | 自定义文案。**必须保持官方骨架** `"<X>" 撤回了一条消息`（渲染层按此模式匹配，非规范形态显示为 Unsupported 占位；`wxkeep runtime tip` 会强制校验）；`{from}` 占位符展开为撤回者昵称（纯 `"{from}"` 形态展开后与原内文恒等长，最稳）；总长 ≤ 原提示内文（约 31B，超长自动放弃保原文）。推荐：`"⚠️" 撤回了一条消息` |
| `rewrite_self` | `true` 时自发撤回（「你撤回了一条消息」）也改写；默认 false 保持诚实反馈 |

示例：`tip_text = "⚠️" 撤回了一条消息`（实测可渲染形态）。改写是**等长原位替换**（多余长度空格填充），文案长于原提示时放弃保原文；tip/开关类配置 **≤30 秒热生效**（77 续㉘ 双缓冲热重载，无需重启微信；hooks 地址表仍随启动装载）；**自发撤回零干预**（「你撤回」判别门放行原生删除+原生提示，77 续㉘/T5 F1）；hook 按构建 UUID + 入口字节双门匹配，未知构建零作用；11 个构建（270094/097/099/100/101/102/131-135）双架构行另带函数级身份门（func_size 布局指纹）——微信自更新「同 UUID 换函数」时 hook 拒装而非错挂（`runtime status` 诊断位 func-id-mismatch 可见；270100 arm64 曾实测该场景破坏消息渲染，详见 docs/RUNTIME-DESIGN.md）。地址表随 `install` 写入（44 行 = 4.1.15 全家族（除从未发布的 270087/270092）+ 270131-270135 × 双架构），新构建由 `tools/derive_runtime_hooks.py` 产出数据行即生效。**格式约束（实测）**：渲染层按官方骨架 `"…" 撤回了一条消息` 匹配显示，非规范形态会显示为 Unsupported 占位。**群聊**：提示文本由服务端在撤回推送里原文下发（群=replacemsg/私=content，16 条实弹捕获零例外），改写与 keep_message 在群聊数据层同构成立（逆向定案 2026-10-28）；渲染校验终验随 T5 真机验证。

**通用 keeptip（默认开启）**：hook 还会在解析前把撤回 XML 的 `<newmsgid>` 清零——撤回删除按目标查不到，**原消息保留**。runtime 用户无需 keeptip 字节补丁即得「消息保留 + 提示正常显示」（实测消息与灰条提示同时成立）；`keep_message: false` 可关闭。进阶配置：`wxkeep restore` 撤掉 revoke/keeptip 字节补丁 + `wxkeep patch --variant keeptip --only update` 仅保留更新屏蔽——撤回防护完全由 runtime 承担，微信升级后 revoke 域无需重新打点。

## 安全模型

1. **expected 多变体字节门**：写入前逐点校验原始字节（接受 pristine/已打补丁两态），错版/未知修改零写入
2. **全量预检**：所有 target 所有 entry 先验后写，杜绝「打到第 5 个点失败留下半套补丁」
3. **崩溃一致性（WAL journal）**：每次 patch/restore 事务写前落 intent journal、确认成功后收口——中途被杀（SIGKILL/断电，catch 型恢复覆盖不到的路径）后 `doctor` 判定「中断」并给收敛指引（restore 幂等永远安全；字节态完好时降级为 verify 确认；写前失败指回修因重跑；跨 app 残留不劫持本 app 判定）
4. **自动备份**：写入前生成 `<binary>.wxkeep-bak-<ts>`（大小校验）
5. **restore 幂等反演**：`expected[0]` 恒为原始字节；有 target 不可恢复则整体不动
6. **重签五步流水线**：entitlements 快照 → 嵌套先签（注入保命键）→ 根深签 → 漂移恢复（deepest-first）→ strict verify
7. **隔离区**：无 expected 溯源的条目（如上游导入数据）默认拒写——手上有对应构建原版 dylib 可一键回填：`python3 tools/contribute_expected.py /Applications/WeChat.app`
8. **发布清单签名**：`manifest.json`+`manifest.sig`（Ed25519）守护 config/signatures 供应链——篡改过的补丁数据会被 `wxkeep manifest` / doctor 检出并拒载；`python3 tools/contribute_expected.py /Applications/WeChat.app --hashes` 可登记本机构建切片哈希
9. **数据 OTA**：`wxkeep update-data` 从仓库拉取最新已签名 catalog（Ed25519 验签后原子安装到用户目录）——新构建适配 day-0 生效，无需升级工具本体
10. **行为验证**：`verify` 把补丁函数拉出进程调用，证明补丁生效——不再依赖人工撤回测试
11. **深度证据台账**（[docs/V3-DEPTH.md](docs/V3-DEPTH.md)）：L1 地面真值全扫 / L2 可逆性 sha 恒等 / L6 补丁确定性（双副本独立运行恒等，7/7 构建）+ 篡改负控 + 随机化性质测试；`tools/launch_soak.py` 提供补丁后启动浸泡对照实验（隔离副本 + DiagnosticReports 零新增断言）

## 版本兼容

见 [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)（由 `tools/gen_matrix.py` 自动生成，120 个构建号——4.x 全线 + **3.x 主程序时代 16 构建（3.5.5→3.8.10.17）双变体双架构**）。
catalog 未收录的新构建：`wxkeep patch` 会自动跑签名配方定位（配方代不变时 day-0 可用），或显式 `wxkeep locate [--append]`。

## 从源码构建

要求：macOS 13+，Swift 6 工具链（Xcode 或 Command Line Tools；测试使用 swift-testing，无 XCTest 依赖）。

```bash
swift build -c release          # 产出 .build/release/wxkeep
swift test                      # 177 项测试（合成 fixture + 真 codesign 集成 + 解析面模糊/变异测试杀灭套件 + 崩溃一致性/确定性/负控/性质深度门；arm64 行为项在非 arm64 主机自动 skip）
WXKEEP_REAL_DYLIB=/path/to/pristine/wechat.dylib swift test   # + 真实 dylib 全链路（开发机）
```

## 目录

```
Sources/wxkeep/   CLI 与引擎（Patcher/RecipeEngine/Resigner/Doctor/Verifier/…）
config.json       双架构补丁库（条目级溯源：zengtianli/tanranv5/wxkeep-analysis）
signatures.json   定位配方 SSOT（x64 imm64 锚点 + arm64 几何三代 + verify 规格）
tools/            Python 孪生（定位/合并/矩阵，machutil 统一 Mach-O 解析）与 spike 存档
docs/             兼容矩阵 / AMFI 知识 / 方法论 / 逆向发现 / 工具审计记录
.github/          CI（macos-14/15 build+test）+ 新版本追踪流水线
```

## 诚实的限制

- **3.x 主程序时代（3.5.5-3.8.10.17，16 构建）**：撤回链在 ObjC 方法级（非 4.x 的 C++ 谓词）——silent=撤回 sysmsg 入口裸 ret（原消息保留、无灰条、无落库），keeptip=执行体 `DelRevokedMsg:msgData:` 裸 ret（原消息保留+灰条提示并存）。入口选择子四代改名谱系全裁决（FFToNameFavChatZZ→processNewXMLMsg→onRevokeRoomHistory→onSecMsg，`__FUNCTION__` 字面量+xref 双信号验证门）；**update 屏蔽面**=MMUpdateMgr 三方法（onServiceInit 吞 Sparkle 调度+checkForUpdates:+3.8.2 起 startBackgroundUpdatesCheck:，体内 100% update 专属实读）随 patch 附带；引擎级往返 64+32 组全绿；**`wxkeep verify` 行为级可用**——3.x 位点是可调用的方法入口（裸 ret），verify 逐个调用「已打补丁」位点证调用即返回（87 轮；worker 返回类型 UInt8 归一修复裸 ret 垃圾寄存器 UB）。**多开**：3.x 主程序无内建单实例锁（85 轮终裁——already-running 簇两架构死引用、无拦截对话框、无锁原语；4.x 的锁是 4.0.x+ 时代引入），`open -n /Applications/WeChat.app` 原生可多开，无需补丁。**行为差异（vs 4.x）**：静态裸 ret 无法区分自发/他发撤回——自己撤回时自己的视图同样保留原文（对端仍见已撤回）；拍一拍撤回同样被保留。3.x 的 Sparkle 本体在独立 framework（主机侧无法字节触达）——但调度入口 onServiceInit 在主程序，屏蔽面已闭合
- **keeptip 覆盖**：4.1.13 全线 + 4.1.15 全家族双架构对称（revoke-keeptip 每构建 x64+arm64 各 2 点；私聊提示保留，群聊提示为字节路线已知限制——全生态皆然）；silent 双架构全可用
- **二进制级屏蔽更新**：4.1.13 全线 + 4.1.15 全家族双架构同构 8 点（XAppUpdateManager 四方法+访问器对；270100 真机行为验证，其余同构派生+字节级往返）；269602 为纯 C++ 更新器时代（周期工人→ret 双架构单点）；4.1.12 及更老构建的 arm64 8/9 点来自 zengtianli/fzlzjerry 导入。偏好层三开关（`wxkeep update-guard`，patch 时自动附带）在无二进制目标的构建上兜底
- verify 的行为验证双架构可用：worker 在 arm64 走 **MAP_JIT 拆分映射**（EXEC 前缀段=MAP_JIT，数据段=普通 RW 匿名映射紧贴其后——macOS 27 的 W^X 是执行级：写态页不可执行、保护态页不可写且 mprotect 全封，代码数据同区即死锁；2026-10-14 最小探针定案），x64 直接 RWX 映射；写入后 `sys_icache_invalidate` + `np(1)` 回保护态再执行。arm64 执行路径已 CI（macos-15）与 **macOS 27 真机**（270100 装机件四探针全对）双端验收；stock arm64 真机无需 AMFI boot-arg
- **verify spec 按构建变体**（`verify_variants`）：stubs/zero_regions 是绝对 VA、逐构建漂移——legacy spec 覆盖 270099 族，270131-135（当前家族）已各派生双架构变体（arm64 真件端到端 5/5 全绿；x64 走 CI Rosetta 验收）。无变体的构建上 `verify` 优雅跳过并提示（worker 有 stub 形态/越界门；x64 探针条目按配方 asm 匹配，无匹配即跳过；arm64 位点形态不符同样跳过）——补丁效果始终由 strict verify 字节级证明承担，`doctor` / `patch --dry-run` 不受影响。CI 另在 Rosetta 下跑 x86_64 全量测试覆盖 Intel worker 路径
- 78 个隔离条目缺 expected 溯源字节（tanranv5 x64 + zengtianli arm64，全部为 4.1.12 及更老时代构建）——官方 CDN 无归档；zsbai 社区归档虽有其 dmg 但老线资产**系统性源头损坏**（digest 与 GitHub 一致仍 XZ corrupt，2026-09-19 抽样实证），回填源确认为永久缺口
- 运行时组件地址表 = 4.1.15 全家族（除从未发布的 270087/270092）+ 270131-270135 × 双架构 44 行（270101/270102 于 2026-10-20 补齐——CDN 实为在档，旧「无 dmg 工件」结论有误）；M-R2 parse 直挂已实机验证（270100），其余家族行为同构派生（序言门全过，未单独实机验收）
- 270087/270092 与 4.1.13.1-.4、.12-.49 段（含 269602）、4.1.14 整线（2026-10-19 全区间 CDN 扫描定案无归档）官方 CDN 无归档（疑似从未公开发布）——269602 条目已由历史轮次覆盖，其余为目录永久缺口

## 贡献

- 新构建适配优先自动：CI 流水线每日盯官方新版本→自动跑配方→开 PR（人工审核合入）
- 手动适配 SOP 与每代签名的逆向记录：`docs/MAINTAINING.md`
- 补丁数据 AGPL-3.0 继承；条目级溯源（`source` 字段）必须保留

## 致谢

- [sunnyyoung/WeChatTweak](https://github.com/sunnyyoung/WeChatTweak) — 开创（AGPL-3.0）
- [zengtianli/WeChatTweak](https://github.com/zengtianli/WeChatTweak) — 安全设计（expected 门/doctor 契约/重签流水线）与 arm64 catalog
- [tanranv5/WeChatTweak](https://github.com/tanranv5/WeChatTweak) — x86_64 catalog 与适配方法论
- [fzlzjerry/wechat-antirecall](https://github.com/fzlzjerry/wechat-antirecall) — MAINTAINING 审计方法论
- [zsbai/wechat-versions](https://github.com/zsbai/wechat-versions) — 版本归档（追踪流水线数据源）
- [vvanglro/WeChatTweak](https://github.com/vvanglro/WeChatTweak) `feat/wechat-269602-keeptip` — 269602 arm64 条目

AGPL-3.0。仅供学习研究，请遵守微信服务条款；使用后果自负。
