# WeChatKeep (wxkeep)

macOS 微信 4.x **双架构（Apple Silicon + Intel x86_64）**防撤回工具链。

安全第一：**expected 原始字节门 → 全量写前预检 → 自动备份 → 幂等 restore → entitlements 保留重签 → strict verify → 行为级验证**，任何一环失败宁可不写。

## 安装

```bash
brew install 0xGenesi/tap/wxkeep
```

或从 [Releases](https://github.com/0xGenesi/wechatkeep/releases) 下载单文件（universal，约 2.4MB）。

## 功能

- **防撤回**（silent 双架构 / keeptip arm64+实验x64）——撤回的消息留在聊天里
- **行为验证**——`verify` 拉补丁函数出进程直接调用，机器证明有效
- **更新防护**——不检查更新、不自动安装、关闭更新遥测（patch 时自动附带）
- **隐私加固**——遥测/诊断/埋点上报最小化（`privacy-guard`）
- **多开（克隆式）**——独立数据目录的第二/第 N 个微信，与构建号无关（`clone create`）
- **体检**——`doctor` 含 AMFI 预检与精确修复指引

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

## 安全模型

1. **expected 多变体字节门**：写入前逐点校验原始字节（接受 pristine/已打补丁两态），错版/未知修改零写入
2. **全量预检**：所有 target 所有 entry 先验后写，杜绝「打到第 5 个点失败留下半套补丁」
3. **自动备份**：写入前生成 `<binary>.wxkeep-bak-<ts>`（大小校验）
4. **restore 幂等反演**：`expected[0]` 恒为原始字节；有 target 不可恢复则整体不动
5. **重签五步流水线**：entitlements 快照 → 嵌套先签（注入保命键）→ 根深签 → 漂移恢复（deepest-first）→ strict verify
6. **隔离区**：无 expected 溯源的条目（如上游导入数据）默认拒写——手上有对应构建原版 dylib 可一键回填：`python3 tools/contribute_expected.py /Applications/WeChat.app`
7. **发布清单签名**：`manifest.json`+`manifest.sig`（Ed25519）守护 config/signatures 供应链——篡改过的补丁数据会被 `wxkeep manifest` / doctor 检出并拒载；`python3 tools/contribute_expected.py /Applications/WeChat.app --hashes` 可登记本机构建切片哈希
8. **数据 OTA**：`wxkeep update-data` 从仓库拉取最新已签名 catalog（Ed25519 验签后原子安装到用户目录）——新构建适配 day-0 生效，无需升级工具本体
7. **行为验证**：`verify` 把补丁函数拉出进程调用，证明补丁生效——不再依赖人工撤回测试

## 版本兼容

见 [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)（由 `tools/gen_matrix.py` 自动生成，52 个构建号起步）。
catalog 未收录的新构建：`wxkeep patch` 会自动跑签名配方定位（配方代不变时 day-0 可用），或显式 `wxkeep locate [--append]`。

## 从源码构建

要求：macOS 13+，Swift 6 工具链（Xcode 或 Command Line Tools；测试使用 swift-testing，无 XCTest 依赖）。

```bash
swift build -c release          # 产出 .build/release/wxkeep
swift test                      # 39 项测试（合成 fixture + 真 codesign 集成）
WXKEEP_REAL_DYLIB=/path/to/pristine/wechat.dylib swift test   # + 真实 dylib 全链路（开发机）
```

## 目录

```
Sources/wxkeep/   CLI 与引擎（Patcher/RecipeEngine/Resigner/Doctor/Verifier/…）
config.json       双架构补丁库（条目级溯源：zengtianli/tanranv5/wxkeep-analysis）
signatures.json   定位配方 SSOT（x64 imm64 锚点 + arm64 几何三代 + verify 规格）
tools/            Python 孪生（定位/合并/矩阵）与 spike 存档
docs/             兼容矩阵 / AMFI 知识 / 方法论 / 逆向发现
.github/          CI（macos-14/15 build+test）+ 新版本追踪流水线
```

## 诚实的限制

- **keeptip 仅 arm64**（x64 的 newmsgid 存储点未定位，silent 双架构可用）
- **269602+ 的二进制级屏蔽更新未覆盖**：更新器为纯 C++（见 docs）；已通过 `wxkeep update-guard`（偏好层三开关：不检查更新/不自动安装/关遥测，patch 时自动附带）防护升级弹窗与误升级（两个 slice 均无 XAppUpdateManager），需新一轮字符串锚点逆向（docs/findings-269602-updater.md）
- verify 的行为验证在 SIP 开启的机器上不可用（RWX 映射被禁）；CI 上自动跳过
- tanranv5 来源的 29 个构建条目缺 expected 字节，处于隔离区（补验后放行）

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
