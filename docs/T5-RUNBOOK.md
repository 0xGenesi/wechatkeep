# T5 真机验证执行手册（77 续㉔，2026-10-28）

> 目的：arm64 runtime hook 的真机语义验证（队列第 1 项）——渲染影响判定、
> keep_message/自定义 tip 语义确认、群聊自定义提示终验。前置 = 用户一次
> 微信窗口（预计 30-45 分钟）。本文把 ⑰-㉓ 的全部静态产出收敛为可执行
> 单据；窗口内只做采集与判读，不做即席决策。

## Phase 0 — 前置检查（窗口前完成）

1. `sw_vers` + 微信 build 确认（`wxkeep versions`；当前适配基线 270100/270135）。
2. `python3 tools/launch_soak.py --seconds 45` 全绿（发版门同款）。
3. 捕获索引（附录 A）在档确认——本轮新采集沿用 `var/wxarm/dT5_*.xml` 命名。
4. 微信完全退出；日常微信与副本微信的区分（soak 隔离区口径）。

## Phase 1 — 基线安装与真实撤回（约 10 分钟）

1. `wxkeep runtime install && wxkeep runtime status`——预期 hook 武装
  （mr2=hook-armed，status=8；若 func-id-mismatch → 见归因表 R6）。
2. 启动微信，等 30s（boot log late20s 行落盘）。
3. **私聊**对方撤回一条文字消息 → 30s 内采集：
   - `wxkeep runtime status`（fires/hits/zero 计数）
   - `~/Library/Containers/com.tencent.xinWeChat/Data/tmp/wxkeep-boot.log` 尾部
   - 截图（tip 显示形态 + 原消息是否保留）
4. **群聊**同上一次。

**判据**：zero>0（newmsgid 清零发生）+ 原消息保留 + tip 显示 + 渲染正常
→ keep_message/tip 语义修复**真机关账**，跳 Phase 4。渲染破坏 → Phase 2。

## Phase 2 — config 键级二分（约 10 分钟，无需重编译）

现有配置键即可拆分「改写动作」与「hook 存在」两个变量：

| 步骤 | runtime.json | 隔离变量 | 预期采集 |
|---|---|---|---|
| 2a | `keep_message=false`（tip_text 保留） | 只 tip 改写 | 同 Phase 1 |
| 2b | `tip_text` 清空（`wxkeep runtime tip --clear`，keep_message=true） | 只 newmsgid 清零 | 同 Phase 1 |
| 2c | 两者都关 | **纯武装 no-op** | 同 Phase 1 |

每步重启微信生效。2c 若仍破坏渲染 → hook 存在本身即机制 → Phase 3。

## Phase 3 — 安装级二分（约 10 分钟，**变体已预构建**）

候选③（安装机械动作×宿主完整性，⑪ 登记）的二分。两个变体 dylib 已
预构建并二进制级验证（var/t5/，77 续㉕）：

- **变体 A** `var/t5/libwxkeep_runtime_T5A_cow_only.dylib`
  （只 COW 不挂 stub——`write_entry_stub` 入口即返，实锚 `mov w0,#0; ret`
  @0x3848）：`wxkeep runtime install --dylib var/t5/libwxkeep_runtime_T5A_cow_only.dylib`
  ——渲染破坏消失 → 机制=stub 写入路径；
- **变体 B** `var/t5/libwxkeep_runtime_T5B_stub_nocow.dylib`
  （只挂 stub 不 COW——vm_remap 块编译期删除（`nm -u` 零引用），mprotect
  直写在 macOS 27 预期 EACCES 拒装=kStInstallFail）：`wxkeep runtime install
  --dylib var/t5/libwxkeep_runtime_T5B_stub_nocow.dylib`——**拒装即归因
  COW 必要性**（归因表 R5），渲染自然正常。

每个变体装后重启微信采集同 Phase 1；**换回正式件** =
`wxkeep runtime install`（默认搜索序回 BASE）。两变体均不破坏 → 机制在
hook 执行面（回到 Phase 2 深化）。重建变体：源级补丁见
/var/t5 生成脚本口径（write_entry_stub 入口 return 0 / mprotect 失败直连），
`swift build -c release` 后还原 runtime.m。

## Phase 4 — 群聊自定义提示终验（约 10 分钟）

前置：Phase 1 渲染正常。`wxkeep runtime tip '"⚠️" 撤回了一条消息'`。

1. 群聊对方撤回 → 采集同 Phase 1。**预期**：tip 显示自定义文案（服务端
   replacemsg 载荷在改写面内，㉓ 数据层已证）。
2. `{from}` 形态一次（`"{from}" 撤回了一条消息`）。

**判据**：群聊渲染自定义文案 = 群聊自定义提示**全链关账**（含「全生态
未解」旧判断的正式废止）。渲染 Unsupported 占位 → 采集 boot log inner=
字段（原始内文快照）+ 截图，归因表 R7。

## 归因表

| 编号 | 症状 | 归因 | 动作 |
|---|---|---|---|
| R1 | zero>0、消息保留、tip 正常、渲染正常 | 全链 ✓ | Phase 4 → 关账 |
| R2 | 渲染破坏，2c no-op 也破坏 | hook 存在=机制（候选③域） | Phase 3 |
| R3 | 渲染破坏，仅 2a（只 tip）破坏 | 改写路径×渲染校验 | 采 inner= 快照，评 canonical 形态 |
| R4 | 渲染破坏，仅 2b（只清零）破坏 | newmsgid 清零×下游 | 对照 ⑰ 单键裁决复核 |
| R5 | 变体 B 拒装（EACCES） | COW 必要性实锤 | 记录，回到变体 A |
| R6 | func-id-mismatch 拒装 | 自更新换函数（预期防护） | `runtime hooks` 刷新后重试 |
| R7 | tip 显示 Unsupported 占位 | 渲染校验拒绝非服务端原文 | 采 inner= + 群/私对照，评 qm 表消费路径 |

## 退出准则

- R1 + Phase 4 通过 → 队列第 1 项关账，arm64 语义修复升级为「真机验证」，
  群聊自定义提示关账；下一版 release notes 移除「诚实边界」段。
- 任何 R2-R5 → 按归因入 RUNTIME-DESIGN 候选表，机制收窄一轮；不阻塞
  keep_message 在 x64 的既有语义。

## 附录 A — 实弹捕获索引（⑳ 教训落地）

| 文件 | 形态 | 要点 |
|---|---|---|
| var/wxarm/d27_parse_*.xml（×2） | GROUP | replacemsg+newmsgid+msgid+session |
| var/wxarm/d29_parse_*.xml（×6） | GROUP×4 / priv×2 | 两形态并存首证 |
| var/wxarm/d32_parse_*.xml（×4） | GROUP×2 / priv×2 | 同上 |
| var/wxarm/d34_parse_*.xml（×4） | GROUP×2 / priv×2 | ㉓ 群聊裁决引用 |
| ~/Library/Containers/com.tencent.xinWeChat/Data/tmp/wxkeep-boot.log | 动态 | T4 时代全轨迹（enter/done/late20s/tick） |
| var/logs/launch-soak-*.txt | 动态 | 浸泡台账（最新 20261027-210545） |
| var/HANDOFF-2026102{4,5}.md | 文档 | T4 实验交接 |

捕获形态学（16/16 零例外）：**群=replacemsg+newmsgid+msgid+session；私
=content 单元素**——runtime.m 双标签改写序（content→replacemsg）与之
完全吻合。
