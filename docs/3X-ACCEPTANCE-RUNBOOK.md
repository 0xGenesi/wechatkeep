# 3.x 真机行为验收 Runbook（用户窗口项，83 轮起唯一在册 3.x 项）

> 前置：静态面已全绿（83/84 轮：16 构建 × revoke/keeptip/update × 双架构
> 引擎往返 84 组 ALL PASS + L1 + Rev3xLineageTests 谱系锁）。本 runbook
> 只补**行为级**——需要真登录 + 真撤回事件，机器不可替代。

## 0. 准备

- 选构建：建议 **3.8.10.17（28632）**（Rodert 归档有源；谱系最后一员）。
  dmg：zsbai `3.8.10.17` tag 或 Rodert 归档（MAINTAINING「官方 CDN 归档」节）。
- **数据隔离警告**：3.x 与 4.x 数据格式不同。**不要覆盖登录现有 4.x 数据**——
  把 /Applications/WeChat.app 改名备份（`mv WeChat.app WeChat4.bak.app`），
  装 3.x dmg；验收完还原。聊天记录用小号或空白环境（3.x 登录不影响 4.x
  账号本身，但本地数据目录分开）。
- 机器已验：doctor 应报 build 28632 / catalog matched。

## 1. patch 三域 + 行为级 verify

    sudo wxkeep patch --variant keeptip   # revoke/keeptip/update 三域自动附带
    wxkeep verify                          # 行为级（out-of-process worker）

预期：3.x 条目为 ObjC bare-ret 形（入口/执行体各一代际），verify 走
macOS-arm64 分支（3.x 双架构含 arm64）。

## 2. 撤回行为矩阵（人工事件，每格一条消息即可）

| # | 事件 | 预期（keeptip） | 预期（silent 对照，可跳过） |
|---|---|---|---|
| 1 | 对方撤回私聊文本 | 消息保留 + 灰条 tip「…撤回了一条消息」 | 消息保留、无 tip |
| 2 | 对方撤回群聊文本 | 同上（群聊口径） | 同上 |
| 3 | 自己撤回自己消息 | **保留**（已知边界：静态裸 ret 不区分自发/他发） | 同 |
| 4 | 拍一拍撤回（如有） | 保留（同边界） | 同 |
| 5 | 撤回图片/语音 | 保留 + tip | 保留 |

已知边界（83 轮入档）：自撤自留 + 拍一拍保留——这是入口/执行体裸 ret
设计的诚实边界，不是缺陷。

## 3. update 面核对

- 「关于微信」手动检查更新 → 应无升级弹窗动作（MMUpdateMgr 三方法
  bare-ret 屏蔽调度；Sparkle 本体在独立 framework 属主侧不可触达，调度
  入口已断）。

## 4. 多开核对（89 轮裁决：3.x 原生支持）

    open -n /Applications/WeChat.app    # 应可直接第二实例，无需补丁

## 5. 收尾

    sudo wxkeep restore                   # 或直接重装 4.x dmg
    mv /Applications/WeChat4.bak.app /Applications/WeChat.app
    wxkeep doctor                         # 应回 4.x build / protected

## 6. 结果登记

验收结果（哪格不符/截图）贴回 wxkeep 仓库 issue 或直接告知，登记入
ROADMAP 3.x 行——16 构建谱系的行为级背书自此闭环。
