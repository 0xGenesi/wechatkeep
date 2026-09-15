# WeChatKeep (wxkeep)

macOS 微信 4.x 双架构（arm64 + Intel x86_64）防撤回补丁工具链。

**状态：M1 开发中** — 引擎核心（catalog/Patcher/Backup/CLI）已完成并通过 16 项单测；配方引擎、行为验证、doctor、重签、CI 在后续里程碑交付。当前请勿用于真实打补丁（未接线重签，CLI 已加防护）。

## 特性路线

| 能力 | 状态 | 说明 |
|---|---|---|
| 双架构 catalog（52 构建号起步） | ✅ M1 | 合并 zengtianli(arm64) + tanranv5(x64) + 自研 269602，条目级溯源 |
| 写前全量预检 + 自动备份 | ✅ M1 | 任何一点校验失败则一字节不写 |
| expected 字节安全门 + 隔离区 | ✅ M1 | 缺原始字节的条目默认拒绝执行 |
| patch / restore / versions | ✅ M1 | 幂等，restore 反演 |
| 定位配方引擎（DSL） | M2 | 定位方法论变成数据 |
| 行为验证试验台（verify） | M2 | 拉出进程调用补丁函数，证行为不 信字节 |
| doctor（含 macOS 15 AMFI 预检） | M3 | ad-hoc+受限 entitlements 的 SIGKILL 预警 |
| 保留 entitlements 重签 | M3 | |
| CI + 新版本自动追踪流水线 | M5/M6 | 每日发现新构建→自动定位→验证→PR |

## 使用（M1 阶段）

```bash
swift build
.build/debug/wxkeep versions                 # 列出已装构建号 + catalog
.build/debug/wxkeep patch --dry-run          # 只读体检（可在线运行）
```

## 安全模型

1. **expected 多变体字节门**：写入前逐点校验原始字节，错版/未知修改一律拒绝
2. **全量预检**：所有 target 所有 entry 先验后写，杜绝半途状态
3. **自动备份**：每次写入前生成时间戳备份
4. **隔离区**：无溯源（expected）的条目默认拒写（tanranv5 来源条目在补齐 expected 前被隔离）
5. **restore 幂等反演**：expected[0] 恒为原始字节，restore 接受已打补丁态

## 致谢

- [sunnyyoung/WeChatTweak](https://github.com/sunnyyoung/WeChatTweak) — 开创性工作
- [zengtianli/WeChatTweak](https://github.com/zengtianli/WeChatTweak) — 安全设计（expected 门/doctor 契约/重签流水线）与 arm64 catalog
- [tanranv5/WeChatTweak](https://github.com/tanranv5/WeChatTweak) — x86_64 catalog 与适配方法论
- [fzlzjerry/wechat-antirecall](https://github.com/fzlzjerry/wechat-antirecall) — MAINTAINING.md 审计方法论
- [zsbai/wechat-versions](https://github.com/zsbai/wechat-versions) — 版本归档

AGPL-3.0。仅供学习研究，请遵守微信服务条款。
