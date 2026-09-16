# V2 方案 — 原位撤回提示（群聊可用 + 标记被撤回的是哪条）

> 2026-09-16 定稿。综合 zengtianli/WeChatTweak、EEEEhex/RevokeHook（Windows）、
> zetaloop/BetterWX、a244573118/WeChatIntercept、sunnyyoung/WeChatTweak 调研结论。

## 现状与业界对照

| 方案 | 方式 | 私聊提示 | 群聊提示 | 标记哪条 | 自己撤回 |
|---|---|---|---|---|---|
| WeChatTweak (3.x) | ObjC swizzle 注入 | ✓ | ✓ | 通知带原文 | ✓ |
| WeChatIntercept (4.1.x) | 特征码注入+监听daemon | ✓通知 | 部分群无原文 | 通知带原文 | ✓ |
| RevokeMsgPatcher / BetterWX legacy | 抑制式补丁 | ✗ | ✗ | ✗ | ✗ |
| zengtianli keeptip / **wxkeep v1** | 源头清零 newmsgid | ✓ | ✗ | ✗ | ✓ |
| BetterWX 新版 (Win 4.0) | **外科式两规则补丁** | ✓ | ✓ | ✓ 原位下方 | 边角瑕疵 |
| **wxkeep v2（本方案）** | 同 BetterWX 思路, macOS 双架构 | ✓ | ✓ | ✓ 原位 | 待验证 |

关键事实：
- zengtianli README 明确承认同样的群聊限制（私聊有/群聊无），指出根因与本仓行为模型一致：
  **newmsgid 同时控制「删哪条」和「群聊提示挂哪条」**，并指出完整解法 = 保留 newmsgid
  + NOP 下游删除调用，但该调用经虚派发/异步分发，「静态定位不到，需 lldb 动态定位」，
  属未实现的独立工程——与本仓静态深挖结论（0x36F2DD0 std::function 异步层断链）吻合。
- fzlzjerry 的 --runtime-tip 运行时注入也救不了群聊（同样落在 newmsgid=0 状态）→
  排除「上注入就能白拿群聊」的假设；WeChatIntercept 4.x 也已把聊天内提示退化成系统通知。
- Windows 阵营（RevokeHook→BetterWX）已用**纯字节补丁**（无注入）实现完整效果：
  规则1 = 把撤回函数内 `call DeleteMessage` 换成 `SrvID+=1`（删除不执行 + 为提示记录
  铸新 ID，提示作为新消息插在原消息下方）；规则2 = 放行 DB 接受本地自造 ID 的一个字节。
  已知瑕疵：提示需重进会话刷新；自己撤回的边角行为。

## 方案定义

在 keeptip v1 基础上改造为「外科式」：

1. **撤销 newmsgid 清零**（0x50A5BAD 恢复原 call+store）→ 原生解析全量流动，
   群聊/私聊原生提示照常插入。
2. **NOP 下游删除调用**（macOS 对应 Windows 的 DeleteMessage call；藏在
   0x36DBAE0 执行器 → 0x36F2DD0 异步任务的 lambda 链内、虚派发点）→ 原消息保留。
3. **配套放行规则**（仅当实测提示入库被拒时需要，对应 BetterWX 规则2）。
4. 落地形态：config.json 新 variant `keeptip2`（保留 v1 条目做回退）；补丁点
   配方化（锚点 = 执行器链内跨版本稳定证据：`_b13e0758` 服务名、type-10000
   过滤器的 0x2710 比较 + obfuscated 日志串几何）。
5. arm64 同源移植（zengtianli 已证明处理函数两架构同构；v2 点位在其 arm64 孪生处）。

## 实施步骤

- **P0 动态定位**（唯一硬依赖，约 30 分钟配合）：`tools/lldb-trace-revoke.cmd` 已备好。
  前置：微信先 `wxkeep restore`（必须原生态，否则删除链不执行、断点白打）。
  运行梯：① `sudo lldb -p <PID>` 直接 attach（本机 amfi_get_out_of_my_way=0x1 大概率可行）
  ② 失败则 lldb 启动微信 ③ 再失败给 bundle 加 get-task-allow 重签后 attach。
  产出：撤回时 5 个断点的命中顺序 + 调用栈 → 删除 vcall 的模块内偏移。
- **P1 补丁设计**：x64 间接 call（`FF /2`，2-7 字节）按命中点现场字节替换为等长 NOP
  （若返回值被使用则 `31 C0` + NOP 填充）；arm64 `blr xN`→`NOP`（4 字节等长）。
  每处过 expected 门。
- **P2 真机矩阵验证**：私聊/群聊 × 他人/自己撤回 × 消息保留/提示位置/刷新行为。
- **P3 配方化 + 发版**。

## 风险与兜底

- 自己撤回边角（Windows 同款：可能重进会话后自己删的消息再现）——P2 实测，
  若不可接受且链内可分辨 self（0x4BC3FB0 的 (0x31,0x57) 判别疑似 self 分型），
  再评估条件化；字节层无条件化则文档明示该瑕疵。
- 提示不实时刷新（Windows 同款，重进会话才出现）——可接受，文档明示。
- lldb 定位失败/删除点不可安全 NOP → 维持 v1（已 = arm64 阵营最好水平），v2 挂起。
- 封号面：v2 与 v1 改动同为本地展示层字节，不触协议，风险面不变。
