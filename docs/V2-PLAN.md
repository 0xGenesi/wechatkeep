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
- fzlzjerry/wechat-antirecall = **混合路线**（字节补丁 + 预注入运行时 dylib）：补丁只在
  微信函数序言装 `adrp x16; ldr x16; br x16` 跳板重定向进自家 dylib，全部逻辑在运行时
  组件内（消息内容进程内缓存 + 撤回匹配 + 自定义文案「已拦截 {from} 于 {time} 撤回：
  {content}」，{content} 仅部分构建可用、仅本次启动后收到的消息）。改文案不重签微信。
  但其提示仍是替换原生提示 → 群聊限制依旧（zengtianli 实证）。
- fzlzjerry 的 --runtime-tip 运行时注入也救不了群聊（同样落在 newmsgid=0 状态）→
  排除「上注入就能白拿群聊」的假设；WeChatIntercept 4.x 也已把聊天内提示退化成系统通知。
- Windows 阵营（RevokeHook→BetterWX）已用**纯字节补丁**（无注入）实现完整效果：
  规则1 = 把撤回函数内 `call DeleteMessage` 换成 `SrvID+=1`（删除不执行 + 为提示记录
  铸新 ID，提示作为新消息插在原消息下方）；规则2 = 放行 DB 接受本地自造 ID 的一个字节。
  已知瑕疵：提示需重进会话刷新；自己撤回的边角行为。
- **目录增益（已并入）**：fzlzjerry patches.json 的 269628 / 270090(4.1.15.10) arm64
  条目已合并进 config.json（revoke/revoke-keeptip/update；runtime-tip 跳板条目指向其
  自家 dylib，已剔除）。arm64 gen3（newmsgid 字段 0x1C8）延续到 270090 未变代。

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

- **P0 动态定位（状态：2026-09-17 判定离线不可达，等待一次性实验窗口）**
  lldb 全套基建已备好并归档（tools/dyntrace/：WeChatMain 哨兵、滑移硬编码+地面真值校验、
  驱动循环），但多轮会话实证该 lldb 构建存在五层障碍（-a 语义、dlopen 时机、回调注册
  KeyError、事件监听饿死、SB Continue 状态误报），且 wrapper 0x50A5120 在登录+真实撤回中
  动态零命中——静态「唯一调用者」结论与 v1 行为生效矛盾，模型有缺口。
  **下一次的执行方案（不需用户反复配合）**：一次性补丁实验法——对三个候选消费点逐个做
  「patch→观察行为→restore」的对照实验（机器上一次撤回即可判定），或改用 watchpoint 盯
  +0x1C8 的读取者。在此之前不再消耗用户时间做断点陪跑。
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

## v3（可选扩展，依赖 v2 先落地）：fzlzjerry 式跳板 + 运行时组件

若 v2 之后还想「提示文案含撤回原文（{content}）+ 自定义模板」，唯一途径是运行时组件
（撤回 XML 里没有原文，需进程内缓存消息内容——fzlzjerry 已验证可行）：
- 补丁只装 `adrp x16; ldr x16; br x16` 跳板（等长、可配方化），逻辑全在 wxkeep 自家
  runtime dylib（LC_LOAD_DYLIB 注入需在 wechat.dylib 前加载，fzlzjerry 踩过闪退坑）
- 与 v2 叠加后群聊/私聊提示原生插入（v2 保证）+ 文案改写含原文（v3 负责）= 完全体
- 代价：注入面（重签+AMFI）、更新适配复杂度、x64 需自研（fzlzjerry 仅 arm64）
- 决策：v2 验证通过、确有原文需求时再立项，不阻塞主线

## v3 运行时组件设计备忘（2026-09-17，源自竞品逆向）

若 v2 落地后立项运行时组件（提示含原文/自定义文案），两个已验证的机制直接采用：

### 配置通道：微信偏好域前缀键（X1a0He 模式）
- 键名：`io.github.wxkeep.*` 前缀，写进微信自己的域
  `com.tencent.xinWeChat`（组件运行在微信进程内，CFPreferences 直读）
- 优点：改配置**不触发重签**（对比 fzlzjerry 独立配置文件方案）；
  与现有 UpdateGuard 的域写入经验（cfprefd 所有权：微信须退出）复用
- 外部写入工具：`wxkeep tip-config set/get`（sudo + launchctl asuser 委托，
  同 update-guard 的既有模式）

### 通知门控：登录态判断（RecallKeeper 模式）
- 触发通知前检查 `~/Library/Containers/com.tencent.xinWeChat/Data/Documents/
  app_data/login` 存在性——未登录/已切换账号时静默，避免噪音与跨账号泄漏

### 内容来源（开放课题）
- X1a0He 实证进程内 SQLCipher 直读可行；wxkeep 无注入路线拿 key 需独立研究，
  记录为 v3 前置课题，不阻塞 v2
