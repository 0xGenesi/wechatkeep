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
2. **NOP 下游删除调用**（macOS 对应 Windows 的 DeleteMessage call；**74 轮
   三次静态修正后定案**：本链 DB 动作 = RemoveRevokeItemTask 协程任务——
   启动点 0x3aafb96（0x3aafad0 执行门内 `call 0x7102b50`）→ 存储原语
   0x4196130（经 0x3aa8800 闭包 invoke 0x3aab070 内 0x3aab0da 调用）；
   await 调用点 0x3aa397b/0x3aa3a35 是协程基建**非**执行点，NOP 无效；
   **75 轮关账**：0x4196130 语句级语义经 Windows 孪生定性（Weixin.dll
   0x18322b240 伪代码 = DELETE FROM revokemessage WHERE 时间列 < now−配置）
   为**清理族写（删过期撤回条目）**，非原消息删除——「全链无原消息行
   DELETE」闭环，详见 MAINTAINING「75 轮增补」+ WINDOWS-SPIKE.md）→
   原消息保留。
2b. **（75 轮新增）插入链候选**：撤回持久化同步写路径定案——0x3a7a040
   （AddRevokeData impl，revoke_manager 0x3a7xxxx 区，失败日志行号 0x589
   与 Windows 孪生 0x182380b60 同值=同源函数实锤）→ ctor 0x3aa8590 →
   invoke 0x3aaae70 → INSERT 0x4195ca0。铸行内容类干预（revokemessage
   记录字段改写，使渲染门 0x5514280 走保留分支）在此层最干净，与候选
   ①-⑤并列进 P0 A/B 矩阵。
3. **配套放行规则**（仅当实测提示入库被拒时需要，对应 BetterWX 规则2）。
4. 落地形态：config.json 新 variant `keeptip2`（保留 v1 条目做回退）；补丁点
   配方化（锚点 = 执行器链内跨版本稳定证据：`_b13e0758` 服务名、type-10000
   过滤器的 0x2710 比较 + obfuscated 日志串几何）。
5. arm64 同源移植（zengtianli 已证明处理函数两架构同构；v2 点位在其 arm64 孪生处）。

## 实施步骤

- **P0 动态定位（状态：2026-10-24 静态收口完成，真机 A/B 待用户窗口）**
  74 轮把 270135 x64 全链剥到存储原语层（地址图与依据见 MAINTAINING
  「270135 撤回链地图」）：任务机制 = RemoveRevokeItemTask（执行门 0x3aafad0，
  启动点 0x3aafb96，await 基建 0x7102860/0x7102b50），存储动作 = 0x3aa8800
  闭包 invoke 0x3aab070 → 存储原语 0x4196130；破坏性候选 = ①0x3aafb96
  任务启动 ②0x3aab0da 存储原语调用（需替换非 NOP，eax 为 bool 返回值）
  ③0x3aa8800 调用点 ④（对照）0x55132f0 内存层改写 ⑤保持 newmsgid 原值；
  75 轮追加插入链候选（见方案定义 2b：0x3a7a040 谓词门/FUN_05546730 记录
  构造/插入 ctor 调用点）。
  **真机 A/B 一次性实验方案不变**：
  对候选点逐个「patch→观察行为→restore」（一次撤回即可判定），不做
  lldb 陪跑。drive35/36 双路径模型（原生撤回疑走存储层直写）未被静态
  推翻——A/B 同时裁决「本链在无运行时组件时是否可达」。
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

## v2 关键情报更新（2026-09-17，源自 fzlzjerry MAINTAINING.md 的 {content} 误区）

**撤回 XML 解析器只服务扩展消息类型 71/72，其 newmsgid 不是普通 Message 的
serverId**——fzlzjerry 为拿正确的内容缓存被迫在「通用 Message 终结器」上挂第二个
hook（缓存 serverId/msgType/content 三元组）。

对本仓的含义：
- 我们 v1 清零的 newmsgid 处于 71/72 解析器（TryParseMessage）内——这解释了
  v1 行为谜团的一半：为什么清零后私聊提示仍显示、为什么 0x36d「按 newmsgid 查找」
  链路动态零命中（那条链找的是另一种 id 体系）
- **A/B 实验候选点修订**：除既有候选外，增加「通用 Message 终结器中的 serverId
  消费点」——真正的删除键更可能在那里。arm64 上先找 Message 终结器（dtor/finalize
  形态、含 msgType 分支）→ x64 孪生 → 三点 A/B
- v3 内容缓存若立项：直接用他们的结论——挂通用终结器，不挂 71/72 解析器

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

## 附录：270135 x64 静态收口（2026-10-24 74 轮）

> 本轮把 V2-PLAN 追尽数月的「下游删除调用藏在 lambda 链哪一层」问题在
> 270135 上剥到底。完整地址图与指令级依据见 MAINTAINING「270135 撤回链
> 地图」；此处只记录对 v2 决策的直接含义。

1. **lambda 体定址并定性**：0x3a90d60（0x3a91130 Phase3 末尾的投递器）
   所投 functor 的 invoke 体 = **0x3aa3100**（vtable @0xa8c4ae0 七槽按
   libc++ __func 布局逐槽解出）。任务名解密 = `RemoveOutOfDataRevokeItemAsync`
   ——延迟任务体；「删除+tip 都在立即执行链」的旧预期就此修正。
2. **双层模型（参数级复核后定案）**：
   - **内存层立即改写**：0x3a91130 Phase3 查库命中 → 0x55132f0（0x6f0，
     纯内存、无 DB 调用；内含 0x5512dd0×3 `<a href="` HTML 构造 = 269602
     0x50B4F10 同源体）把撤回内容写入内存消息对象；
   - **DB/协程层延迟强制**：RemoveRevokeItemTask（dely_time_ms=createTime×1000；
     执行门 0x3aafad0，已执行则 `has execute just skip`）→ 启动点 0x3aafb96
     （`call 0x7102b50` 协程入口）→ 存储动作 = 0x3aa8800 闭包（invoke 体
     0x3aab070）→ **0x3aab0da call 0x4196130**(msgid,u64,string)→bool =
     存储原语（0x5e/0x5f ORM API 族，语句级语义=链上最后未知）；
   - tip 模板（0x278，type-10000）仅提取内容（0x5495180，其首指令
     `cmp dword [rdi+0xc],0x2710` = 新配方锚点）投给延迟任务后即销毁；
   - 0x7102860/0x7102b50 本体为协程基建（多链路共用），不可整体动；
     await 调用点 0x3aa397b/0x3aa3a35 非执行点（工作已先行启动）。
3. **锚点增益**：任务名与日志串（dely_time_ms/is exist/success/failed/
   task has removed）与构建机源码路径（message_revoke_manager.cc）都是
   滚动密钥可解的静态锚——配方化时可用（decrypt_strings 同族算法，
   var/wxarm/decode_revoke_logs.py 可复现）。
4. **诚实边界**：以上全部静态结论；本链是否在「纯字节补丁、无运行时
   组件」时可达（drive35/36 双路径之问）与群聊 tip 最终效果，仍由
   P0 真机 A/B 裁决，静态推定不得写成已证。

## 附录二：模型升级——macOS 无「原消息删除」（2026-10-24 深夜，B 批全量伪代码终版判读）

> 证据与完整地址图见 MAINTAINING「270135 撤回链地图·终版判读」。本节只记对
> 本方案结构的直接影响。

1. **规则1 前提修正**：macOS 4.x 撤回持久层 = `revokemessage` 表（表名明文
   实证）；撤回显示 = 该行 + +0x278 内存载荷（唯一附着点 0x55132f0，唯一
   调用者 = CoCheck 链 0x3a91b69）+ 渲染期 tip（GetRevokeMessage 0x55139e0，
   模板 DAT_09581de0，不入库）。**「NOP call DeleteMessage」在 macOS 无
   对应物**——全链没有原消息行 DELETE。
2. **规则2 作废**：tip 不作为 DB 行插入（渲染期从载荷生成），「DB 放行自造
   SrvID」无 macOS 对应物；「提示需重进会话刷新」的 Windows 瑕疵映射为
   载荷内存态生命周期。
3. **新的首选落点**：revokemessage 行插入点（同步路径写者，待定位）与
   渲染门（0x5514280/0x55139e0）；本链（CoCheck + RemoveRevokeItemTask +
   0x4196130）是消费/清理侧，NOP 只影响清理不影响撤回效果。
4. **P0 A/B 问题不变但更聚焦**：一次真机群聊撤回裁决「0x3a91130 链在纯
   字节补丁（无 hook）时是否可达」——这直接决定上述所有落点的可达性。
5. 配方锚点增益：+0x278/+0x248/+0x1D0/+0x218 对象字段偏移跨版本稳定
   （269602↔270135 实证）；`revokemessage`/`GetRevokeMessage`/
   `reeditrevoke`/`RemoveRevokeItemTask` 明文与可解密串见
   var/wxarm/decode_revoke_logs.py。
