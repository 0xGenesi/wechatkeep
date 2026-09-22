# 运行时组件设计（可选功能，M-R 系列）

用户决策（2026-09-17）：把注入作为**额外可选功能**加入——突破纯静态补丁的能力
边界（自定义提示、消息标记等运行时才可能的能力）。与字节补丁完全独立、可随时
移除、默认不装。

## 总体架构

```
主程序(Contents/MacOS/WeChat)
  └─ LC_LOAD_DYLIB "@executable_path/../Frameworks/wxkeep_runtime.dylib"   ← 注入
Contents/Frameworks/wxkeep_runtime.dylib                                    ← 运行时组件
  └─ 构造器(启动时) → 读配置 → 按 270099 地址表 hook 目标函数
配置: Application Support/wxkeep/runtime.json（提示短语等）
```

- 注入机制：MachOInjector 在主程序 Mach-O 头部追加 LC_LOAD_DYLIB
  （头空间预检，空间不足拒绝；insert/remove 严格互逆，字节级往返测试覆盖）
- 卸载：removeLoadDylib + 删 dylib + 重签；主程序头部尾零补齐
- 微信小版本更新：注入随二进制替换消失 → `runtime install` 重装即可
  （字节补丁需要 locate 重定位，runtime 只需确认地址表——韧性更好）

## 里程碑

- **M-R1 ✅（已交付）**：注入机制 + 最小 dylib（marker 构造器）+
  `wxkeep runtime status/install/remove`
- **M-R2 ✅（工程已落地，待实弹验收）**：提示文本替换。hook 点 =
  **parse 入口直挂**（270099 = 0x537db40，drive25 地面真值：parse(rdi,
  rsi=XML 裸 SSO)，0.2.0 实机真实撤回 fires=0 证伪 wrapper+0x130 静态
  推定后全家族切换，ROADMAP ㉑/㉒；早期「撤回解析汇点 wrapper
  0x537d910」三路径汇点分析与 isRevokemsg 类型串证伪、排水函数 0x538d700
  候选均为研究中间态，已被取代）。hook 入口处把 `<content>`（线上实测
  承载元素）内文**等长改写**为 runtime.json 文案（含「撤回」needle 门、
  超长放弃、差额空格填充、`<>&` 配置期剥除），SSO 结构与分配器零接触；
  下游解析/入库/会话预览/渲染/历史重扫全链一致（连 DB 持久化都是自定义
  文本）。引擎：UUID 门 + 序言门（x64 12B 纯栈 / arm64 16B + 可换址性
  编码防线）+ RWX 蹦床 + `_dyld_register_func_for_add_image` 同步回调
  与既有镜像扫描双保险。
  **实弹定案补遗（2026-09-18 drive25）**：调试器同语义改写已肉眼验收 ✅
  ——线上撤回 XML 的提示文本承载元素实测为 **<content>**（非
  <replacemsg>，后者为 parse 内另一分支形态），改写已补充双标签 +
  CDATA `]]>` 闭合保护；且 sysmsg 会被多轮重解析，**已入库
  的旧提示亦可追溯换文案**。
  **2026-09-18 午后增补**：
  - **{from} 占位符（M-R3-lite）**：tip_text 里的 `{from}` 展开为原内文
    首对引号内的撤回者昵称；昵称 >64B 或展开超缓冲 → 放弃改写保原文
    （截断会切碎 UTF-8）；无引号形态展开为空
  - **自发撤回门 rewrite_self（默认 false）**：「你撤回了一条消息」
    内文默认不改写——自己的撤回保持诚实反馈（RecallKeeper 同款语义）
  - **地址表外置**：runtime.json `hooks` 数组 = day-0 数据通道（行 schema
    见 runtime.m hook_row_parse；UUID 形制/hex/长度/arm64 序言编码全过门，
    坏行整行丢弃）。`runtime install` 按 uuid 合并写入已知行；外部表在场
    则 dylib 只用外部表，否则回落内置表。新构建 = 数据一行，无需重编
  - **arm64 hook 机器**：16B `ldr x17,#8; br x17; .quad` 入口桩 + 蹦床 +
    `sys_icache_invalidate`（wechat.dylib arm64 切片实测无 PAC/BTI）；
    序言可换址性有编码级防线（ADRP/ADR/B/BL/CBZ/TBZ/LDR-literal 拒绝）。
    待 RE 产出 arm64 wrapper 地址行即可启用
- **通用 keeptip（0.2.x，✅ 实机验证）**：parse 直挂 hook 的降维实现——
  不改任何指令，把 XML 里 <newmsgid> 数字等长清零（'1'-'9'→'0'），parse
  读到 0 → 撤回删除按目标查不到 → 消息保留（v1 语义），提示文本不受影响。
  跨构建通用：不依赖指令地址，hook 能武装即工作。配置键 keep_message
  （默认开）。实机对照实验（270100，Jennifer 撤回"1"/"2"）：字节补丁全撤
  （revoke/keeptip pristine，仅 update 在位）→ 消息保留 ✓ + 灰条正常渲染
  ✓ + zero=1/fires=25 计数器证据 ✓。**附带收益**：isRevokemsg 恢复原状后
  提示正常渲染（silent 变体的 "Unsupported message" 占位消失）。
- **M-R3 余项**：{content} 占位符（消息缓存，按 serverId 终结器缓存——
  fzlzjerry 同款思路，其 {from}/{time} 已由本轮 {from} + 服务端时间戳
  文案部分覆盖）+ 群聊适配实弹验证
- **M-R4 ⛔（阻塞：活体数据缺）**：消息"已撤回"标记。
  **状态机修正（2026-09-19 ㉘ 实弹推翻 drive22/26 旧判）**：
  `mov [rdx+0x118],9` @0x355ab00@270099 实为 UpdateCancelUploadMessageStatus
  （上传取消状态机），与撤回**无关**——「keeptip 置零 newmsgid 导致零命中」
  的旧解释不成立，该函数从来不在撤回路径上。撤回状态机真宿主 =
  share_card_message_handler 0x3444b40@270100：`cmp [msg+0x118],2`
  @0x3445e20 → ==2 走 3421bb0(…,1,1) 完成回调 / ≠2 写 `[msg+0x118]=5`；
  唯一写 2 点 0x33b1407（emoticon handler 族内，vtable 派发）。消息
  +0x118 枚举修正：0x3=常态、2=撤回已收到、5=待撤回（9=上传取消）。
  文本消息推测走同构 text_message_handler（0x3453860+），待实弹。
  **drive26 布局补遗（仍有效）**：Message 向量（async-body rsi，步长
  0x278）活体实证 +0xC=type(1文/3图/49表情)、+0x18=talker、+0x30=self、
  +0x48=sender；async-body 为通用批处理器。
  三方案判定（ROADMAP ⑧）：A 状态位注入（写 2/5 语义已实证，恐触发
  UI 隐藏）/ B 存储层内容前缀打标（XML 含 <session>/<msgid> 可定位，
  可行性中）/ C UI 遮罩（工程量大）。近期实用替代：M-R2 文案即标记。

## 信任与安全

- runtime dylib 由本项目构建、随 bundle 重签（ad-hoc）；无网络行为
- 配置只读本地 runtime.json；不上传任何内容
- `runtime remove` 完整还原；安装前自动备份主程序
- **宿主门（2026-09-18 复审加入）**：构造器先验证主程序 basename ==
  "WeChat" 才启用全部机制——dylib 被其他进程链接（单测 runner 为活例）
  时零副作用（不扫描、不定时器、不写 marker，避免污染 `runtime status`
  的「已加载」判定）；区域扫描只解引用**当前** protection 可读的区域
  （PROT_NONE 保留区实测会让进程 SIGSEGV）
- **安装/移除原子性（2026-09-18 复审加入）**：install 在 LC 注入后的
  dylib 拷贝/重签失败会回滚主程序并清理 dylib（不留「LC 在场但库缺失」
  的启动必崩态）；remove 对「LC 缺失 + 孤儿 dylib」做安全清理而非报错
  （LC 已实证缺失时删除 dylib 无启动风险）
- **外部 hooks 表的信任边界（2026-09-18 增补）**：runtime.json 属用户
  本地信任域（与 tip_text 同域）。hooks 行被全部结构性门约束：UUID 必须
  形制合法且与在载镜像 LC_UUID 全等（错构建零作用）、expected 必须与
  目标入口原像逐字节相等（错位点零作用）、arm64 序言过 PC 相对编码
  过滤、偏移/参数有界——恶意/误配行最坏结果是「hook 不装」或「在指定
  构建上对指定入口改写撤回文案」，无法注入任意执行语义。数据权威源
  仍是经 Ed25519 清单签名的工具侧（RuntimeConfig.knownHooks / 未来的
  signatures.json 分发），runtime.json 只是投放通道
