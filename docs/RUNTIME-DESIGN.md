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
- **外部 hooks 表的信任边界（2026-09-18 增补；2026-10-20 72·L3④ 重审
  扩写）**：runtime.json 属用户本地信任域（与 tip_text 同域）。hooks 行被
  全部结构性门约束：UUID 必须形制合法且与在载镜像 LC_UUID 全等（错构建
  零作用）、expected 必须与目标入口原像逐字节相等（错位点零作用）、arm64
  序言过 PC 相对编码过滤、偏移/参数有界——恶意/误配行最坏结果是「hook
  不装」或「在指定构建上对指定入口改写撤回文案」，无法注入任意执行语义。
  数据权威源仍是经 Ed25519 清单签名的工具侧（RuntimeConfig.knownHooks /
  未来的 signatures.json 分发），runtime.json 只是投放通道
- **runtime.json 物理位置的真实威胁面（72·L3④）**：文件在微信自己的
  App Group 容器（`~/Library/Group Containers/5A4RE8SF68.com.tencent.xinWeChat/
  wxkeep/runtime.json`）——**腾讯代码对该目录可写**（沙盒同组）。旧表述
  「用户本地信任域」低估了这个面。威胁模型与残余风险：
  1. 腾讯代码可**删除/损坏**该文件 → dylib 回落内置表（270099 x64 兜底）
     或 hook 不武装——可用性影响，无完整性影响。
  2. 腾讯代码可**改写行内容**：UUID 门把行锁死到真实在载的 wechat.dylib
     构建，但 `hook_off`/`expected` 是行作者自选的——他可以指向同构建内
     **任意函数**（expected 照抄真实字节即过门），把改写逻辑挂到非预期
     入口。hook 体本身无任意执行语义（只做 needle 门控的等长改写/清零），
     但蹦床会**换址重放入口 12/16B**：arm64 侧有编码级过滤（ADRP/B/BL/
     CBZ/TBZ/LDR-literal 全拒绝），x64 侧纯字节门挡不住含 PC 相对编码的
     序言（E8/E9/EB/0F8x 家族被换址后跳向错误目标）——72·L3④ 起对含
     转移编码字节的 x64 expected 整行拒绝（启发式字节扫描，非完整反汇编：
     零散 E8/E9/EB 字节会误拒——家族序言 554889E54157… 实测全过，误拒
     的可见后果是 hook 不武装，与「宁可不挂也不挂错」同一哲学）。
  3. **残余风险（接受与否的依据）**：完整利用要求腾讯在自家 App Group
     容器里定向对抗 wxkeep 用户（写恶意行 + 等微信重启）。收益是让该用户
     的微信崩溃或行为异常（可归咎于「装了补丁工具」）；对腾讯是可否认的
     反制手段，对用户是稳定性损失，**不是**任意代码执行（hook 体语义有
     限且 newmsgid/文案改写全在门控内）。
  4. **加签评估（评估结论：暂缓，条件触发再上）**：给 hooks 行附 Ed25519
     签名（dylib 内嵌 release.pub、CLI 侧 mergeKnownHooks/update-data 落
     签）可根治 2——密钥/签名基础设施本项目已齐（manifest 通道同款），
     工程量集中在 dylib 侧验签代码与老格式兼容（未签行=回落内置表）。
     暂缓理由：利用前提是腾讯主动定向对抗（前述 3 的收益结构弱），而
     x64 转移编码门已把「换址破坏控制流」的随意性压到需要精心构造且
     绕过字节扫描；一旦出现腾讯实际对抗的实证（marker/status 显示行
     被改），加签升级为 P0 立即实施。

## macOS 27 安装链修复（2026-10-26，77 轮）

**硬化的表现**：微信进程（entitlements 全注入）内 `mmap RWX` 与
`mprotect(已签名页, +W)` 全部 EACCES——runtime hook 自用户升级 macOS 27
起就装不上（此前症状被 status=11 位形误读掩盖：kStInstallFail=3 与
uuid-mismatch(1)+prologue(2) 位形重叠）。与 Verifier 的 MAP_JIT 硬化
（65 轮）同期同源。

**修复**（install_hook 两处，实证 installed=1）：
1. trampoline 页（arm64）：`MAP_JIT` + `pthread_jit_write_protect_np(0/1)`
   写开关 + icache 失效——Verifier 同款语义；页装成后只执行不再写。
2. 目标镜像页：直接 mprotect RWX 失败时走 **vm_remap COW**
   （`VM_FLAGS_OVERWRITE|VM_FLAGS_RETURN_DATA_ADDR` + `VM_INHERIT_COPY`
   自映射）——私有副本脱离 cs 只读强制，mprotect RW 可写；写 stub 后
   恢复 R|X。

**残余（77 续收口两项，2026-10-26）**：①新壳（10-03 自更新起的 libwxld
世代）吞 stub 疑云已由 stub 存活性读回证伪（alive=1 全程稳定，77 轮的
「calls 22→0」是诊断代码自身采样缺陷）；真残余 = hook 点参数语义需对
10-03 dylib 重验（x1 取证通道已备，re-derive 见 ROADMAP 顶部队列）。
②沙盒微信 App Group 写被拒（ad-hoc 签名无 team）的 marker 盲区已修：
`write_marker_ex` 改为「候选目录按序尝试，首个建目录+写成功者胜」——
Group 拒写时回落 legacy（沙盒内展开 = 容器 Application Support，boot log
同位面可达），不再只认 Group；**读/清侧对偶同步修复**（CLI 侧
`RuntimeConfig.markerURLs` 共享同一候选序：Group → 微信沙盒容器 legacy →
真实 home legacy，`runtime status`/doctor 按序探查、install/remove 全位
清理——只修写侧会让回落 marker 对 CLI 依旧「无记录」）。③status 诊断位改为独立 bit
（1/2/4/8/16/32/64，见 runtime.m g_hook_status 注释）——旧编码
kStInstallFail=3 与 uuid(1)+prologue(2) 位形同形是 77 轮误判排障方向的
根因；marker 新增 `enc=2` 编码标记 + `istep/ierr`（安装失败步骤与
errno，macOS 27 W^X 排障钥匙），CLI 判读只对 enc=2 marker 解位
（runtimeStatusFlags/markerStatusDecode），旧编码 marker 展示原值不误读；
武装态权威表达仍是 `mr2=` 字段，不受位形重编码影响。

## hook 链全参透传（77 续⑨，2026-10-27）

**问题（反汇编实锤）**：hook 函数原为 6 参 C 形态（`revoke_wrapper_hook
(a0..a5)`）。对 T4 当时装机 的 Release dylib 反汇编：尾跳序列 `ldr x6,
…; br x6` 把 **x6 当草稿寄存器清掉**——arm64 行挂的解析族函数（0x4bc4d34
系）签名未知（77 续⑦已证其 x1 语义与 x64 行不同构），若它有第 7 个整型
寄存器参，**每次调用该参数被静默替换为蹦床地址**；同时 hook 体调用
memcpy（诊断快照）会清 **v0-v7（FP 参）**。这两者与「T4 hook 体纯
no-op 仍渲染全占位」完全相容，是机制级头号候选（真机复核待 T5）。社区
同类实证：Dobby #190（x8/sret 被清崩）、frida-gum 历史修复「Fix access
to arguments 4 through 7 on arm64」。

**修复（arm64 naked thunk，结构保证而非代码生成运气）**：
`revoke_wrapper_hook` 改 `__attribute__((naked))` 纯 asm 蹦床——
`x0-x8`（8 整型参 + sret 隐参）与 `q0-q7`（FP/SIMD 参）全量保存/恢复，
尾跳 `g_real_wrapper` 前 sp 已复原（第 9+ 参的栈参原位可读）；x16/x17
（IP 草稿，非参数位）承担转移。主体逻辑抽出 `revoke_hook_body(void
*const *args)`（`__attribute__((used))`——静态函数只被内联 asm 引用，
无标注会被当 dead code 删除，链接期 undefined symbol 实测）。**x64 保持
C 形态**：整型参寄存器全集（rdi..r9）恰好 6 个，C 形态即完整；hook 行
契约 = 目标函数无 FP 参（x64 行实弹多年，parse(rdi,rsi,&ok) 无 FP/栈参）。

**帧布局（0xE0）**：[0x00]=x29/x30；[0x10..0x3F]=x0..x5（8B 槽，
body 的 msg_arg 索引面）；[0x50]=x8；[0x60..0xCF]=q0..q7（**16B 槽**）。
三类槽间距踩坑全部被透传测试当场抓出（见下），其中最危险的是 Q 槽按
8B 排布时 `stp q6,q7,[sp,#0x90]` 的 q7 半段**溢出帧边界砸调用方栈参**
——若无该测试，这是一个「只在特定 SIMD 残留值下偶发」的生产级栈腐败。

**透传契约测试（`wxkeep_runtime_test_hook_transparency`，arm64 宿主）**：
MAP_JIT 页内手工构造转储哨兵（入口 16B=4×NOP 可换址重放段；续段把
x0-x7/[sp]/v0/v1/x30/sp 逐槽转储到独立 RW 页后 EOR 折叠返回），经生产
同一蹦床/stub 公共路径（`prepare_trampoline`+`write_entry_stub`，77 续⑨
从 install_hook 提出——测试驱动的是生产代码不是副本）挂钩后调用，
全部参数逐位穿透返回 1。对修复前代码红（Debug 即红：memcpy 清 v0/v1）、
修复后 Debug/Release 双绿。排障出口（diff 指纹/逐槽快照）留在测试缝，
未来任何透传回归可逐槽指认。测试走 MAP_JIT 页的原因：本机（macOS 27）
实测**无 entitlement 的进程连 vm_remap COW 后的 mprotect RW 也被拒**
（vm_remap 本身 KERN_SUCCESS 但别名仍受 cs 只读强制）——文件页 W^X
舞步只在带 allow-unsigned-executable-memory 的宿主（微信）内成立，
测试只能在 MAP_JIT 页内驱动。

**社区方案对照（2026-10-27 全网检索，frida-gum/substitute/ElleKit/
Dobby 源码级）**：naked/asm thunk 全量保存是主流做法（frida 保
q0-q31+x0-x28+NZCV 调试器级全量；Dobby instrument 桥 = q0-q7+x0-x30，
与我们同级的「最小正确集」；我们多保 x8/sret 是 Dobby #190 的翻车点）。
另两条未来可用增量：①入口 16B patch 的 scratch 寄存器（x17）对标准
C/C++ ABI 安全，但 frida 2026-09 `9573d3ef` 证明 iOS 27 起系统库序言
双用 x16/x17——若未来 hook 目标含手写 stub/非标准进入函数，需像
ElleKit `findSafeRegister`/substitute `arm64_get_unwritten_temp_reg`
那样按目标序言 liveness 选寄存器；②写页原语的社区最优解是
substitute/frida 的「匿名补丁页 + `mach_vm_remap(VM_FLAGS_OVERWRITE)`
整页盖回」——从不请求签名页可写，无 entitlement 进程也可行，作为
vm_remap COW 舞步的备选记录在案（现路径在微信进程内实证可用，不换）。

## hook 行函数级身份门（77 续，2026-10-26）

**为什么 UUID + 序言门不够**：10-03 微信自更新交付了**同构建号、同
LC_UUID、新字节**的 wechat.dylib——身份门（UUID）与入口门（expected
序言）全部通过，但 9-18 derive 时的函数 0x4bc4d34 在新字节里已是另一个
同家族序言的函数（x1 取证 = 对象字段非 XML SSO，hook 破坏消息解析 = 全
会话渲染占位，台账 T4 推进轮二）。两道旧门对「同序言不同函数」零分辨力；
44 行 hook 行（非补丁位点）对 10-03 世代全部存疑——补丁位点不受影响
（65 轮 23/23 字节级核对 + v1 日常实弹持续有效）。

**schema 扩展（可选字段，向后兼容）**：HookRow / hook_row_parse 新增
`func_size`（门①）与 `anchor_va` + `anchor_bytes`（门②，成对出现）。
旧行不带这些键 → 门不启用、行为与 77 轮前完全一致；带则坏值（0/超界/
半对/垃圾 hex）在解析期整行拒绝（与既有门的哲学一致——半合法的身份
字段比没有更糟）。`tools/derive_runtime_hooks.py` 派生新行时自动携带
func_size。

**门① func_size（布局距离指纹）**：值 = 目标函数起点到 LC_FUNCTION_
STARTS 下一函数起点的**距离**（不是函数字节数——含对齐 padding；这个
定义与派生侧 tools/machutil.py 同源，安装侧 runtime.m 的
func_size_matches 同语义实现，测试缝锁两处不漂移）。安装期从**运行中
镜像自身元数据**（段表 + FUNCTION_STARTS，mach 读探针取 blob，不直解
引用——linkedit 尾部未映射段直读会 SIGSEGV 杀微信）重算该距离并比对：
重编译挪动函数边界即失配。语义上这是「布局指纹」：同 UUID 同序言但函数
重新排布的镜像会被拒。x64/arm64 同机制（两架构切片都带
LC_FUNCTION_STARTS；PE 侧对应物 = .pdata，Windows 新仓复用本设计）。

**门② anchor（字节锚）**：切片内固定 VM 偏移处的期望字节（≤64B）。
建议取目标函数体内 distinctive 指令序列或其引用的常量——重编译几乎必动
的位置。与门①互补：门①看边界布局，门②看内容字节；两者可独立携带。

**fail-closed 边界**：行带任一身份字段但镜像元数据缺失（无
FUNCTION_STARTS / blob 不可读）→ 拒装（kStFuncMismatch=64，独立诊断
位）。带身份门的行宁可不挂；旧行（无字段）不经过此门——向后兼容与
fail-closed 不矛盾：字段存在本身就是「行作者要求该门」的声明。

**arm64 串对象布局与 per-arch 读取器（77 续⑧，2026-10-26）**：字节同一
性判定先行——**场代际（/Applications 装机 dylib）的 arm64 切片与参考切片
逐字节相同**（sha256 0902af60… 双向吻合；「10-03 自更新换 wechat.dylib
字节」叙事证伪），因此参考切片上的全部静态结论直接适用于场字节。arm64
串对象布局 = **{data@0, size@8, cap|flag@0x10}，长/短标志 = +0x10 qword
的 MSB（即 [0x17] 符号判长）**——证据链：0x4a7d6ac 反汇编形态（ldrsb
[0x17] 负=长 → csel data=[x0]/内联 → 't' 字符搜索）、41,334 处 flag 位点
的共读直方图（data/0x10 共读 19,757 次居首）、T4 真机 x1 取证
{0x79b72ded80, 0x338=824B} 逐字段吻合。与 x64 布局（byte0 奇=长 /
size@+8 / ptr@+0x10）相比：**size 偏移相同，ptr 偏移与判长门不同**。

后果与修复：**现行 44 行 arm64 行按 x64 模型读头 = ptr 取到 cap、byte0
奇偶门永假**——arm64 行的 hook 效果（keep_message 与 tip 均经头取
size/ptr）自派生日起从未生效（T4 hits=0 的机制级解释；x64 行不受影响）。
修复已落地：runtime.m `sso_head()` per-arch 读取器（行 arch 置位，arm64 =
[0x17] 符号判长 / size@[8] / ptr@[0]；仅长串路径，短串一律跳过——XML
≥60B 必为长串），变体布局端到端单测锁定。**T4 渲染破坏机制仍未解释**
（hook 体当时为纯 no-op，不推断）；arm64 hook 在真机的首次生效验证 =
T5（ROADMAP 队列第 1 项收尾步）。

**残余分辨力缺口（诚实边界）**：两个不同函数若序言相同、到下一函数
距离相同、锚点字节也相同，仍会过门——概率上锚点选得 distinctive 即可
忽略；根治 = 对 10-03 世代 re-derive hook 点（数天级工程，ROADMAP 顶部
队列第一项）。本门的价值 = 把「重验后发现行失效」变成「装不上 + 可诊断
（kStFuncMismatch）」，从有害（破坏消息解析）降级为无害（不武装）。
