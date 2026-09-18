# 路线图（待办归档）

## 研究队列处置（2026-09-18 深夜会话，从队尾起做）

1. **DSL expected 通配 ✅（已交付）**：`ExpectedPattern`（`?` 半字节通配 +
   `:maskHEX` 后缀，与 confirm 的 mask 思想统一；半字节粒度，mask 朝严格侧
   取整）进 Patcher/Config 校验/Engine restore。关键设计：branch-flip 配方
   改用 **test al,al(84C0) → xor al,al(30C0)** 编码——al 清零 ⇒ ZF=1 ⇒
   je 恒跳，与 je→jmp 翻转同语义，但 asm 与构建无关、restore 只写回
   `84C0` 前缀（通配起点必须在 asm 跨度之外才可物化，渗入则
   restoreUnavailable，安全不变量维持）。端到端实测：真 270099 dylib
   副本 patch（`30C0`，disp32 原样）→ restore（前缀物化）完美还原。
   locate_x64_parse_guard.py 同步改发 xor 形条目（269602:
   test@0x50a5639 / 270099: test@0x537de29，后者与 d22 实测 parse 内
   isRevokemsg 调用点吻合）；工具另修两处：--append 的 site_va NameError
   （研究期只跑过只读模式故未触发）、isRevokemsg 入口边界启发式在
   270099 失配（懒初始化块 `cmpb [rip+d]; jne` 制造假边界——改多边界
   +调用者数筛；解析函数甄别改为围绕 je 的固定窗口）。
2. **M-R4 消息标记 ⛔（跳过，活体数据缺）**：keeptip 态 status-write
   零命中（newmsgid=0 → 路径不达，d22 实证），rdx 对象布局需
   silent/无补丁态重跑 drive22 同轮捕获。位点 0x355ab00 静态唯一性
   已足够支撑 hook 设计，数据到手即可开工。
3. **M-R2 渲染层 hook ✅（工程落地）**：研究已收口（⑦ 终验），本轮把
   runtime.m 从排水函数候选切到 **wrapper 0x537d910 终案**：hook 入口
   改写 rsi+0x130 XML SSO 数据缓冲内的 `<replacemsg>` 内文（等长、
   needle 门、空格填充、`<>&` 配置期剥除），6 项单测 + 全量 74 测通过。
   剩余：真机装 dylib 一轮真实撤回肉眼验收。
4. **③ 270091-270098 回填 🔶（前置检查完成，6/8 永久缺口）**：
   - 版本映射实证：`WeChatBundleVersion` ↔ CFBundleVersion 线性对应
     4.1.15.N ↔ 2700(80+N)（.10=270090 fzlzjerry 实证 + .19=270099
     本机 Info.plist 双点验证）。
   - **270094（4.1.15.14）/ 270097（4.1.15.17）**：zsbai 归档有 dmg asset，
     **本轮已本地回填**（GitHub 资产直连超时，走 gh-proxy 镜像取 dmg；
     WeChatBundleVersion↔CFBundleVersion 映射实测复核 .14=270094、
     .17=270097）：wxkeep locate 各 2 条（revoke_x64 0x4E884C0 /
     0x4E8CBB0 + arm64 gen3 0x4BC1C88 / 0x4BC4724）+ 解析守卫 xor 条目
     （test@0x5378ea9 / 0x537d599，expected `84C00F84????????`）入
     config.local.json。270094 真 dylib 副本端到端：patch 3 写入（silent
     函数级 + xor 守卫，disp32 原样）→ restore 3 还原（前缀物化）字节级
     往返 ✓。守卫位点随解析簇规律漂移（269602 0x50a5639 → 270094
     0x5378ea9 → 270097 0x537d599 → 270099 0x537de29）。
   - **270091/92/93/95/96/98**：归档无 release、官方 CDN 从不暴露
     构建号直链（`WeChatMac_<营销版本>.dmg` 覆盖式）——从未公开发布，
     目录永久缺口（除非未来出现第三方存档）。
   - **watch 收集器 bug 已修**：现行 body 的任意-token 数字提取抓的是
     ContentLength（DestVersion 已改点分格式）→ dest_version 改行锚定，
     数字命中/点分返回 None/ContentLength 不误抓（回归过）。CI 实跑
     回填若要覆盖 4.x 时代，workflow 需改为挂载后读 Info.plist 的
     WeChatBundleVersion/CFBundleVersion 判新（设计已记录，未实施）。
5. **② 270099 stubs ✅（前会话完成，本轮复核确认）**：signatures.json
   revoke_x64.verify 带 270099 反解（stubs 7A23CE4/7A2373E、zero
   AD2C3F8），pristine 1/0/0/0 + patched 全 0 双向实测通过（见复核会
   话第 2 条）。
6. **① AMFI 判定实证 ⛔（跳过，硬件动作）**：需原生 SIP 引导执行
   tools/amfi_sip_probe.sh（nvram -d boot-args → Recovery csrutil
   enable → 一键 patch→launch→harvest→恢复），本轮无法代做。

## 已归档待办

### ① 解析守卫 branch-flip（冗余 silent）——✅ 已交付（2026-09-18，见顶部处置记录 1）
已交付：`tools/locate_x64_parse_guard.py`（269602 实测：isRevokemsg 9 调用者 →
8 处 `test al,al; je` 守卫 → 按"函数体含 newmsgid 存储"甄别出解析守卫
**je@0x50a563b，expected 0F84A6000000，asm E9A700000090**，支持 --append）。
~~剩余：RecipeEngine 的 expected 门是静态字节~~ → **已解决**：expected 通配
DSL（`?` 半字节 + `:maskHEX`）落地，配方改 test→xor 编码（asm 静态、restore
可逆）。269602 条目形态：addr=50a5639（test 位点）、expected
`84C00F84????????`、asm `30C0`；270099 同构（test@537de29）。
完成后效果：未来 x64 新构建获得第二条独立 silent 路径
（不依赖 isRevokemsg 函数存活）。

### ② 入口指纹纳入 archive 工具链
fzlzjerry 的研究脚本在导出函数时记录 12 字节入口指纹（供跨构建关联）。
落地：`contribute_expected.py --hashes` / archive_index.json 增加
`entry_fingerprints` 字段（addr + 前 12 字节），配合 watch-wechat 的自动定位
做"新构建 = 旧构建 + 指纹漂移比对"的快速预检。

## 新功能设计草案：自定义撤回提示（可选，默认关）

目标：用户自定义撤回提示文本，**不注入 dylib**（non-goal 不破）。

关键洞察：fzlzjerry 的 runtime-tip 需要 Runtime dylib 在运行时把短语对象写进
地址槽（返回运行时构造的 ObjC/C++ 对象）。但存在一条**纯静态路径**：

- Mach-O 的 `__DATA_CONST,__cfstring` 段存放编译期 CFString 常量——32 字节结构
  `{isa→__kCFConstantStringClassReference, flags=0x7C8, char*→__cstring, len}`，
  纯静态数据、无需运行时构造、天然是不可变 NSString（toll-free bridged）。
- 做法：在代码洞手工构建一个 CFString 常量（isa 指向镜像内既有的
  __kCFConstantStringClassReference 槽、flags 0x7C8、字符指针指向洞内自定义
  UTF-8 文本、长度字段），再把"提示文本消费点"的引用重指向该洞。
  x64 重写 lea rip-rel / arm64 重算 ADRP+ADD——均为静态字节。

前置研究（每构建一次，规模类比 keeptip2 攻坚）：
1. 定位提示文本消费/插入点（私聊：服务端 10000 消息 content 的落库/渲染；
   群聊：客户端生成的 replacemsg 路径）
2. 确认消费点字符串类型与所有权：NSString*/CFStringRef → CFString swap 可行；
   std::string（需构造语义）→ 标记不支持

已知风险与限制：
- CFString 常量是真对象（isa 合法、immortal），风险远低于 v7 的裸值——
  但仍须真机验证（v7 教训：任何"伪对象"都可能崩）
- 群聊：fzlzjerry 带完整运行时也在群聊失效（#63）——预期同样受限，先私聊
- 占位符 {from}/{time}/{content} 需运行时插值 → 静态方案只能整句固定文本

结论：可行、不违反 non-goal、可选项（默认关）。排期建议 v0.1.5 研究项，
不阻塞 v0.1.4。

### ③ 自定义提示研究判定（2026-09-17 深夜，drive12-14 动态+静态收口）——**静态不可行**

实验过程：入队断点+SSO 字符串读取（drive12-13 因 lldb 批处理会话不稳定未命中，
drive14 改**附加模式+动态基址自校验**成功命中 dispatch/A-entry）。
随后静态收口得到决定性事实：

1. `replacemsg` 属性名在 dylib 中**零明文零解密串**——提示文本不走客户端
   模板，而是**服务端预生成的 replacemsg**（含发送者昵称），随 10000 消息
   原样入库、由通用渲染路径显示。
2. dylib 内唯一的撤回文案是**自发撤回**的本地 UI 串（0xa62f517
   "你撤回了一条消息" 等）——与对方撤回提示无关。
3. 因此"自定义对方撤回提示"的替换对象是**服务端数据流经的 C++ std::string
   管道**——静态字节补丁无法构造 std::string（需运行时堆分配），CFString
   swap 的前提（ObjC/CF 类型消费点）不存在。
4. fzlzjerry 用注入 Runtime dylib 正是为了跨过这道墙；且即便如此群聊仍
   失效（#63）。

**定案**：自定义提示需要运行时注入（本项目 non-goal），纯静态路线不可行，
研究项关闭。可选的静态替代（均已有/无额外价值）：silent=无提示、
keeptip=服务端原文提示。

### ④ 设计复审补遗（2026-09-17 深夜，本地信任域分流落地）
- locate --append 信任域分流：缺省写 userDataURL（用户派生数据，免签名）；
  显式 --config 时写指定文件（CI watch-wechat 流水线路径，合并后由
  manifest-sign job 重签）——自动 PR 循环与普通用户两条路都通。
- 覆盖优先级已正确：load 合并时签名目录优先于本地同位点条目
  （官方改进版条目不会被旧本地条目永久遮蔽）。
- 已知小项（接受）：update-data 的新旧条目数对比把本地条目计入旧值（纯展示）；
  verify 仅覆盖 silent 位点；config.local.json.bak.* 随时间累积（可手动清理）。

### ⑤ M-R2 研究进展（2026-09-17 深夜，drive16 对象字段图谱）
270099 x64 撤回信息对象布局（post-store 实测转储）：
- +0x1a8：SSO "revokemsg"（消息类型）
- +0x1e8：SSO 撤回者 wxid（$wxid_xxx）
- +0x1C8：newmsgid（keeptip 置零点 ✓）
- +0x18/+0x28：堆字符串字段 ×2（长度 11/10，内容待定）
- 对象内**无 replacemsg 提示文本**——提示文本不在此对象构建
M-R2 hook 点结论：自定义提示的 runtime hook 需要挂在 tip 文本组装处
（排水/UI 层），或直接 hook 消息展示层。下一轮：drive16b 在 tip 显示后
做全堆扫描定位文本载体，或 hook 消息 DB 插入层（通用点位，一劳永逸）。

## 2026-09-17 深夜复核会话：五项决策与状态

1. **AMFI 判定重写**：基于外部证据推翻早前 kill_predicted 结论（旧判定疑似把
   verifier worker 的 RWX 杀机误外推到微信重签场景）。doctor 已改为证据中性表述。
   验证方案：原生 SIP 开机实机 patch 一次；若 .ips 显示 CODESIGNING kill 则恢复
   旧判定。状态：**实证协议已交付（tools/amfi_sip_probe.sh），待一次原生 SIP
   引导执行**。本机先例补强（2026-09-17 复核发现）：Sep 15 16:28/16:29 两份
   `WeChat-*.ips`（repo 首提交 17:58 之前的手工实验期）记录
   `CODESIGNING / Taskgated Invalid Signature` SIGKILL，flags=0x1000000(CS_ADHOC)
   ——ad-hoc 态在 AMFI 活跃引导下确曾被杀，随即 16:35 关机重启进 Recovery 开启
   bypass（现 SIP off + amfi boot-arg 的由来）。定性：**当时重签配置无记录**
   （早于 Resigner 管线，疑似 entitlements 剥光的裸 codesign，即 sunnyyoung
   #1038 同款杀机路径），不能充当当前管线的受控反证。实证按 probe 脚本头部
   runbook 执行：`sudo nvram -d boot-args` → Recovery `csrutil enable` →
   `sudo tools/amfi_sip_probe.sh`（自动 patch→launch→harvest .ips→恢复 pristine，
   判据 RUNS/KILLED/OTHER-KILL 内建）。
2. **verify 规格 270099**：真机 verify worker 崩溃（spec 仍是 269602 家族的
   stubs/zero_regions）。需对 270099 x64 重新逆向 stubs（isRevokemsg 已知
   0x4e8d440，stub 地址需重找）。状态：**已完成**（同日收口）——
   崩溃定性：SIGSEGV/GPFLT 于 isRevokemsg@0x4E8D47A 的第一个 call 目标
   （strlen 桩 0x7A23CE4）——旧 stub VA 在 270099 非 `ff 25`，worker 桩守卫
   静默跳过→GOT 槽 0xA40EF88 保持 chained-fixup 原始值
   0x8010000000000834（非规范地址）；旧 zero 区 0xA988320 落在无关
   __DATA（次要破坏）。崩溃=布局漂移的预期失败模式，非环境/Verifier 缺陷
   （SIP off、同镜像同 worker 换新 spec 即通过）。270099 反解已落地
   signatures.json（stubs 7A23CE4/7A2373E、zero AD2C3F8；gen_verify_spec
   的第二 zero 区 AD2C408 属隔壁 qy_revoke_msg 比较器，已裁剪）；
   pristine 1/0/0/0 + patched 全 0 双向实测通过。
3. **catalog 缺口 270091–270098**：270099 已本地适配（x64 locate/keeptip），
   其余 8 个构建需 CI dispatch watch-wechat 实跑回填。注意：中间号可能是
   内部构建无公开 dmg——回填前先验证制品存在性。状态：流水线待实跑验证。
4. **Intel 数据入库决策**：tanranv5 270098 条目、fzlzjerry #55 269574 候选
   （解析入口 0x5063940、守卫 0x5063F87）均缺 expected 字节 → 按隔离区策略
   不导入，待 contribute_expected 以真实 dylib 回填后放行。未擅自导入未验证
   数据 ✓。
5. **runtime hook 同步回调模式**：将来加 hook 必须用 fzlzjerry 的
   `_dyld_register_func_for_add_image` 同步回调（270090 启动闪退教训——
   异步时机错误即闪退）。当前 M-R1 仅 marker 无需。已写入 RUNTIME-DESIGN 约束。

### ⑥ M-R2 第二轮（2026-09-18 凌晨，drive17-22：270099 全图谱 + hook 设计转向）

**静态（tools/xref_x64.py 新工具：LC_FUNCTION_STARTS 边界 + E8 对齐验证；
ULEB128 字节序陷阱已修——`cur=(cur<<7)|b` 是反的，正确为 `cur |= low7<<shift`）**

270099 x64 撤回链与消息管道（269602 同构，全部重定位）：
- isRevokemsg **0x4e8d440**（9 调用者，与复核会话第 2 条一致）；isType10000
  谓词 0x4e8d430（`cmp [rdi+8],0x2710; sete al; ret`，紧贴 isRevokemsg 前）
- 解析函数 [0x537db40..0x537efa0)（newmsgid→[obj+0x1C8] @0x537e39d =
  keeptip v1 位点）；wrapper [0x537d910..0x537db40)（唯一调用者，拓扑同 269602）
- **状态写 [0x355aa90..0x355af60)：`mov [rdx+0x118],9` @0x355ab00——全镜像
  唯一**（269602 0x32e73a0 双子，M-R4 标记位点）；调用方 0x351cc8f / 0x355b42d
- storage 服务解析器 [0x3952d50..0x3952de0)（"_b13e0758" @0x91ae9fc，
  rip-disp32 反查定位）← 异步撤回任务体 [0x3951040..0x3951ea0)
- decrypt_strings 270099 全量 120 串新图谱：**system_message_handler**
  0x3449100/0x344baa0（vtable 派发，无私有 E8 调用者）、text_message_handler
  0x3453900/0x3459270、emoticon/share_card 家族、**mac_message_storate_impl**
  ×7（0x3a01fb0..0x3a15700）、**base_msg_data_producer** 0x4db8f20/0x4db9ff0
- 23 处 `==0x2710` 比较；[0x3dc9250..0x3dcd490) 兼具 type@[+0xC]==10000 与
  isRevokemsg 调用（撤回消息消费者）

**动态（drive17-21，自主会话）**：
- producer/storage/syshandler 的**解密循环 site 是冷路径**——启动+自动登录+
  空闲全程零命中（登录已确认：账号 message_0.db 空闲期仍活跃写入）
- **全堆扫描**（`memory region` 命令枚举 + needle 扫 1.1GB）："撤回了一条消息"
  42 处，tip 文本以**四种容器**共存：① protobuf 同步批缓冲 ② 会话预览记录
  （`loneboys你撤回了一条消息`）③ DB 页缓存（紧邻 `dialogue_id INTEGER`）
  ④ **UI 气泡模型**（`"Rhaegar" 撤回了一条消息\0` + 头像 URL 相邻的
  NUL 结尾 C 串三连——渲染就绪态）
- WP 挂 tip 数据区后 URL scheme 切会话未触发重读（缓存）——消费链回溯
  需真实撤回/消息事件（自主会话无触发源）

**M-R2 hook 设计定案（转向）**：不再追渲染读取点——**hook isRevokemsg 入口**：
管道处理到达 tip（10000 消息）时恰以内容 SSO 为参调用它，此刻把 SSO 原地
改写为 runtime.json 自定义文案（长串形态指向 dylib 拥有的缓冲，生命周期随
dylib 永驻），下游入库/会话预览/渲染全部拿到自定义文本。优势：isRevokemsg
是跨构建锚点（locate 配方已覆盖）、调用约定简单（rdi=SSO*，返 al）、易区分
tip 内容与 "revokemsg" 类型串（内容/长度判定）。约束（复核会话第 5 条）：
hook 安装必须走 `_dyld_register_func_for_add_image` 同步回调。前提待验：
到达 tip 内容串确实过 isRevokemsg（drive22 一轮真实撤回即验）。群聊合成
tip 走 0x50B4F10 双子，二期再挂。

**M-R4 就绪度**：状态写唯一位点 0x355ab00 已定位——runtime hook 其入口即可
「保消息可见 + 打标记」（状态写与删除分离的落点）；drive22 同轮捕获 rdx
对象布局。

**下一轮（drive22，已归档）**：附加模式 + isRevokemsg/post-store/async-body/
status-write/parse 五断点，人工触发一次对方撤回：①验证 isRevokemsg 收到
tip 内容串并对含"撤回"串挂读 WP 抓消费链（M-R2 终验）②捕获 status-write
的 rdx 对象转储（M-R4）。

### ⑦ M-R2 第三轮（2026-09-18 凌晨，并行会话：0x538d700 排水函数 + hook 引擎落地）

与 ⑥ 并行的自主会话产出（静态 xref/capstone + drive22 被动侦察）：

**静态实证链（推翻两个旧结论）**：
- parse@0x537e3b9 以 `movabs rax,0x6d6563616c706572` + `mov word,0x6773`
  构建 **"replacemsg"** 标签（立即数编码）→ ROADMAP ③「replacemsg 零明文
  零解密串」结论**被推翻**（strings 工具看不见 movabs 立即数）。
- 0x5212c70 提取 → `lea r14,[rbx+0x1d0]`：drive16 的未定性字段 **+0x1d0
  即 tip 文本 SSO**（当时按裸指针解引用扫描，把 SSO 结构体当地址漏检）。
- **0x538d700（排水函数，async-body 0x3951040 的被调）**：rdi=信息对象
  （+0x1d0 SSO setter：free 旧串→movups 写入→`lea rsi,[rbx+0x1d0]` 传递
  消费），**rsi=刚提取的 replacemsg 裸 SSO 指针**。序言 12B 恰为纯栈操作
  （554889e54157415641554154，蹦床安全边界）。
- async-body rsi=消息向量（步长 0x278=632B，社区已证 Message 尺寸）——
  原消息批在此，revoke-manager 全族无 0x2710 立即数（tip 无本地 10000
  常量构造路径）。

**drive22 被动侦察（附加运行中微信，有机消息流）**：消息对象布局实测
type@+0xC、content SSO@+0x168（3.8KB 群消息实况）、msgsource@+0x198；
decrypt_strings.json 的 func 值**基址有误**（用了首 section 地址而非
__TEXT vmaddr）——storage/producer 断点此前零命中的根因，真入口已重算
（见 tools/xref_x64.py 会话记录）。

**M-R2 hook 引擎已落地（Sources/WxkeepRuntime/runtime.m）**：
- inline hook 全机制：LC_UUID 门 + 12B 序言原像门 + RWX 蹦床
  （saved+movabs r11/jmp r11）+ `movabs rax/jmp rax` 入口改写；
  `_dyld_register_func_for_add_image` 同步回调 + 既有镜像线性扫描双保险
  （复核会话第 5 条约束）。
- 改写语义：**缩短式 SSO 原地重写**（长串只动 size+数据/短串只动 tag+
  内联，分配器零接触），"撤回" needle 门防误伤。
- 配置：`Application Support/wxkeep/runtime.json` 的 `tip_text`。
- 地址表现挂 0x538d700 行（UUID 97e21436…）；4 项单测
  （RuntimeHookTests）覆盖改写核心。
- **两个候选点并存**：⑥ 的 isRevokemsg 入口（跨构建锚点优势，前提=
  tip 内容串过 isRevokemsg，待 ⑥ drive22 结果）vs 本轮 0x538d700
  （rsi=replacemsg 裸 SSO，静态实证最强，单构建地址表）。引擎两者通用，
  换表行即切换。注意：并行会话对 isRevokemsg 比较器体的解读是 rdi=被比
  的 type 属性短串（"revokemsg"），与 ⑥ 前提相抵——以实弹为准。

**终验工具（tools/dyntrace/drive23.py，已就绪）**：断 0x538d700，命中即
读 rsi SSO+回溯，并用调试器执行与 dylib 完全同语义的原地改写——一轮真实
撤回后看微信界面是否显示自定义文案即可定案（无需先安装 dylib）。

**AMFI 原生 SIP 实证协议亦已交付**（复核会话第 1 条的实验侧）：
`tools/amfi_sip_probe.sh`——preflight（SIP/boot-args 门）→ pristine 快照 →
标准 patch（完整 Resigner 管线）→ codesign 自检 → 启动观测 25s → .ips
终止原因分类（RUNS/KILLED/OTHER-KILL）→ trap 保证恢复 pristine。头部含
原生 SIP 引导 runbook（nvram -d boot-args → Recovery csrutil enable）。
本机先例补强：Sep 15 16:28/16:29 两份 WeChat .ips =
`CODESIGNING/Taskgated Invalid Signature`（flags 0x1000000 CS_ADHOC）——
ad-hoc 态在 AMFI 活跃引导下确曾被杀（当时重签配置无记录，系 repo 诞生前
手工实验，不能充当当前管线反证；doctor 注释已补）。

### ⑦ M-R2 终验（2026-09-18 00:15，drive22 真实撤回实捕——研究阶段收口）

一次对方私聊撤回，五断点全链捕获（/tmp/wxarm/d22_run2_full.log 已归档）：

```
到达漏斗: 0x6f4c919 → 0x6f53512 → 0x4b5d2ac → 0x4b8a078 → 0x4b56d05
           → 0x4b2a807 → 0x4b3b6cf ∈ sysmsg处理器 [0x4b3aee0..0x4b3db20)
  ├─ A 到达解析:  [0x3559430..0x35594b0) → [0x530ca60..0x530d2f0)
  │    → [0x530e0f0..0x530e200) → wrapper [0x537d910..0x537db40) → parse
  │    （parse 内部 isRevokemsg@0x537de29 类型检查 → post-store newmsgid=0 ✓keeptip）
  ├─ B revoke_manager 二次解析: [0x35594b0..0x3559b00) → 0x394be13
  │    ∈ [0x394ae30..0x394e4c0) → wrapper → parse（同 XML 再解析一遍）
  ├─ C 异步任务体: [0x35594b0..0x3559b00) → [0x351f480..0x351f580)
  │    → async-body [0x3951040..0x3951ea0)（静态猜测命中 ✓）
  │    → 0x39510f8 → [0x5037ef0..0x5037fb0) → tiny [0x538e690..0x538e6e0) → isRevokemsg
  └─ D 历史批扫（tid 独立，parse 洪峰 20+ 源头）: 0x5cda0e2 → 0x5d97333
       → [0x364ee50..0x3652310) → [0x3611fa0..0x3612bf0) → [0x3664510..0x3664620)
       → 同一漏斗 [0x530e0f0..0x530e200) → wrapper → parse
```

**关键判定**：
1. **isRevokemsg 全程只收 "revokemsg" 类型串**（40+ 次实测，无一例外）——
   ⑥ 的"hook isRevokemsg 改写内容 SSO"前提**证伪**。isRevokemsg 是纯类型谓词。
2. **wrapper [0x537d910] 是全路径唯一汇点**（A 到达 / B 二次解析 / D 历史批扫
   都过它）——**M-R2 hook 终点定案**：hook wrapper 入口，检查 XML 参数中
   `<replacemsg>…</replacemsg>`，把内文替换为 runtime.json 文案（短则原位补空格、
   长则 SSO 重指向 dylib 持有缓冲），再调原函数。下游（解析结果/入库/会话预览/
   渲染/历史重扫）全部一致拿到自定义文案——连 DB 持久化都是自定义文本。
   wrapper 为 vtable 派发（269602 槽位 +0x18 经验）→ 可选 vtable 槽替换
   （免 inline trampoline，改 __DATA_CONST 一指针）。
3. **keeptip v1 行为模型活体证实**：post-store newmsgid=0；status-write
   **零命中**（newmsgid=0 → 原消息查不到 → 状态标记路径不达）——与 v1 模型
   （私聊提示保留+消息保留）完全一致。M-R4 如需活体捕获 rdx 对象，需在
   silent/无补丁态重跑 drive22（位点静态唯一性已足够支撑 hook 设计）。
4. drive22 的 900s 时限卡在阻塞 Continue（消息流安静后无停止事件）——
   心跳/时限检查不能依赖 Continue 返回（drive18 教训重演，脚本已带伤运行）。

**M-R2 研究收口**：hook 点位、改写策略、安装时机（add_image 同步回调）、
跨路径一致性全部落定。剩余为工程实现（runtime dylib 的 wrapper trampoline +
XML 内文替换 + runtime.json 读取），无未知研究项。

### ⑧ M-R2 实弹定案 + M-R4 侦察（2026-09-18 晨，drive24-26 三轮实弹）

**drive24（判别实验）**：普通消息+真实撤回对照——pred10000 命中 93 次、
parse(0x537db40) 3 次、async-body(0x3951040) 4 次、**drain(0x538d700) 0 次**。
⑦ 的 drain hook 假设被推翻（call 边在条件分支，keeptip 置零 newmsgid 后未走）；
parse/async-body 实时撤回路径实证。断点四项全部 resolved=1（排除断点失效）。

**drive25（M-R2 终验，端到端通过 ✅）**：parse 入口 rsi = **sysmsg XML 裸 SSO**
（154B 全文实拍：`<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg>
<content>"joy👀" 撤回了一条消息…`）——**提示文本承载元素是 <content>**，
非 <replacemsg>（后者是 parse 内另一分支的静态形态）。等长改写 <content>
内文（尾部空格填充）后微信界面灰字变为 `🔒wxkeep M-R2 hook OK`——
**且旧撤回提示在 sysmsg 重解析时被追溯改写**（parse 对同一 XML 多轮重派，
已入库提示亦可换文案）。M-R2 hook 语义闭环。

**runtime.m 集成**：并行会话 wrapper 方案（0x537d910 入口，XML SSO@rsi+0x130）
+ 本轮补 `<content>`/`<replacemsg>` 双标签 + CDATA `]]>` 闭合保护；
tip_text 剥 `<>&` 防破 XML；8 项单测含线上形态，全仓 76 测试通过。
⚠️ wrapper 的 +0x130 偏移未经独立动态验证（parse 直挂 rsi 已验证）——
首次 `runtime install` 实机若 hook 未生效，地址表切 parse 入口方案即回退。

**drive26（M-R4 侦察）**：真实撤回下 **status-write(0x355aa90) 零命中**——
keeptip 置零 newmsgid 使查找失败，状态写（+0x118=9）与删除**同源阻断**，
「写状态不删除」的天然分离点不存在于当前补丁态。Message 向量布局实证
（async-body rsi，步长 0x278）：+0xC=type(1文本/3图片/49表情)、+0x18=talker、
+0x30=self、+0x48=sender、+0x118=状态(常态 0x3)、async-body 为通用消息
处理器（撤回与普通批流共用，非撤回专属）。

**M-R4 标记方案判定**（待做，需新研究轮）：
- A 状态位注入（+0x118=9）：语义未观察过（keeptip 下从未执行），可能触发
  UI 隐藏（自毁）——风险高；
- B 内容前缀打标（存储层改 content 加「[已撤回]」前缀）：需挂 async-body
  向量处理段 + 按 XML 的 session/msgid 定位目标消息——XML 已含
  `<session>/<msgid>`（drive25 #5 实拍），可行性中；
- C UI 气泡层遮罩（X1a0He 式）：drive20 曾扫到气泡模型，工程量最大。
近期最实用替代：M-R2 文案即标记（tip_text 写「⚠️已拦截撤回并保留」语义，
一行配置零新代码）。

### ⑨ 全仓复审（2026-09-18 午，独立会话：⑧ 集成代码审查，八处修复）

对 ⑧ 落地的 M-R2 工程（runtime.m hook 引擎 / expected 通配 / CLI 防线）
做独立代码审查，确认并修复（79 测全过，release 构建通过）：

1. **uuid_matches 恒假（致命，hook 永不安装）**：`buf+'----'` 填充实现在
   want 耗尽后 a 停在填充字符上，收尾 `*a==0 && *b==0` 永假——任何镜像
   （含目标本尊）都判不匹配，构造器扫描/add_image 回调/区域扫描**全链
   失效**。独立 C 程序实证后修复：与 header_uuid_is（逐半字节正确实现）
   合并为单一 uuid_matches。新增测试缝 `wxkeep_runtime_test_uuid_match`
   + 回归测试锁死该失效类。
2. **测试进程确定性 SIGSEGV**：区域扫描只查 max_protection（PROT_NONE 的
   保留区 max_protection 可含 X，实测 0x7ff800000000）即解引用 header。
   `swift test` 三次复现，crash 栈指 find_wechat_base_by_region_scan。
   修复=加当前 protection 可读门。
3. **宿主门缺失**：dylib 被 test target 链接后构造器在任意宿主进程跑
   扫描/定时器/写 marker——既崩宿主又污染 `runtime status` 的「已加载」
   判定。修复=host_is_wechat()（主程序 basename == "WeChat"）门控，
   非微信宿主零副作用；测试缝为直接函数调用不受影响。
4. **install_hook mprotect 缺大括号**：`return -1` 无条件执行——hook 已
   武装但 g_hook_installed/marker 永报失败（真机验收会被误导成未生效）。
5. **write_marker 移出 try_hook_image**：add_image 回调持 dyld 锁，不在
   其中做 Foundation 磁盘 I/O；armed 态 marker 改由构造器尾部 /
   arm_late / 定时器在安全上下文回写（覆盖等价）。
6. **CDATA 未闭合拒绝改写**：`]]>` 不在闭合标签前时旧逻辑会把 CDATA 段
   改破（永不闭合）——现放弃改写保原文。
7. **Engine.restoreAsm mask 后缀崩溃**：全具体带 `:maskFFFF` 后缀的条目
   原样透传 spec → 下游 `Data(hex:)` 强解包崩。修复=物化字节（concretePrefix
   全长），补测试。
8. **CLI 原子性**：install 的 LC 注入后 dylib 拷贝/重签失败原先留「LC 在场
   但库缺失」半装态（启动必崩）——现回滚主程序+清理 dylib；remove 对
   「LC 缺失+孤儿 dylib」从报错改为安全清理（与 2026-09-18 事故防线互补：
   危险的是 LC 仍在时删 dylib，LC 已实证缺失时清理无风险）。

未动项（有意）：真机装 dylib 肉眼验收 / AMFI probe（均需硬件动作）；
watch CI 的 4.x Info.plist 判新——其服务的 270094/270097 缺口已本地回填
闭环，改造现役流水线无本地验证手段，风险大于收益，维持「设计已记录」。

**工件目录整改（同日追加）**：研究工件不再写 `/tmp`（⑦ 引用的
`/tmp/wxarm/d22_run2_full.log` 已被系统清掉、无法找回）。d23–d26 实弹
日志已迁入仓库 `var/wxarm/`（gitignore——含真实昵称/wxid 隐私，不入库），
lldb 诊断脚本 `check_hook.py`/`uuid_check.py` 入 `tools/dyntrace/`
（check_hook 直接服务真机验收：读 wrapper 入口 12B 判 ARMED），
drive16/22–26、xref_x64、amfi_probe 的输出路径全部改为按 `__file__`
相对仓库根解析。惯例见 MAINTAINING「工件目录惯例」。

### ⑩ 全网调研 + 五线交付（2026-09-18 午后，独立会话）

**调研输入**：双代理全网调研（生态/技术前沿）+ 本机验证。关键外部事实：
270099 仍是最新构建（无 4.1.16）；官方 CDN 存在 `xWeChatMac_universal_<ver>_<build>.dmg`
按构建号归档直链（生态此前不知，实测仅 4.1.15.12_270092 404）——
「270091-98 永久缺口」与「历史构建无可靠回填源」两个旧结论**作废**。
X1a0He 已闭源化（v2.9.0→270090）；fzlzjerry 新增抢红包+{content} 占位符；
WeChatIntercept 的特征码自动定位思路与我们 recipe 引擎同向。详见
related-tools-analysis.md 2026-09-18 节。

**五线交付**：
1. **目录回填（5 构建闭环）**：270091/93/95/96/98 全部下载→挂载→
   `locate --append`（arm64 gen3 + x64 双命中）→ 解析守卫 xor 条目 →
   BackfillRoundtripTests 端到端（pristine→patch→幂等→restore 字节级一致 ✓×5）。
   守卫位点漂移链补全：269602:50a5639 → 270094:5378ea9 → 270097:537d599 →
   **270091:5376609 → 270093:5378cf9 → 270095:537d5a9 → 270096:537d589 →
   270098:537ddb9** → 270099:537de29。270080-270099 目录缺口只剩 270092
   （CDN 无该文件，疑似从未发布）。新增通用验证 harness：
   `WXKEEP_BACKFILL_DYLIB` + `WXKEEP_BACKFILL_JSON` 环境变量驱动的
   BackfillRoundtripTests（未来回填 SOP 直接复用）
2. **runtime 地址表外置（day-0 数据通道）**：runtime.json 增 `hooks` 数组
   （uuid/arch/hook_off/msg_arg/xml_sso_off/expected），dylib 侧
   hook_row_parse 全字段过门（UUID 形制/hex/长度匹配 arch/arm64 序言无
   PC 相对编码——ADRP/B/BL/CBZ/TBZ/LDR-literal 编码级过滤）；外部表在场
   则只用外部表，否则回落编译期内置表。`runtime install` 经
   RuntimeConfig.mergeKnownHooks 按 uuid 合并写入（未知 uuid 行保留，
   tip_text/rewrite_self 用户键透传）。新构建支持 = 数据一行，dylib 不重编
3. **M-R3-lite {from} 占位符 + 自发撤回门**：tip_text 支持 `{from}`（展开为
   原内文首对引号内昵称，>64B 或超缓冲放弃保原文）；`rewrite_self`（默认
   false）——「你撤回了一条消息」自发提示默认不改写（RecallKeeper 语义）
4. **arm64 hook 机器就位**：install_hook 双路径（x64 12B movabs/jmp 不变；
   arm64 16B `ldr x17,#8; br x17; .quad` + 蹦床 + `sys_icache_invalidate`，
   依据=调研实证 wechat.dylib arm64 切片无 PAC/BTI）。缺 arm64 wrapper
   地址行（RE 待做）——机器+解析门已测，数据到手即用
5. **270099 二进制级屏蔽更新破局**：XAppUpdateManager 在 4.1.15 回归
   （91 方法+SPUUpdaterDelegate），Sparkle.framework 2.6.4 fork 重新在位
   且被 dylib 直接链接——269602「纯 C++ 更新器」结论对该构建失效。
   locate_update_x64.py 修掉 relative 方法表 imp 解析 bug（偏移相对 imp
   字段自身 entry+8，按 name 字段解析会落在真入口前 8B 填充区——270099
   startUpdater 处穿帮成 `dec [rdi]` 才暴露；NOP 前导假象同时解释了此前
   「看似正常」的错位）。四条 update 条目（startUpdater/checkForUpdates:/
   startBackgroundUpdatesCheck:/enableAutoUpdate: → C3，expected 554889E5）
   已入 config.local 并过 pristine 端到端。待真机行为验证 + arm64 同轮
   （详见 findings-269602-updater.md 2026-09-18 节）

**顺手修复**：arm_late 定时器 retain cycle（__weak 打破 source→block→source
环，ARC 实证 -fobjc-arc 在场）。

**未动（诚实边界）**：arm64 wrapper/parse 的 RE（M-R2 arm64 行）；update
条目真机行为轮（启动后偏好重写是否停止）；270092 永久缺口维持；抢红包/
撤回转发等新功能面（非防撤回核心，未立项）。

### ⑪ 全代码审查 + 270100 现场事件（2026-09-18 晚，独立会话）

**全源码审查（Sources/ 22 文件 + runtime.m 逐行）**，修复六项、全部带回归：

1. **Config.validate 新安全不变量（最重要）**：`asm` 写入跨度 ≤ expected 溯源
   跨度（max 变体 byteCount）。原 expected 门只比较 expected 长度的前缀，
   asm 更长的条目会覆盖无出处尾部字节且 restore 无法回补——catalog 拒载是
   唯一安全侧。全量 463 条真实 entry 程序化审计 0 违例；通配/等长/短于形态
   均有测试锁定（ConfigLocalTests.asmSpanBeyondProvenanceIsRejected）。
2. **Engine.patch 半套态防线**：多 target 顺序补丁中前一个已写盘、后续失败
   抛错时不再跳过重签——尽力补签（成功=可启动、doctor 报 mixed）+ 失败给
   人工恢复指引，再抛原错。与 runtime install 回滚同哲学（2026-09-18 事故
   防线推广到 catalog patch 路径）。
3. **runtime.m 三处**：expand_tip 昵称缺失时 memcpy(dst,NULL,0) UB 消除；
   install_hook 的 mprotect 失败路径补 munmap+g_hook 复位（原泄漏 RWX 页且
   残留武装态字段）；定时器 cancel 加 nil 门（dispatch_source_cancel(NULL)
   在 libdispatch 显式 CRASH）。
4. RuntimeStatus 双重 JSON 解析合一；UpdateGuard 头注释的「269602+ 纯 C++
   无 ObjC 更新器」表述按 ⑩ 发现修正；Doctor 死 MARK 清理；Config.PatchEntry
   缩进修正。

**审查过不改的（有意的，防引入新问题）**：inline hook 入口 12B 写的非原子性
（线程竞争窗口=微秒级、Dobby 同款行业限制，线程挂起方案风险更大）；Patcher
callerCount O(N×text)（仅配方期）；isRevokemsg 谓词化等既有设计——均有实测
依据，维持现状。

**270100 现场事件（重要情报）**：审查期间本机微信被热修通道从 270099 自动
升级到 **270100**（营销版本同为 4.1.15）——「每日热修」节奏与 auto-update
威胁的活体实证（270099 的偏好层防护在位但字节级 update 未打，升级照常发生）。
**配方引擎 day-0 表现**：`wxkeep locate` 双架构命中（x64 0x4E8D5D0 /
arm64 gen3 0x4BC4FA4）+ 解析守卫 0x537dfb9（漂移链 270099:+0x1F0），端到端
往返验证通过——未适配新构建时配方自动兜底的完整闭环首秀。
守卫位点链更新：…270098:537ddb9 → 270099:537de29 → **270100:537dfb9**。

### ⑫ hooks 表家族化 + 目录晋升（2026-09-18 深夜，同审查会话续）

1. **runtime hooks 地址表扩到 4.1.15 全家族（7 构建）**：新工具
   `tools/derive_runtime_hooks.py`（守卫位点→LC_FUNCTION_STARTS→parse 唯一
   E8 调用者→wrapper 入口→12B 纯栈序言门→LC_UUID）从官方 DMG 派生
   270091/93/95/96/98/99/100 全部 7 行（expected 全部
   554889E54157415641554154）。**方法论互证**：270099 行（0x537d910 +
   UUID 97e21436…）与 drive22 实弹定案的内置表逐字段一致。行进
   RuntimeConfig.knownHooks，`runtime install` 随装写入 runtime.json；
   新增跨边界回归测试（knownHooks JSON → C 侧 hook_row_parse 全数通过 +
   uuid/build 唯一性）锁死两侧行 schema 漂移。⚠️ 诚实边界不变：
   wrapper+0x130 偏移为家族同构推定，首次实机验收未做。
2. **270100 update 条目**：XAppUpdateManager 四方法（startUpdater/
   checkForUpdates:/startBackgroundUpdatesCheck:/enableAutoUpdate:）imp 与
   270099 逐字节相同（热修未动该区域，slice md5/UUID 不同已核实）——
   条目直接沿用，revoke+update 7 条目端到端往返通过。
3. **目录晋升**：config.local 的 9 构建（270091/93/94/95/96/97/98/99/100）
   36 条目按 Config.merge 语义合入签名 config.json（source 溯源全保留），
   manifest 重签（keys/release.key），COMPATIBILITY.md 再生成（64 构建），
   97 测试全绿。此后新用户 `update-data` 即得全家族支持；config.local
   保留为备份（合并幂等）。

### ⑬ 真机验收轮（2026-09-19 凌晨：两真缺陷实弹揪出并修复，overall=protected 达成）

**微信 270100 实机全链**（patch → verify → runtime install → launch → 行为观测）。
这一轮的价值在「验收揪 bug」——两个此前测试网完全漏掉的真缺陷被真机暴露：

1. **区域扫描直解引用崩溃（P0，实弹崩溃）**：首次 launch 即 SIGSEGV @
   0x7ff800000000（ips: find_wechat_base_by_region_scan）。⑨ 的修复
   （查当前 protection 可读）**被证伪**——该共享缓存孔洞的 vm_region
   basic_info 报告 protection 含 R，访问照样 KERN_INVALID_ADDRESS。
   唯一可靠防线 = `mach_vm_read_overwrite` 安全探针（probe_match_target：
   header+load commands 拷进本地缓冲再比对；读失败返回错误码不崩）。
   protection 降级为启发式预筛，直解引用在全路径禁止。
2. **runtime 配置/markers 的沙盒路径缺陷（P0，静默失效）**：微信是沙盒
   应用（app-sandbox + App Group），NSSearchPath 的 ~/ 在其内部展开到
   **容器**——CLI 写的真实 home runtime.json dylib 读不到、marker 写进
   容器 CLI 看不到（marker=marker-only status=9 实证）。修复：统一走
   **App Group Container**（5A4RE8SF68.com.tencent.xinWeChat，双端唯一
   可达位点）：dylib containerURL(…)（非沙盒宿主 nil 回落 legacy）、
   CLI 直拼真实 home；旧路径保留为迁移种子。连带修复 runtime.json 格式
   缺陷（CLI-JSON / dylib-plist 不兼容——现统一 XML plist）与 status
   显示路径同款 bug。新增 plist 端到端测试缝
   （wxkeep_runtime_test_load_config_file）锁死跨格式回归。

**验收结果（全部通过）**：
- patch：revoke 3 + update 8 条目写入，strict verify OK，wxkeep verify
  行为级证明（isRevokemsg 全探针归零）
- runtime：LC 注入 + dylib 加载 + **hook-armed**（marker status=13 =
  armed+callback，构造器→scan→install_hook 全链真机走通）
- update 行为：SUEnableAutomaticChecks 启动后保持 0；SUAutomaticallyUpdate
  经判别实验（退出→重写 0→重启→观察 60s）**保持 0**——访问器对补丁
  （automaticallyDownloadsUpdates getter→0 / setter→ret、canCheckForUpdate
  对）拦住了改写者，此前观测的 1 是补丁前启动的残留值
- doctor overall = **protected**（revoke/update 双 patched）

**新情报**：270100 的 C++ 更新器字符串锚点更名（MacStoreUpdate.xml →
`MacUpdate_%@.xml` 格式串，与 StartCheckUpdate/try check update 混在
混淆串里）；行为层已被上述补丁封死（无改写/无弹窗/无自动下载路径），
深挖其引用链暂无必要。locate_update_x64 访问器对（getter/setter）在
270100 的 imp 较 270099 漂移 +0x20。

**备份保留策略**：Backup.make 增 prune（同前缀保留最新 3 个，时间戳
字典序即时间序）；locate 的 config.local.json.bak.* 同规；存量清理完毕。

### ⑭ 补遗（2026-09-19 晨：隔离区清欠 + arm64 表全家族 + hook 内存级实证）

1. **arm64 hooks 行补齐全家族**：270091/93/95/96/98 五行派生（同款拓扑 +
   序言门全过，expected 与 270099/100 逐字节相同）——runtime.json 地址表
   达 14 行（7 构建 × 双架构），kMaxExtHooks 16 内。重装后真机复验 armed。
2. **hook 武装的内存级实证**：lldb 只读附加存活进程，wrapper 入口 12B =
   `48B8…FFE0`（movabs rax,jmp rax 直指 hook 函数）——安装真实性从 marker
   声称升级为字节证据（tools/dyntrace 思路，270100 位点 0x537daa0）。
3. **backfill 流水线接入 CDN 归档源**：官方 CDN 按 营销版本_构建号 归档
   dmg（非 XZ、无限制），插入为首选候选（hints 表提供营销版本），zsbai
   降为回落。本地实跑 269629/269631 各 2 条 x64 隔离条目回填官方原始字节
   （je rel32 + 函数序言），隔离 86→82。剩余 82 条为 CDN/zsbai 均无归档的
   3.x–4.1.12 时代构建——**回填队列实质清空**（余量永久缺口）。
   教训：脚本 zsbai 回落对慢网不可控（urllib 900s×多候选）且输出全缓冲，
   本轮以 curl 断点续传 + 手工提取收尾；CDN 源上线后该路径仅剩历史价值。

### ⑮ 第二轮复查（2026-09-19 晨：新堆代码精读，修复三处）

对 ⑬⑭ 新增代码的复查结论与修复：
1. **RuntimeStatus 补 hook 武装状态行**（设计缺陷）：此前「整体: 已启用」
   在 dylib 加载但 hook 未武装时（构建无匹配地址行/序言不符）具有误导性
   ——现解析 marker 的 mr2= 字段显式区分「已武装/未武装/未知」。
2. **`wxkeep runtime hooks` 子命令**（流程缺口）：runtime.json 刷新原先
   必须走完整 install（退出微信+重签+换 dylib）；实际只需重写配置文件
   （dylib 仅启动时读取）——新命令免退出免重签即刷新地址表。
3. install/status 的构建列表去重显示；header 里 M-R1 时代死声明清理。

复查确认无问题的（有依据）：@autoreleasepool 内返回 NSString（ARC
autoreleaseReturnValue 安全）；expand_tip 多占位符上界（cap 检查放弃）；
Backup.prune 前缀匹配无跨二进制误删；restoreAsm 与新 validate 不变量的
交互（inverted 条目 asm=restoreAsm ≤ 原跨度恒成立）；外部表 14 行 ≤
kMaxExtHooks 16（越限有测试锁死）。

### ⑯ 第三轮复查（2026-09-19 晨：watch 流水线病根 + 防御性收紧）

1. **watch-wechat 失败根因判定与修复**：旧失败（51ad552，日志需 admin
   权限读不到）由代码侧定位——「Download & locate」步骤在 set -e 下，
   任一构建的 zsbai asset 403/404/XZ 损坏即杀死整轮；且 PR/issue 步骤
   从未执行过（仓库 PR/issues 全空实证）。修复：单构建故障隔离（下载
   失败/空 dmg/挂载失败均只记录转人工，不再中止整轮）+ 官方 CDN 构建
   归档直链作为 zsbai asset 失败时的自动回落（collector 输出补 tag 字段
   供构造 URL，bash -n + collector 对真实 API 实测通过）。
2. **runtime.m 防御性收紧**：uuid_matches 与 on_image_add 诊断走查的
   循环条件 `p < end` → `p + 8 <= end`——病态尾部数据时防 4B 越读
   （缓冲式调用路径；合法镜像行为不变）。
3. 实机 dylib 同步重装，armed 复验 ✅。

复查过不改：locate_update_x64 的 NOP 前缀长度启发式对 SIB 边角可能
短算（失败方向=拒绝条目，保守安全）；RuntimeStatus 已含全部诊断面，
doctor 不再重复（单一 verdict 原则）；测试缝符号未做 hidden（能调用
它们的威胁模型下本已可写内存，符号可见性不改变信任边界）。

### ⑰ 第四轮复查（2026-09-19：发布链审查——一条误报更正 + 两处收尾）

1. **「私钥入库」误报更正**：keys/release.key 在 .gitignore（仅 release.pub
   入库），CI 有「无私钥材料入库」守卫步、签名走 RELEASE_SIGNING_KEY
   secret——信任链完好，本地密钥与 CI secret 同源（双端签名对同一内嵌
   公钥验证通过互证）。复核方法教训：看到本地文件存在 ≠ 已入库，需
   `git ls-files`/`check-ignore` 实证。
2. **主仓 Formula 同步**：brew 用户实际消费的 0xGenesi/homebrew-tap 为
   0.1.3（当前最新 release），主仓参考副本停在 0.1.0——已按 tap 原样
   同步（含 config/signatures resource 段）。
3. **brew 安装的目录数据冻结问题**：tap formula 的 config/signatures
   resource 指向 v0.1.2 tag——brew 用户默认拿到旧 catalog。已有双兜底
   （wxkeep locate 配方 day-0 + update-data），README 安装节补
   `wxkeep update-data` 提示，消除盲区。
4. **runtime.json 原子写**：mergeKnownHooks 落盘改 .atomic——微信启动
   瞬间撞上写入会读到半文件静默回落内置表。

发布链其余（release.yml 单文件产物流程、ci.yml 双 runner 矩阵 + 私钥
守卫 + manifest-sign secret 流程、GUI 子包未入库、contribute_expected
machutil 化）核对无缺陷。
