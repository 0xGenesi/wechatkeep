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
