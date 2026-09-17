# 路线图（待办归档）

## 已归档待办

### ① 解析守卫 branch-flip（冗余 silent）——工具已交付，配方化待 DSL 扩展
已交付：`tools/locate_x64_parse_guard.py`（269602 实测：isRevokemsg 9 调用者 →
8 处 `test al,al; je` 守卫 → 按"函数体含 newmsgid 存储"甄别出解析守卫
**je@0x50a563b，expected 0F84A6000000，asm E9A700000090**，支持 --append）。
剩余：RecipeEngine 的 expected 门是静态字节，call/jump 的 rel32 逐构建不同，
自动配方化需 DSL expected 通配/掩码扩展（confirm 的 `bytes@+off:mask` 思想）。
方案：expected 支持 `XX??????XX:mask...` 通配语法（掩码思想已在 confirm 的
`bytes@+off:mask` 存在，扩展到 expected 即可）。
位点族已存档（269602 x64：isRevokemsg 9 调用者中 8 处 `test al,al; je +disp32`，
解析函数内 = 0x50a5634）。完成后：未来 x64 新构建获得第二条独立 silent 路径
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
   旧判定。状态：待实机验证。
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
