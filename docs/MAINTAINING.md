# MAINTAINING — 维护方法论（沉淀自 M1-M6 研发与各上游经验）

> 每个地址的推导来源、置信度、验证方式都要可追溯。本文件是新代签名适配的 SOP。

## 新构建适配 SOP

1. **先自动**：`wxkeep locate` 跑全部配方（或 CI 流水线自动跑）。
   - 命中且唯一 → 进入第 4 步（expected 门会兜底）。
   - 全部 miss → 新签名代，走人工流程（第 2 步）。
2. **人工定位**（参考 diff 法，学 fzlzjerry）：
   - 从 [zsbai/wechat-versions](https://github.com/zsbai/wechat-versions) 取邻近版本官方 dmg
   - `lipo -thin` 抽对应架构 slice，记录 slice SHA-256（审计日志用）
   - 在参考版本定位同源函数，将「屏蔽地址相关立即数后的指令形状」在新 slice 滑窗匹配
   - 用 capstone 反汇编验证（`/tmp/wxre/analyze.py` 模式：带 rip/adrp 引用注解）
3. **新配方入库**：signatures.json 加一条（anchor+derive+confirm），**不是**改 Swift 代码。
4. **字节门核对**：派生 entry 必须带 expected（现场读原始字节），过不了 = 定位错了，禁止放行。
5. **行为验证**（x64，需 SIP off 机器）：`wxkeep verify`。
   - 新构建的 PLT stub VA / magic-static 区可能变化 → 重新反解 verify spec 的 stubs/zero_regions。
6. **真机实测**：撤回一条消息（dry-run/编译/测试都不能替代最后这一步）。
7. **登记**：config.json 条目带 `source`；新签名代在本文末尾登记代际特征。

## 已知签名代（arm64 revoke，几何特征）

| 代 | 构建 | cbz 字节 | delta | newmsgid 字段 |
|---|---|---|---|---|
| 1 | 268575–269136 (4.1.10–4.1.11) | E00F0034 | +0x794 | 0x168 |
| 2 | 269332–269341 (4.1.12) | 40100034 | +0x7A0 | 0x198 |
| 3 | 269574+ (4.1.13) | 40100034 | +0x7A0 | 0x1C8 |

x64 revoke（imm64:revokems 锚点 + padding-boundary + unique-positive-callers）：
2026-09 在 269602 验证（0x4BC5940, 9 callers；已打补丁态靠双边界推导仍可定位）。

## x64 撤回处理链完整地图（2026-09-16 深挖，269602；keeptip v1 行为模型的基础）

工具链：LC_FUNCTION_STARTS 精确函数边界（勿再用 padding 边界猜测）+ E8 扫描必须过
对齐验证（位移字节误报教训：`cmp byte [rip+X],0` 的位移里就含 `E8 .. .. .. ..`）。

```
isRevokemsg 0x4BC5940 (9 真调用者)
isQyRevokemsg 0x4BC59E0 —— 第二分支=企业微信撤回（chat_id/revoke_climsgid），不是群聊!
TryParseMessage [0x50A5350, 0x50A67B0] —— 唯一调用者=wrapper 0x50A5120
  分支1 revokemsg: newmsgid→[this+0x1C8](u64), replacemsg→+0x1D0(string)
  分支2 qy_revokemsg: chat_id→+0x2C8, revoke_climsgid→+0x2E0, replacemsg
wrapper 0x50A5120 → 解析成功 → 0x50A67B0(obj, &obj->replacemsg) 后处理
  → 依次调 0x50AF090/0x50B0350/0x50B1600/0x50B2060(obj, replacemsg) 四类型处理器
  → 0x50B38F0(obj) 生成 +0x218 结果串
提示文本构造 0x50B4F10：含 "reeditrevoke" + "xwechat://reedit" 五分钟重编辑链接（自发撤回），
  按 0x4BC3FB0(obj)=([obj+8]==0x31 && [obj+0xC]==0x57) 选模板，写入 +0x1D0 和 +0x218
提示谓词 0x50B5EA0：isRevokemsg(xml) && [obj+0x288] > A->v50()-B()
type-10000 过滤器：0x4BC7400(msg->[0x218]content, [msg+8]==10000) / 0x4D6EFD0(+0x220,+0xC)
执行器 [0x36DBAE0, 0x36DC940]（唯一调用者 0x32ABD90 中转）：
  扫到达消息批次（0x278 尺寸消息结构），过滤 type-10000+isRevokemsg → 收集 id
  → 0x36F2DD0 每id构造异步任务（std::function 队列）→ 0x36DD7F0 解析 "_b13e0758" 服务
  → 对每条命中原消息：memcpy 0x278 模板 → 0x50B4F10 构造提示 → 0x36DB710(ctx,...) 原位更新
```

**行为模型（v1 补丁=清零 newmsgid 存储后，用户实测验证）**：
- 私聊：提示以 type-10000 消息随消息流到达 → 渲染不依赖查找 → **提示保留**（落点=到达位置，
  在原消息之后但不贴邻——用户反馈"不知道是哪条"的原因）；原消息原位改写需按 newmsgid 查找
  → 查 0 失败 → **原消息保留** ✓
- 群聊：撤回走带外通道，提示须由客户端按 newmsgid 查到原消息后合成 → 查 0 失败 →
  **整链静默：无提示**（消息保留）✓

**v2 方向（未实现）**：恢复 newmsgid 让查找成功，改掐下游破坏性步骤（在异步任务体内，
0x36F2DD0 派发的 lambda 链），使「提示插入原位 + 原消息内容保留」同时成立——两架构同源，
arm64 同样适用。需动态分析（另一账号触发真实撤回事件）辅助定位 lambda 体。

**v2 路线已被 Windows 阵营验证**（2026-09 调研，EEEhex/RevokeHook → zetaloop/BetterWX
revoke.py，Weixin.dll 4.0.6+，仅两条通配规则、无注入）：
1. 在撤回处理函数里把 `call DeleteMessage`（特征 `48 8D 55 C0 / 45 31 C0 / E8 ?? ?? ?? ??`
   / `48 8B BD 48 04 00 00 / 48 85 FF`）替换为 `SrvID += 1`——删除不执行，且为提示记录
   铸一个新服务端 ID，使提示作为**新消息插在原消息下方**；
2. 在 `AddRevokeTipToDB→…→CoAddMessageToDB(…, flag)` 的调用点把第 5 个 bool 参数
   （`C6 44 24 20 00` = mov byte [rsp+0x20],0）改为 1，DB 才接受本地自造的 SrvID。
已知瑕疵：提示需重进会话才刷新；自己撤回的边角行为未完美。macOS 对应物应在
0x36DBAE0 执行器链内（删除/原位改写步骤 ≈ 规则 1 的 DeleteMessage；提示入库链
0x36DB710 ≈ 规则 2 的放行标志）。

## x64 keeptip v1 定位方法论（2026-09-16，269602 已真机验证：私聊提示✓ 消息保留✓）

**核心结论：arm64 的撤回处理函数与 x64 的 TryParseMessage 是同一函数**（证据：
都先调 isRevokemsg，为假时转同一形态的第二检查器；都按 newmsgid → replacemsg
顺序懒初始化全局串并解析 XML；解析结果写入同一 C++ 结构）。

定位步骤（在新构建上复现）：
1. `imm64:newmsgid` 锚点在 __text 命中数处（TryParseMessage + 日志/服务层片段）。
2. 唯一目标 = 命中点前方短窗内存在 movabs "revokems" 惰性初始化、且紧随其后
   出现 `E8 ???????? 48 89 ?? C8 01 00 00`（call 转换器 + 存 [reg+0x1C8]）的那处。
3. 补丁点 = 该 call 的起始（覆盖 call+store 共 12 字节）：
   原 `E8 rel32 | 48 89 83 C8 01 00 00`（newmsgid 串→u64 转换后存入 [this+0x1C8]）
   改 `48 31 C0 66 90 | 48 89 83 C8 01 00 00`（xor rax,rax; 2字节nop; 原样存储）。
   存入 0 → 下游按 newmsgid 删除落空，replacemsg 灰条提示照常 —— 与 arm64 keeptip
   语义一致（zengtianli 验证过的机制）。
4. 安全性：被跳过的转换器（269602 为 0x4F38270，c_str+strtoull 包装）是纯函数；
   call 移除对 ABI 无影响（call 本就 clobber 全部易失寄存器，r13/rbx 等被调用者
   保存寄存器不受影响）。

注意：
- **精确 VA 条目跨构建必然失效**——E8 的 rel32 与 modrm 基址寄存器都可能变，
  新构建需按上述步骤重定位并重读 expected，勿直接复制 269602 字节。
- 269602 上旧的 x64 keeptip 尝试点 0x32A0D9D（mov rdx,rax 清零）删除的是
  「日志/服务层片段函数」的指针参数，与删除路径无关——该条目已改造为
  清理恢复型（旧补丁存在则还原，幂等）。

## 误改与踩坑记录（防重蹈）

- **~~x64 结构偏移 ≠ arm64~~（2026-09-16 推翻）**：newmsgid 字段两架构同为
  +0x1C8（同一 C++ 结构）。M2 的旧结论源于当时只扫到 TryParseMessage 之外的
  日志片段、未定位到真正的解析函数——**跨架构不能假设「无此访问模式」，
  只能假设「未找到」**。
- **fixture 代码区撞段表**：合成 Mach-O 的 0x40–0x68 是 vmsize/fileoff 字段，测试代码必须放 load command 之后（≥0x68）。
- **已打补丁状态会污染边界扫描**：补丁自己的 `ret+NOP` 构成第一个函数边界 → padding-boundary 取前两个边界（M2-1）。
- **dlopen 路线不可行**：wechat.dylib 依赖 app 内框架 + Qt 初始化器在 app 外崩溃（M2-3 spike 判死）。
- **Swift `load()` 严格对齐**：读未对齐 rel32 必须逐字节组装（Verifier 实证）。
- **Swift 数组不是 C 数组**：`withUnsafeMutableBytes(of: &array)` 传的是数组头（指针+count），必须用 Array 自己的 withUnsafeMutableBytes（Verifier 实证）。
- **macOS 15 AMFI（2026-09 复盘改写）**：ad-hoc 重签 + 保留 restricted entitlements
  在原生 SIP 开启机器上可正常运行（zengtianli/fzlzjerry 双实现 + 大用户群实证；
  sunnyyoung #1038 闪退根因是 entitlements 被**剥光**）。doctor 降级为 watch 级提示
  （崩溃日志取证指引），不再处方 AMFI boot-arg；重签须 `--force-library-entitlements`
  （macOS 15+ codesign 默认丢弃库文件 entitlements）。
- **漂移比对的目标态**：重签后比对「原始+注入键」而非「原始」，否则自家注入被误判永久漂移（M3-1 实证）。
- **codesign 拒绝合成 Mach-O**（"main executable failed strict validation"）：集成测试用 clang 现场编译真二进制（M3-1 实证）。
- **JSON 数字 vs 字符串**：signatures.json 的 spec 数组元素必须全字符串（Codable 严格类型，M4 实证）。

## 269602 更新器（开放项）

`XAppUpdateManager` 在 269602 双 slice 均不存在（66 个 ObjC 类里只有 Qt/媒体/FileProvider/设置类）。
更新逻辑为纯 C++（字符串证据：`StartCheckUpdate`/`CheckForUpdates`/`MacStoreUpdate.xml`，Sparkle 文案静态链入）。
下一步：以这些字符串的代码交叉引用为锚点做双架构定位。详见 `findings-269602-updater.md`。

## 代码审查记录（2026-09-15，v0.1.0 后首轮）

已修复：
- **[P0] ResignerTests 硬编码 `.x86_64`**：arm64 CI runner 上 clang 产出 arm64 dylib，MachImage 找 slice 即抛错（CI 必红）。改为编译期按宿主架构选择，catalog entry 同步。
- **[P1] Patcher.resolveRecipes 吞错**：`try?` 把配方失败（歧义/新签名代/缺 slice）降级为 noArchMatched，误导排障方向。改为传播 `recipeResolutionFailed`（带真实原因）。
- **[P2] patchedBinaries 重复**：同 binary 多 target 时重复 append → 同一文件被重签多次。改为每 binary 记一次。
- **[P3] doctor nvram 双调用**：竞态+浪费，改单次。
- **[P4] next_command 语义**（2026-09 复盘后失效留档）：AMFI 判定已降级为 watch 级、
  不再处方 boot-arg（见上方 macOS 15 AMFI 条目）；next_command 只给 patch 命令。

观察未修（低风险/有实测依据，改动需权衡）：
- **Shell.run 未读 terminationReason**：信号死亡判定依赖 `status == 128+signal` 约定（本机 SIGILL=132 实测成立）。若 Foundation 行为变化，应改用 `terminationReason == .uncaughtSignal`。
- **callerCount 每候选全扫 __text**：O(N×170MB)，实测秒级可接受；多候选场景可优化为单遍调用计数表。
- **silent 请求但 catalog 只有 keeptip 条目**：抛 variantUnavailable，不自动降级为「恢复 cbz」（zengtianli 语义支持降级；当前无此形态数据，暂不做）。
- **verify worker 长字符串 probe（≥23 字节）被跳过**：SSO 长串构造未实现，当前 spec 全短串。

## 第二轮审查（同日，逐文件精读）

已修复：
- **[R7] RecipeEngine 残留两处 WXKEEP_DEBUG 调试块**（M2 清理不彻底）——删除。
- **[R4] Engine 头注释过期**（还在说 M3 未接线/--ack-no-resign）——更新。
- **[R14] Shell.run 顺序读双管道**：先 drain stdout 再 stderr，子进程 stderr 超 64KB 管道缓冲即死锁（codesign verbose 对 340MB bundle 可能触发）——改并发读取+锁。
- **[R10/R11] verify worker 越界写风险**：zero 区 memset、GOT 槽写入、调用 VA 均未验界——坏 spec 会先污染映射邻接内存再崩（错误不可读）。全部加边界 guard → exit(3) 明确失败。

观察未修：
- restore 路径不做备份（写入内容本身就是 expected[0] 原始字节，expected 门兜底）。
- probe 文本含 "|" 会破坏 worker 输出协议解析（当前 spec 无此字符）。
- resolve 的 confirm 注释说 "exactly one"，实现是"过滤后剩一"（语义等价，措辞差异）。

## 第三轮审查（同日，数据层 + workflow + 工具链）

数据审计（程序化全量 422 条 entry）：
- 两个初判「问题」经核实均为审计脚本自身误判：keeptip 恢复型条目 asm==expected[0] 是设计语义（幂等重打）；signatures/config 比较是 list vs string 类型差，值一致。**数据层 0 问题**。
- 重复键 / 坏 hex / 空 addr / 重复 version：均无。

已修复：
- **[W1] watch-wechat.yml 的 `if:` 用字符串比较构建号**：GitHub 表达式 `>` 是字典序，构建号位数变化（如 5 位 vs 6 位）时误报/漏报新版本。改为 shell 内 `-gt` 数值比较输出 need_report 布尔。

观察未修：
- merge_catalogs.py 的 SOURCES_PRI 全局字典在 main 定义之后初始化（依赖模块级执行顺序，重构时易踩）。
- ci.yml 的 `wxkeep versions || true` 依赖无 WeChat 环境下的报错路径（有意的冒烟）。

## 第三轮审查（同日，数据层 + workflow + 工具链）

数据审计（程序化全量 422 条 entry）：重复键 / 坏 hex / 空 addr / 重复 version 均无；
两个初判「问题」经核实均为审计脚本自身误判（keeptip 恢复型条目 asm==expected[0]
是设计语义；signatures/config 比较是 list vs string 类型差，值一致）——数据层 0 问题。

已修复：
- [W1] watch-wechat.yml 在 if: 表达式里用 > 比较构建号——GitHub 表达式的 >
  是字符串字典序比较，构建号位数变化（如 5 位 vs 6 位）时会误报/漏报新版本。
  改为 shell 内 -gt 数值比较输出 need_report 布尔。

观察未修：
- merge_catalogs.py 的 SOURCES_PRI 全局字典在 main 定义之后初始化（依赖模块级
  执行顺序，重构时易踩）。
- ci.yml 的 versions || true 依赖无 WeChat 环境下的报错路径（有意的冒烟）。

## 隔离区回填：数据源鉴定结论（2026-09-16 迭代会话）

zsbai 归档的 dmg 资产为 XZ 重压缩格式且**文件尾无 XZ footer magic（YZ）**——上传侧
已损坏或非标准封装（头 6 字节 XZ magic 正确、Content-Length 完整 496MB、xz -d 仍报
"Compressed data is corrupt"）。`--single-stream` 部分解码不可靠（dmg 截断后 hdiutil
无法挂载）。

可行替代源：
- 官方 CDN 直链（release body 的 DownloadFrom 字段，dldir1v6.qq.com）——仅对**当前
  最新版本**有效（滚动分发，旧版 404）
- tanranv5 fork 的 config.json（2026-09-17 核实）：条目仅 `arch/addr/asm` 三字段，
  **无任何原始字节字段**——x64 隔离条目的源头本身不带 expected，数据层回填死路
- 结论：历史构建的 expected 回填暂无可靠免费源。隔离区条目维持 quarantine
  （引擎安全设计如此，不影响有溯源条目的正常使用）。

本轮流水线工程收获（已沉淀）：GITHUB_TOKEN 对外部仓库=匿名级（60/h 共享 IP 必 403）→
归档索引随仓库分发；XZ 解压的 suffix 要求与 brew xz 路径探测；下载 Content-Length
校验。整条流水线架构完备，待上游出现健康数据源即可启用。

## v2 追踪会话沉淀（2026-09-16 深夜，269602 x64）

**lldb 基建教训**（tools/dyntrace/ 存档了可用脚本）：
- wechat.dylib 由主程序 dlopen 后 dlsym 调 `WeChatMain`（仅有的两个导出符号之一）——
  `breakpoint set -n WeChatMain` 是可靠的"模块就绪"哨兵
- `breakpoint set -s wechat.dylib -a <va>` 在此 lldb 版本把 -a 当绝对地址（不解析 pending），
  全部断点空挂；正确做法：WeChatMain 命中后按 `__TEXT load base + va` 设绝对断点
- `SetScriptCallbackFunction` 多次注册触发 KeyError（autogen 包装冲突）；断点命令列表里的
  `echo`/输出在此版本被吞；可靠通道=顶层 `script print` + 事件循环（drive.py）
- lldb 默认关 ASLR：wechat.dylib __TEXT base 两轮恒为 0x11B008000，可硬编码+地面真值校验
- 后台会话必须用托管后台任务；`&` 启动的 lldb 随 shell 退出被杀，微信孤儿化（表面正常、
  断点全空——排查用 `ps -o ppid` 确认微信父进程是 lldb）

**新链路事实**（修正先前模型）：
- 撤回查找执行器 0x36D4A10：按 newmsgid(+0x1C8) 构造查询 → 0x1A215C0 查找 → 结果写
  obj+0x288；企微分支按 chat_id(+0x2C8)/revoke_climsgid(+0x2E0)。调用者 0x36D58D0/
  0x36D9120 ← 分发器 0x32E5D40 ← HandleNewXMLMsg。**动态实证：对方撤回时该家族零命中**
  → 判定为自发撤回/同步路径，非对方撤回主路
- 0x32AD4D0（两个分发目标共调）＝撤回主力：查找收集(0x30DB570)→0x32ABC90(16调用者的
  通用消息处理器)→0x32ABD90→0x36DBAE0 执行器。同样动态零命中——同属非主路
- TryParseMessage 唯一调用者 0x50A5120(wrapper) 是 vtable 虚方法：vtable@0xA3FBE98
  槽位 +0x18（`dyld_info -fixups` 解码 chained fixups 找到——vtable 引用静态定位的标准
  手段）；0x340 结构工厂 0x503D990 在 +0x18 内嵌该解析器
- 解析框架：0x28EE90(构造,三 vtable) → 0x28EF80 → 0x28F0D0×4(0x128 步长四类槽) →
  wrapper(slot+0x18) + 0x50A5110(slot+0x10 取结果)；工厂族 0x28B630/0x29B9E0/
  0x29FA50/0x2A2910
- **下一步（唯一硬需求）**：只断 wrapper 0x50A5120（单断点防过载冻结），一次对方撤回
  的 bt 即锁定真实消费链 → 定位删除调用 → 按 BetterWX 两规则法落地 v2

## 字符串解密器（2026-09-17，tools/decrypt_strings.py）——免 IDA 的符号恢复

看雪 thread-286611（Windows 4.0 符号恢复）方法论的纯静态移植：微信 4.x 的
xlog 日志串运行时解密，循环形态固定：
`out[i] = (BASE[data_off+i] + addend) ^ BASE[key_off + (i%20)]`
（20 字节滚动密钥来自 mul 0xCCCC..CD+shr2+and~3 的 mod-20 运算推导）。
工具扫 __text 四种编码形态的解密循环并现场模拟，产出「函数→字符串」映射。

**269602 x64 实测：139 串 / 115 函数，核心产出——`message_revoke_manager.cc`
全家族 24 函数**（0x36BA000–0x36EDB50）：含已知分发目标 0x36D58D0/0x36D9120、
查找执行器 0x36D4A10、批扫描器 0x36DBAE0，及 13 个未探索新函数
（0x36BA000/0x36BB210/0x36C15C0/0x36C2630/0x36C4840/0x36C5A70/0x36C6CD0/
0x36C9790/0x36CFB80/0x36D0190/0x36D0B20/0x36DB0B0/0x36EDB50）——
**对方撤回真实入口优先在这 13 个里找**（旧候选断点零命中之谜的答案方向）。

v2 A/B 实验修订：用 `decrypt_strings.py --grep` 命名全部 revoke 家族函数 →
在 message_revoke_manager.cc 家族中找 Windows CoReplaceOriginMessageByRevoke
的 macOS 孪生（特征：DeleteMessage 调用 + 提示插入，参考 r8 结构
+8=type(0x2710)/+0xC0=srvid/+0x118=sysmsg，跨架构偏移需本地重推导）。
