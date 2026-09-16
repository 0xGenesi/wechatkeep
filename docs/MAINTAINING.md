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

## x64 keeptip 定位方法论（2026-09-16 攻坚，269602 待真机验证）

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
- **macOS 15 taskgated**：见 README「AMFI 知识」——doctor 独家预检的由来。
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
- **[P4] next_command 语义**：unprotected 且 AMFI kill_predicted 时只给 patch 命令会让用户 patch 完启动即被杀——追加 boot-arg 前置提示。

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
- 结论：历史构建的 expected 回填暂无可靠免费源。隔离区条目维持 quarantine
  （引擎安全设计如此，不影响有溯源条目的正常使用）。

本轮流水线工程收获（已沉淀）：GITHUB_TOKEN 对外部仓库=匿名级（60/h 共享 IP 必 403）→
归档索引随仓库分发；XZ 解压的 suffix 要求与 brew xz 路径探测；下载 Content-Length
校验。整条流水线架构完备，待上游出现健康数据源即可启用。
