# V6-DEPTH — 「更深而非更大」需求重写·第三代（2026-11-04）

> 原始需求（同句第三次重提）：「我需要这个程序的更深版本，而不是更大版本。」
> 前两代答卷：[V3-DEPTH.md](V3-DEPTH.md)（D1-D7 / L1-L6 / R1-R6）、
> [V5-DEPTH.md](V5-DEPTH.md)（D8-D13 / L9 / R7-R12，125-132 轮已执行）。
> 本文是第三代。**前两代把防线立了起来；这一代把「防线有效」的证明从抽样
> 升格为穷举**——产品代码零变更（R18 反目标），全部深度落在证明的完备性上。

## 0. 第三代的定位：从「有防线」到「防线被穷举证明」

V3/V5 立起的主张，今天的证明形态全是**抽样**：

| 已立主张 | 现行证明 | 抽样形态 | 穷举形态 |
|---|---|---|---|
| 「写入失败后可收敛」（A1/A2） | M08 一个杀例 + journal 测试 | fail-at(0) 单格 | **每个写位点一格**（L10） |
| 「状态机不变量成立」（L2） | 固定 6 态 + 1 条链 | 一条手工路径 | **全部 ≤3 长命令序列**（L11） |
| 「expected 门挡错版」（A5） | 单字节篡改负控 | 单点负控 | **他构建×本二进制全矩阵**（L12） |
| 「写入局部性」（L9 --patched） | 单文件位点级 | 单文件 | **bundle 全树差分**（L13） |
| 「全绿 = 对」 | 散落台账 + prose notes | 人读 | **机器可核验证据台账**（L14） |

## 1. 顶尖专家会怎么做（第三代：V5 之后的缺口，全部有勘察实证）

| # | 专家实践 | 本仓 V5 后状态 | 133 轮落点 |
|---|---|---|---|
| D14 | **崩溃点穷举矩阵**（SQLite/LMDB 学派：故障注入测试覆盖每条写入路径的每个中途点，而非代表性样本）：对每条变更命令的**第 k 个写位点**注入 fail-at(k)，逐格断言恢复收敛不变量 | `Patcher.debugWriteFailureAt` 缝在位（126 轮立），但只有一个用例（M08 杀例 fail-at-0）；「任何 k 都收敛」从未被证明 | **L10**：`CrashMatrixTests`——5 命令场景 × 各自全部写位点（20 格），每格断言五不变量（§3） |
| D15 | **有界模型检查**（TLA+/QuickCheck 学派：不变量在**全部** ≤N 长行为序列上成立，而非脚本）：命令字母表 BFS 穷举 | L2 固定链 silent→keeptip→…→restore 是**一条**路径；「脚本对 ≠ 状态机对」——5^3=125 条未测序列里任何一条都可能翻车 | **L11**：`StateMachineExhaustiveTests`——5 命令字母表，深度 3 全序列（155 条），每序列独立副本 + 逐步幂等/合法性/右零元断言 |
| D16 | **负空间完备性（混淆矩阵）**：判别器的价值在拒绝——他构建条目 × 本构建二进制的全矩阵**零假接受**才是「挡错版」的证明；同时如实刻画判别力边界（共享字节 = 字节门不可判别） | 只有「翻转单字节必报 unknown」；「错版目录数据」这一 A5 威胁的判别力从未被系统测量——共享序言（stp 序言在 4.x 家族大量复用）下 expected 门对错版条目**按设计放行**，这从未被写成显式契约 | **L12**：`ConfusionMatrixTests`（合成全矩阵：互异字节非对角必拒 + 共享序言对接受=设计边界入测）+ `tools/verify_confusion_matrix.py`（真切片只读抽样矩阵台账） |
| D17 | **作用域升格**：写入局部性主张从「单文件位点级」升到 **bundle 全树**（patch 修改的不止主目标——备份文件、签名面；主张必须覆盖整棵树） | V5-DEPTH §5 显式登记：「全 bundle 级（多文件+Info.plist 面）未做」 | **L13**：`BundleEffectTests`（合成镜像：诱饵 Mach-O/Info.plist/framework 逐字节不动）+ `tools/verify_bundle_effect.py`（真件：pristine vs patched 全树差分 ⊆ 声明写集 ∪ 备份 ∪ 签名面，含位点外注入负控必红） |
| D18 | **证明随行（proof-carrying release）**：发版携带机器可核验的证据台账——第三方不读 prose 也能复算「这一版凭什么说全绿」 | 证据 = release notes 散文 + `var/logs/` 散落台账；无统一 schema、无一致性引用（台账文件可能被后续轮覆盖） | **L14**：`tools/gen_evidence_ledger.py`——扫描各 L 族台账 → evidence-ledger.json（每条：文件 sha256 + 结论行 + git HEAD）；发版 SOP 接线 |

## 2. 专家使用的原始数据与工具（第三代增量）

**既有缝直接复用**（零产品代码变更的根基）：`Patcher.debugWriteFailureAt`
（DEBUG-only URL 限定写故障缝，126 轮）、`Resigner.debugAttemptHook`（观测缝）、
`MachOFixture`（VA==fileoff 合成镜像）、`Engine.patch/restore` 全真实编排链。

**工具**：swift-testing 合成夹具（CI 常跑，绿=跑过）；Python 孪生第三/四例
（混淆矩阵计划驱动 + bundle 差分独立复算——不复用 wxkeep 自身的 diff 逻辑，
独立 lipo/哈希实现）；`codesign`/`lipo` 外部判官（真件腿）。

## 3. 外部客观标准（第三代判据表，全部机器可核验）

| 标准 | 判据 |
|---|---|
| **L10 崩溃矩阵** | 每命令 × 第 k 写位点注入后：①抛错类型正确（`PartialWriteFailure` 族——journal 必须保留给 doctor 判读）②失败瞬间盘面全部位点 ∈ 合法集（inspect 零 `.unknown`）③restore 收敛后位点级字节 == pristine（签名尾是恢复重签的设计内噪声，位点级直证把收敛语义与局部性语义解耦——局部性归 L13）④**崩溃后恢复 == 干净直打**：restore 后再 patch 的位点字节与对照副本恒等（跨崩溃路径确定性）；⑤恢复重签防线按命令分流断言（patch 场景 `debugAttemptHook` ≥1；restore 场景按设计 ==0——`Engine.restoreTargets` 失败无恢复重签，journal+doctor interrupted 承接） |
| **L11 状态机** | 全部 ≤3 长命令序列（155 条）：①每步后全 target inspect 零 `.unknown` ②X;X == X（**净效应幂等**——重复执行后位点字节恒等；写计数不作断言面：双变体共享 VA 上第二次执行可经 undo 臂产生净零但非零次的写，133 轮穷举实证）③任意序列 + restore == pristine（restore 是右零元，位点级直证）④silent;keeptip 终态 == keeptip 单命令终态（变体切换语义在穷举中成立，非仅脚本特例） |
| **L12 混淆矩阵** | 合成：位点字节互异的构建间**非对角全拒**（patch 抛 `expectedMismatch` / inspect 报 `.unknown`，零假接受）；**共享序言对的非对角接受 = 设计边界如实入测**（字节门的判别力精确刻画 = 字节精确匹配；共享字节构型的上层防线是 L9 目标恒等门 + 行为 verify + build 号选表——边界写成契约而非假设）。真件：抽样矩阵台账（var/logs/confusion-matrix-*.txt），接受率如实登记 |
| **L13 bundle 局部性** | 合成：patch 后全树差分 ⊆ {目标 dylib（位点级）∪ 备份文件}；诱饵（主可执行同族 Mach-O、Info.plist、额外 framework 内 Mach-O、普通文件）逐字节不动；restore 后全树恒等（备份文件除外——keep-3 轮换是设计内）。真件：全树差分逐文件分类（位点/备份/签名面/macho——**未归类差分 = FAIL**；--no-resign 模式下 signature/macho 类改动同为越界，重签面只在 --resign 模式合法）；位点级直证全文件差分（64MiB 截断在双评审揭出后修正——真 dylib 位点 VA≈70MB 曾落在截断区外）；负控 = 诱饵注入**必须出现在差分面且被标记**（缺席 = 检测器失灵 = FAIL） |
| **L14 证据台账** | evidence-ledger.json：每 L 族 → 最新台账路径 + sha256 + 命中判定行原文 + git HEAD；**必需族**（L2/L6/L9/SOAK 真件深度面）缺失/FAIL/无判定行 = 退出非零；CI 合成面族（L1/L12/L13）缺席降级 optional 如实登记（sha 漂移检测不在本轮——工具只记录当下 sha，第三方复算=重算+重跑，见 §6） |
| 既有判据不回退 | 全量测试绿（本地 + CI 双腿含 Rosetta）、L1/L2/L6/L9 台账、变异锚点 canonical、fuzz 干净 |

## 4. 需求重写（对原句的第三代转译）

- **R13（崩溃完备）**：任何变更命令在**任意第 k 个写位点**失败后，系统的
  下一条合法命令必须收敛——从「有恢复防线 + 有样例」升格为「逐位点穷举
  证明」。验收：20 格矩阵全绿 + 五不变量。✅
- **R14（状态机完备）**：命令代数性质（幂等 / 右零元 / 切换语义）在**穷举
  序列**上成立而非脚本特例。验收：155 序列全绿。✅
- **R15（负空间完备）**：expected 门的判别力被精确测量并写成显式契约
  （含边界构型的如实登记）——「挡错版」从口号变为矩阵台账。✅
- **R16（写集升格）**：patch 的作用域主张从位点级升格为 bundle 全树
  （关闭 V5 §5 登记项）。验收：合成镜像常跑 + 真件工具 SOP。✅
- **R17（证明随行）**：每次发版产出机器可核验的证据台账，第三方可复算。
  验收：Makefile 目标 + SOP 接线。✅
- **R18（反目标）**：**产品代码零变更、CLI 表面零增量**；新断言全部叠加在
  既有 317 测之上；全部新代码为测试 + 工具 + 文档。✅

### 设计修正（本轮揭出并修正的不合理处）

1. **「journal + 样例杀例 = 崩溃安全」的抽样过度概括**：fail-at-0 一个格
   子证明不了「任意位点」。M08 缝的存在让穷举免费——只差把它用满（R13）。
2. **「L2 链绿 = 状态机对」的固定路径谬误**：6 态 + 1 链是设计者的想象
   路径；用户/事故的实际命令序列是任意组合。BFS 穷举把不变量的定义域从
   「脚本集合」扩到「全部 ≤3 序列」（R14）。
3. **「expected 门挡错版」从未被证伪测量**：共享序言构型下字节门对错版
   条目按设计放行——这不是缺陷而是字节门的定义域边界，但此前从未被写成
   契约。混淆矩阵把它显式化，并指认上层防线（R15 + FMEA B8）。
4. **「局部性 = 单文件位点级」的作用域缺口**：patch 真实修改的是整棵
   bundle 树（备份 + 签名面）——V5 自己登记了这一点。全树差分分类补上
   （R16）。
5. **「全绿」的读者只有作者**：证据链没有机器可核验的索引，第三方（或
   三个月后的自己）无法复算「凭什么绿」。台账 schema 化（R17）。
6. **「零错误零崩溃」沿用 V5 修正**：预算化判据（定义域上零失败 + 负控
   灵敏度 + 未证明面显式登记，§6）——口号继续不作标准。

## 5. 实施面（133 轮落点）

| 产物 | 层 | 说明 |
|---|---|---|
| `Tests/wxkeepTests/CrashMatrixTests.swift` | L10 | `@Suite(.serialized)`（全局缝无并发歧义）+ URL 限定纪律；目录复用 SyntheticL2L6 拓扑 |
| `Tests/wxkeepTests/StateMachineExhaustiveTests.swift` | L11 | 5 命令 × 深度 3 BFS；每序列独立临时副本 |
| `Tests/wxkeepTests/ConfusionMatrixTests.swift` | L12 | 合成矩阵常跑 + env-gated 真切片腿（`WXKEEP_CONFUSION_PLAN`） |
| `Tests/wxkeepTests/BundleEffectTests.swift` | L13 | 合成 app 全树哈希分类 |
| `tools/verify_confusion_matrix.py` | L12 | 孪生驱动：config.json → 计划 JSON → swift test → 台账 |
| `tools/verify_bundle_effect.py` | L13 | 真件 SOP：clonefile 副本 → --no-resign patch → 独立全树差分复算 + 负控 |
| `tools/gen_evidence_ledger.py` | L14 | 台账 → evidence-ledger.json |
| Makefile | — | `verify-confusion` / `evidence-ledger` 目标 |
| FMEA.md / ROADMAP.md / MAINTAINING.md | 登记 | A11/B8/B9/D4 新行；133 轮落册；SOP 节 |

## 6. 验收与诚实边界

- ✅ 本轮达成：R13-R18 全绿（判定见 §3；台账 var/logs/）。
- ⏳ **未证明面（显式登记，防「全绿=全对」错觉）**：
  - ~~L11 深度封顶 3~~（133 续轮收口：`WXKEEP_SM_DEPTH=4` 门控实跑
    **780 条 ≤4 长序列全绿 1.6s**——原文「625」是「长度恰 4」口径，套件域
    为 ≤4 如实以 780 登记；迁移函数不变的浅层蕴含论证获 4 层直接复核。
    CI 不设 env 恒 155，深度 4 为本地 SOP 档）。
  - L12 真件腿是**抽样矩阵**（真构建 122 个的全矩阵 = 14,884 格，逐格
    inspect 只读也需全语料在场——抽样策略由孪生驱动决定并登记）。合成
    矩阵是真全矩阵。
  - L13 真件腿的「签名面」分类是**结构性判别**（_CodeSignature 目录 /
    Mach-O 头嗅探——后者是宽分类：--no-resign 模式下 macho 类已收紧为
    越界 FAIL，--resign 模式下重签改写的 Mach-O 按签名面放行），不是
    cdhash 级证明——签名面内部的逐字节证明仍归 L6/L9（确定性 + 指令级）
    + codesign --verify（系统判官）。
  - L10/L11 的位点级字节直证不含签名面验证——bundle 签名一致性由
    signatureValid（110 轮门）与 strict verify 承接，两域解耦是设计。
  - 崩溃矩阵覆盖**单点写故障**；多点连续故障（两处先后失败）与硬件级
    位翻转未建模——前者被「失败即抛、无重试」的引擎结构排除（第一次
    失败就离开写循环），后者归 ZFS/APFS 层，不在本工具域。
- 台账索引：`var/logs/confusion-matrix-*.txt`、
  `var/logs/bundle-effect-*.txt`、`var/logs/evidence-ledger.json`；
  L10 崩溃矩阵与 L11 状态机为测试内嵌报告（swift test 全量 CI 双腿常跑，
  不设独立台账族——ledger 判据面归「测试绿」）。
