# V3-DEPTH — 「更深而非更大」需求重写（2026-10-23）

> 原始需求：「我需要这个程序的更深版本，而不是更大版本。」
> 本文把这句话重写为可验收的工程需求：专家实践对照、外部客观标准、
> 设计修正与验收门槛。**深度的定义：在现有功能面不变的前提下，把每一条
> 安全/正确性主张从「设计如此」升格为「机器可核验的预言，且有台账」。**

## 1. 顶尖专家会怎么做（本仓此前未做的部分）

逆向工程（RE）与高保障软件工程两个领域的头部实践，合到本仓的语境内：

| # | 专家实践 | 本仓此前状态 | 本轮落点 |
|---|---|---|---|
| D1 | **崩溃一致性（WAL）**：多点写入当数据库事务对待——写前落意图日志，未确认完成即视为中断，检测与恢复指引是产品的一部分（DB/文件系统工程的标配） | 备份+幂等 restore+catch 型恢复重签都在位，但 SIGKILL/断电窗口**无检测、无指引**：doctor 只能报 mixed，用户不知道发生过事故、备份在哪 | `PatchJournal`（write-ahead intent journal）+ CLI 事务边界 + doctor 三态判读（73 轮 I1） |
| D2 | **确定性即证明义务**：变换（patch/restore）必须是数学函数——同输入必同输出，跨运行/跨机器可复现，用 golden-hash 台账锁住 | 可逆性（restore==pristine sha）有 L2 oracle；patch 输出恒等**从未被断言**（隐含信任） | L6 oracle：真切片 × 双副本独立运行 sha 恒等（7/7 过）；附带实证 **codesign ad-hoc 每次 1 字节不确定**（签名元数据内序号，1.7 亿字节仅此 1 字节差异）——「全管线 sha 恒等」命题**不成立**，边界记入台账（73 轮 I2） |
| D3 | **负控（negative control）**：证明检测器能检测——故意注入已知坏状态，断言系统**报错**而不是通过。生物/医学实验方法论 | verdict 级有 `verdictFlagsIneffectivePatch`；字节级「翻转一个补丁字节 → inspect/doctor 必须报 unknown/mixed」无直测 | `tamperedPatchPointIsDetectedNotReportedClean`（73 轮 I4） |
| D4 | **性质测试（property-based）**：不变量在随机化输入族上成立，而非单个 fixture 上碰巧成立（QuickCheck 学派） | 注入器 round-trip 只在 1 个零填充 fixture 上验证 | 500 次随机化变体（路径长 8-97/镜像 4K-36K/头填充随机）：**逼出精确契约**——往返唯一允许差异=临时命令窗口归零（73 轮 I5） |
| D5 | **端到端启动浸泡（soak）**：唯一用户可感的客观标准是「打完补丁的 app 能启动、活着、零新崩溃」——自动化为对照实验（DiagnosticReports 前后差集） | 真机行为验证为手工动作；ips 巡检为事后人工检查 | `tools/launch_soak.py`：隔离副本→patch→浸泡→存活断言→.ips 零新增（73 轮 I3） |
| D6 | **双实现复式记账**：每个关键结论由两条独立代码路径（Swift 引擎 / Python 工具）各自得出且必须一致 | 事实存在（verify_derivations × verify_staging）但属惯例不属 SOP | 已有惯例在 MAINTAINING 固化；L1-L6 台账统一为「证据目录」 |
| D7 | **供应链纵深**：签名、密钥仪式、轮换预案 | Ed25519 manifest + openssl 三方互证 + CI 泄漏门禁已在位；密钥轮换预案未成文 | keys/ 卫生复核（release.key 不入库 ✓）；轮换预案列 §5 待办 |

## 2. 专家使用的原始数据与工具（本仓对照）

**未经加工的原始数据（ground truth）**
- 官方 DMG 原版镜像（pristine，day-0 验证必须用它——已打补丁二进制上配方全败是设计内）：`var/wxarm/` 现存 7 构建 × 双架构 thin 切片
- 切片级地面真值 JSON（`var/wxarm/*.json`，L1 全扫 145 条目失配=0）
- 真实装机件字节核对（270100 23/23 点位独立 python 复算）
- DiagnosticReports 的 WeChat `.ips`（崩溃对照的原始观测）
- 官方 CDN 归档（直链 + zsbai sha256 边车互证）
- 社区独立逆向（fzlzjerry 三次逐位互证）——第二只眼

**工具链**：Hopper/Ghidra/capstone（var/venv）静态；LLDB dyntrace 动态；`lipo/otool/codesign(1)`；llvm-cov 覆盖率；自研变异测试（杀灭 90%）；ASan/UBSan/TSan；OpenSSL 独立验签；本仓 Python 孪生（machutil 统一解析）。本轮新增：`verify_determinism.py`（L6 台账）与 `launch_soak.py`（浸泡门槛）。

## 3. 外部客观标准（「结果正确」的判据，全部机器可核验）

| 标准 | 判据 | 现状 |
|---|---|---|
| 字节正确性 | strict verify（`codesign --verify --deep --strict` = 0）+ expected 门 + 位点字节 ∈ asm∪expected | ✓ 既有 |
| 可逆性 | 任意状态链后整文件 sha256 == pristine（非位点比对） | ✓ L2，7/7 构建 |
| **确定性** | 引擎层：同 pristine 两份独立副本 → patch 输出 sha256 恒等（silent+keeptip 双路径，L6 7/7 过）。签名层：ad-hoc 输出含每次相异的 1 字节元数据序号（实证），全管线 sha 恒等**不作标准**，以 strict verify 为准 | ✓ 本轮 L6 |
| **崩溃一致性** | journal 残留必被 doctor 检出且给对指引；成功事务必清 journal；restore 必收敛 | ✓ 本轮 12 测 |
| **负控** | 单字节篡改必报 unknown/mixed，绝不容忍误报 patched | ✓ 本轮 |
| **性质** | 注入往返在 500 随机变体上满足精确契约（零填充时完全恒等） | ✓ 本轮 |
| **启动浸泡** | 隔离副本 patch 后进程存活 N 秒 + WeChat .ips 零新增 | 工具就绪，真跑待用户触发（弹 GUI） |
| 覆盖率/变异 | llvm-cov 安全核心 100%/99.6%；变异杀灭 ≥90% | ✓ 72 轮 |
| 供应链 | Ed25519 验签 + OpenSSL 独立互证 + CI 泄漏门禁 | ✓ 既有 |
| 回归 | 全量测试套件绿（本轮后 177 测） | ✓ |

## 4. 需求重写（对原句的工程化转译）

**原始需求**「更深版本而非更大版本」重写为六条可验收需求：

- **R1（崩溃一致性）**：任何写入事务（patch/restore）必须可被事后判定为
  「确认完成」或「中断」；中断态必须被 doctor 检出并给出收敛动作；
  恢复动作必须幂等且永远安全。**验收**：journal 生命周期测试 + 三态判读
  矩阵 + CLI e2e（begin→成功→清除；伪造中断→doctor 指路→restore 收敛）。
- **R2（确定性）**：patch 与 restore 是纯函数。**验收**：L6 oracle 全构建
  双副本恒等 + 合成 fixture 双跑恒等测试。
- **R3（检测器的检测）**：所有「检测/验证」机制必须有自己的负控测试
  （证明其能报错）。**验收**：篡改负控绿。
- **R4（性质升级）**：核心往返性质在随机化输入族上断言，精确到「允许
  差异的字节窗口」。**验收**：500 变体契约测试绿。
- **R5（端到端门槛）**：「补丁后可启动」成为可重复对照实验。**验收**：
  launch_soak --plan 通过（工具链路），soak 真跑由用户触发（涉 GUI）。
- **R6（反目标）**：**不新增功能面**。不为深度牺牲既有语义：所有新断言
  在既有 164 测上叠加且全绿；CLI 表面不变（doctor 输出新增 journal 行
  与 JSON 字段为增量兼容）。

### 设计修正（本轮揭出并修正的不合理处）

1. **「catch 型恢复 = 崩溃安全」的过度概括**：进程被杀时 catch 不会执行
   ——journal 补上这个洞（R1）。
2. **「patch 确定性显然成立」的隐含信任**：从「显然」到「断言」（R2）。
3. **单一全局 journal 会跨 app 误报**：clone/多 bundle 机器上 A 的中断不
   得劫持 B 的 doctor 建议——record 携带 app 路径，doctor 按 app 匹配
   （实现期自纠，`guidanceForeignAppJournalDoesNotHijackThisApp` 锁定）。
4. **预检失败与写入中断不可混淆**：journal 残留 × 字节 pristine（写前
   失败，最高频场景）给「修因重跑」指引，而非吓人的「中断恢复」——
   三态判读（`guidancePatchPristineSuggestsRerunNotRestore` 锁定）。
5. **注入器往返契约此前未言明**：remove 补零语义使往返在非零头填充上
   不恒等——契约现在被精确表述并有 500 变体测试（真实链接器零填充下
   退化为完全恒等）。

## 5. 验收与后续（诚实边界）

- ✅ 已达成本轮：R1-R4、R6 全绿；R5 工具就绪（--plan 验证）。
- ⏳ 待用户动作：launch_soak 真跑（会弹微信登录窗，用户在场时执行
  `python3 tools/launch_soak.py --seconds 45`）。
- ✅ 密钥轮换预案已成文（D7，2026-10-24）：docs/KEY-ROTATION.md（例行/紧急双流程 + 三方互证验收 + schema 2 双签过渡设计占位）。
- ⏳ 长期项（不阻塞）：wxread SQLCipher 课题
  （v3 前置，另行立项）；M-R4 群聊 tip（WCDB 层，维持长期项）。
- 台账索引：`var/logs/l1-ground-truth-*.txt`、`l2-reversibility-*.txt`、
  `l6-determinism-*.txt`（新增）。
