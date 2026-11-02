# FMEA — 故障模式与影响登记册（125 轮 V5 深度轮立册）

> 目的：把散落在 ROADMAP 各轮、T5-RUNBOOK 归因表、MAINTAINING 踩坑记录里的
> 故障模式知识收敛为**单一登记册**——每行 = 模式 × 触发 × 现行防线 × 检出面 ×
> 关联测试/台账。新防线落地时补行；防线退化时此表就是回归清单。
>
> 等级：S=严重度（P0 启动必崩/数据损坏 … P3 体验）；
> 检出 = 谁最先看见（doctor / verify / CI / 工具台账 / 用户症状）。

## A. 字节写入面（patch/restore/变体切换）

| # | 模式 | 触发 | 防线 | 检出 | 测试/台账 | S |
|---|---|---|---|---|---|---|
| A1 | 写到一半进程被杀（SIGKILL/断电） | 系统级中断 | WAL journal（begin 先于任何写机会；complete 仅确认后） | doctor interrupted 三态判读 + 恢复指引 | PatchJournalTests；doctor guidance 矩阵 | P0 |
| A2 | 跨 binary 部分写入后失败（A 成 B 败） | Phase-1 过、Phase-2 抛错 | PartialWriteFailure 包装（journal 不收口）+ 恢复重签兜底 | doctor mixed/interrupted；journal 保留 | `partialWriteFailureIsNotPreWrite`；M21 | P0 |
| A3 | 写前失败被误当收口 | variant 不可用/异变体在位 | isPreWriteFailure 分类 + 旧账保全（restore record） | doctor 判读不降级 | M21 + 124 轮 P3 锁 | P1 |
| A4 | 半套态洗白（全 alreadyPatched 跳过重签） | journal 残留时幂等重跑 | journalPendingAtStart 强制重签 | doctor signatureValid | 110 轮修 + 测试 | P0 |
| A5 | 错版二进制/未知先行修改 | 微信自更新/外改 | expected 多变体字节门（全量预检，零写入） | patch 干净拒绝（expectedMismatch） | PatcherTests；L1 全扫 | P0 |
| A6 | 位点区间交叠（数据事故） | catalog 合并/演进 | buildPlans 区间交叠检测（102/108 轮） | 装载期/规划期拒绝 | overlappingEntries 路径 | P0 |
| A7 | 变体并存（silent+keeptip 同盘） | 旧版本切换残留 | 变体切换还原臂 + keeptip2 残留拒绝（foreignVariantPatched） | patch 拒绝 + doctor leftover 行 | VariantSwitchTests | P1 |
| A8 | asm/expected 数据坏（空串/坏 hex/跨度） | 数据 OTA 事故 | 三层门（Config 装载 / Signatures / Patcher 兜底） | 装载期拒绝 | 空 asm/坏 hex/跨度三测；M04/M05/M22 | P1 |
| A9 | 撕裂写（非原子覆写） | 磁盘故障 | SafeWrite .atomic + 权限保留 | journal/备份完整性 | HardeningTests；M17 | P1 |
| A10 | 备份截断/落错位 | 磁盘满/路径事故 | 大小校验 + 主可执行识别 + bundle 外落点 | Backup 拒绝 | BackupTests；M10/M11 | P1 |

## B. 语义面（补丁到底做了什么）

| # | 模式 | 触发 | 防线 | 检出 | 测试/台账 | S |
|---|---|---|---|---|---|---|
| B1 | 错目标跳转（字节门全绿但语义错） | 目录数据事故 | **L9 目标恒等门**（branch-flip pristine/patched 目标必须相等） | `verify_instruction_diff.py` FAIL 行 | L9 负控①（+4 漂移必红） | P0 |
| B2 | 位点撕裂指令边界 | asm 长度/编码事故 | L9 严格完整解码 | 同上 | L9 负控② | P0 |
| B3 | 位点外写入（引擎/外改） | 引擎缺陷或外部工具 | L9 `--patched` 局部性 + audit 三件套复算 | diff ⊄ 位点集 | L9 负控③；audit_patch 演练 | P0 |
| B4 | 审计账目与盘不符（stale） | 外改/收口前死亡 | doctor `audit_state` 对账 | doctor verdict + audit 行 | `doctorReconciliationFreshStale*`；M24 | P2 |
| B5 | arm64 补丁执行级效果未观测 | — | **登记为未证明面**（V5-DEPTH §5；解码级证明在位） | — | ROADMAP 遗留 | P2 |
| B6 | 账本覆盖面 < 盘上差异面（--only 子集/部分重跑后） | `--only update` 后全量重打：alreadyPatched 位点不入账 → 账本只含新写 | **登记边界**（账本语义=本事务写入；doctor 对账不受影响，离线复算需 --binary/--arch 分次） | audit_patch 输出注记 | ROADMAP 125 续遗留②（账本合并设计） | P2 |
| B7 | runtime 注入写入面污染离线局部性复算 | 装了 runtime hooks 的机器 | **登记边界**（audit 合同=未装 runtime 或注入前 diff；注入面由 doctor LC/marker 判据覆盖） | audit_patch 输出注记 | FMEA 本行 | P2 |

## C. 签名/启动面

| # | 模式 | 触发 | 防线 | 检出 | 测试/台账 | S |
|---|---|---|---|---|---|---|
| C1 | 字节改后未重签（必崩态） | 中断事务/手工改写 | codesign --verify --strict 实测门 + 恢复重签 | doctor signatureValid=false + restore 处方 | 110 轮修；doctor 行 | P0 |
| C2 | entitlements 剥光 → AMFI 击杀 | 错误重签姿势 | 五步管线（快照→嵌套→根→漂移恢复→strict verify） | doctor restricted/amfi 行 | ResignerTests；M12 | P0 |
| C3 | ad-hoc 被 Gatekeeper 评估拒收 | 正常态 | spctl 判读行（明示预期态，不处方系统变更） | doctor gatekeeper 行 | `gatekeeperLineInterpretsSpctlVerdicts` | P3 |
| C4 | CODESIGNING 击杀复发 | 系统策略演进 | `.ips` 近 7 天扫描（CODESIGNING 计数）+ AMFI 行合读 | doctor crash(7d) 行 + verdict | `crashScanCountsMatches*`；M25 | P1 |
| C5 | runtime 注入半套（LC 在 dylib 缺） | remove 半途/手删 | doctor 混合态 verdict + interrupted 判读 | doctor ❌ 行 | runtimeRemove 分支 | P0 |
| C6 | --allow-unverified 机器的账本无法经 restore 收口 | unverified 条目不可反演 → restore 预检整体拒绝 | **登记边界**（既有 restore 语义；doctor stale 处方在该子集会先撞 restore 失败——pre-existing） | restore 报错文案 | ROADMAP 125 续遗留③ | P2 |

## D. 数据/供应链面

| # | 模式 | 触发 | 防线 | 检出 | 测试/台账 | S |
|---|---|---|---|---|---|---|
| D1 | config/signatures 被篡改 | 中间人/误改 | Ed25519 manifest + openssl 三方互证（CI master 腿） | doctor manifest 态 / CI 红 | ManifestTests；M14；CI 步 | P0 |
| D2 | 私钥材料入库 | 误提交 | CI 泄漏门 + keys/ 卫生 | CI 红 | ci.yml Guard | P0 |
| D3 | manifest 与分支改动暂时失配 | PR 改 config 未重签 | 验签门 master-only（PR 分支非红） | — | ci.yml 注释 | P3 |

## E. 测量仪器面（125 轮新立）

| # | 模式 | 触发 | 防线 | 检出 | 测试/台账 | S |
|---|---|---|---|---|---|---|
| E1 | 变异态泄漏进工作树 | 变异器被 SIGKILL | sentinel + 启动自愈 + pre-commit + CI anchor 门 | 拒提交/拒跑/CI 红 | 125 轮演练（泄漏→自愈→拒跑） | P0 |
| E2 | 锚点漂移/歧义 → 变异静默 SKIP → 杀灭率分母缩水 | 代码演进 | canonical-anchor 门（计数恰 1 + 变异形态不在盘——125 续双评审 P1 后同 apply 口径） | pre-commit/CI | 125 轮首捕 M05/M12/M20；125 续再捕 M08（在场≠唯一，死 14 轮） | P1 |
| E3 | 等价变异体误判防线缺口 | 数学等价形 | 等价判例成文（M23：无符号模运算蕴含）+ 换可杀形 | 杀灭率口径 | MAINTAINING 变异节 | P2 |
| E4 | oracle 在 CI 静默 skip（绿≠跑过） | runner 无语料 | 显式登记 + Makefile/SOP 入口 | MAINTAINING 孤岛清单 | V5-DEPTH §5 | P2 |

## 使用约定

- 新防线落地 → 补行（S 列按「若无此防线的事故形态」定级）；
- 防线被移除/弱化 → 行内标注并回读关联测试是否仍绿；
- 每次主动体检（双评审轮）把新发现模式补进来，出处链接到 ROADMAP 轮次。
