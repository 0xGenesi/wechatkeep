# V5-DEPTH — 「更深而非更大」需求重写·第二代（2026-11-03）

> 原始需求（同句重提）：「我需要这个程序的更深版本，而不是更大版本。」
> 第一代答卷见 [V3-DEPTH.md](V3-DEPTH.md)（D1-D7 / L1-L6 / R1-R6）与
> V4-REQUIREMENTS.md（L7/L8）。本文是第二代：**在功能面冻结的前提下，把
> 每一条正确性主张的证明深度再下探一层——从「字节可验证」到「指令语义可
> 验证、第三方可离线复算、系统判官可裁决、证据链 CI 可复现、测量仪器自身
> 可信」。**

## 1. 顶尖专家会怎么做（第二代：V3 之后的缺口，全部有勘察实证）

| # | 专家实践 | 本仓 V3 后状态 | 125 轮落点 |
|---|---|---|---|
| D8 | **指令级语义等价证明**（编译器验证/BinDiff 派系）：字节门只证明「写了声明的字节」，须再证明「这些字节在指令流层面恰好是声明的语义替换」 | 全部 capstone 工具只对 pristine 单向派生；**无任何补丁前后指令流 diff**；arm64 cbz→B 翻转效果从未被语义级证明（Verifier 自白「由字节级证明承担」） | **L9**：`tools/verify_instruction_diff.py`——asm 严格完整解码 + 翻转目标恒等 + 具名语义类（retify/branch-flip/force-flag/store-zero/nop-out/prologue-restore）+ `--patched` 全文件局部性直证（__LINKEDIT 重签尾差单列） |
| D9 | **检测器的元验证**：先证明检测器能报错，再信它的全绿（V3-D3 原则向新检测面延伸） | L7 负控自认「空洞绿」；字节级负控仅单字节 | L9 三型负控（错目标 B / 撕裂字节 / 位点外写入）全被抓住；doctor 对账 stale 负例 + 坏 arch 负例入测 |
| D10 | **per-site 审计清单**（供应链审计）：pristine+patched+账目三件套，第三方**零信任离线复算** | Manifest 只护数据文件哈希；journal 无逐位点字节——「写了什么」只能反推 | `PatchAudit`（Patcher auditSink → wxkeep.audit.json）+ doctor `audit_state` 对账 + `tools/audit_patch.py` 离线复算（真切片演练：9 位点 33B diff 全吻合 + 位点外负例必红） |
| D11 | **系统判官当外部标准**：启动命运与崩溃历史用系统自己的记录裁决 | codesign 已接（非 deep）；spctl 零引用；.ips 无自动扫描 | doctor 新面：`.ips` 近 7 天扫描（CODESIGNING 击杀计数）+ spctl Gatekeeper 评估行（informational，与 AMFI 行互补不越权）+ `--deep` 可选全量校验 |
| D12 | **证据链 CI 化**（SRE：绿≠跑过） | L1/L2/L6/mutation/fuzz/openssl 全是本地孤岛；CI 的 oracle 因 env 未设静默 skip | openssl 独立验签接入 CI（master 腿，LibreSSL 回退 brew）；canonical-anchor Guard 步；L9 入 Makefile `verify-isa`；孤岛清单如实入 MAINTAINING |
| D13 | **测量仪器自身可信**：变异器不能是事故源；测量分母不能悄悄缩水 | 无 sentinel/无自愈/无 pre-commit 门（2026-11-03 M23 泄漏态实证）；3 个锚点已漂移 → 静默 SKIP | sentinel+启动自愈+`make hooks`（pre-commit）+CI anchor 门；**漂移首捕**：M05/M12/M20 刷新；等价变异体判例入册（M23：`a≥b && a−b<c ≡ a−b<c` 无符号模运算蕴含） |

## 2. 专家使用的原始数据与工具（第二代增量）

**原始数据**：var/wxarm 全切片库（187 arm64 + 200 x64）——L9 语料；
config.json 2500+ 位点目录（asm 字节类全枚举）；真实 `.ips`（doctor 判据）；
`keys/release.pub`（CI openssl 判官）；MUTATIONS 锚点表（canonical 判据）。

**工具**：capstone 5.0.7（var/venv）——L9 双解码；machutil（段表权威）；
spctl/codesign(1)（系统判官）；openssl Ed25519（三方互证）；Python 孪生第三例
（sweep × ExpectedPattern 之后：L9 目录镜像 + audit_patch 三件套复算）。

## 3. 外部客观标准（第二代判据表，全部机器可核验）

| 标准 | 判据 | 现状 |
|---|---|---|
| **L9 指令级** | 每位点 asm 在指令边界完整解码；branch-flip 目标与原条件分支恒等；具名语义类覆盖；`--patched` 时代码区 diff ⊆ 声明位点 | ✓ 本轮：32 构建 × 双变体 **1245 位点实例 100% 具名类、0 失败**（silent 585 / keeptip 660；branch-flip=30 全目标恒等） |
| **检测器灵敏度** | L9 三型负控必红；audit 三件套位点外写入必红；doctor stale 必报 | ✓ 本轮全绿 |
| **离线可审计** | 三件套（pristine+patched+audit.json）复算：位点字节吻合 + 局部性 + __LINKEDIT 单列 | ✓ 本轮（270351 真切片：9 位点 33B 全吻合；0x5000 位点外注入必红） |
| **系统判官** | doctor `.ips` 计数/CODESIGNING 分类正确（夹具 4 例定向）；spctl 判读如实；`--deep` 透传 | ✓ 本轮（17/17 DoctorTests） |
| **仪器可信** | 25 锚点全 canonical（CI+pre-commit 门）；泄漏→自愈→拒跑链路演练绿；等价变异体换可杀形不缩分母 | ✓ 本轮 |
| 既有判据不回退 | L1/L2/L6、codesign strict、全量测试绿、变异杀灭 ≥90% | ✓ 保持 |

## 4. 需求重写（对原句的第二代转译）

- **R7（L9）**：每个补丁位点获得指令级证明。验收：全语料双变体台账 +
  负控三型全红 + Makefile 入口。✅
- **R8（审计）**：patch 落 per-site 账目、restore 收口、doctor 对账、第三方
  三件套零信任复算。验收：生命周期测试 + 真切片演练。✅
- **R9（系统判官）**：doctor 回答「最近真的崩过吗 / Gatekeeper 怎么裁」，
  并提供 `--deep` 全量校验选项。验收：JSON 契约键 + 夹具定向测试。✅
- **R10（证据链）**：openssl 验签与 canonical-anchor 门进 CI；孤岛工具全部
  有 Makefile/SOP 入口；「CI 未覆盖项」显式登记。✅
- **R11（仪器）**：变异器 sentinel/自愈/pre-commit 三重门；锚点漂移即红；
  等价变异体判例成文。✅
- **R12（反目标）**：CLI 表面只做增量（doctor 新字段/`--deep` 旗标）；
  不新增用户功能；新断言全部叠加在既有 292 测之上。✅（+11 测；双评审收口后 303 全绿）

### 设计修正（本轮揭出并修正的不合理处）

1. **「字节门通过 = 语义正确」的隐含跃迁**：错目标的 B 指令可通过全部
   字节门（expected/asm 各自全绿）——只有指令级目标恒等能抓（L9 负控①
   钉死）。字节门是必要非充分条件，层级关系自此成文。
2. **「写入局部性靠 L2 间接蕴含」**：L2 的 restore==pristine sha 证明的是
   还原收敛，局部性是推论；audit 三件套把它升级为直证（diff ⊆ 位点集），
   且不再依赖 wxkeep 在环。
3. **「变异杀灭率 ≥90%」的分母可信性**：锚点漂移 → 静默 SKIP → 分母缩水
   → 达标假象。canonical-anchor 门 + 漂移首捕（3 例）证明此风险真实存在。
4. **「零错误零崩溃」口号化**：重写为预算化判据——定义语料（1245 位点
   实例）上的零失败 + 负控灵敏度证明 + 系统判观测面（.ips/spctl）+
   **未证明面显式登记**（见 §5）。诚实边界本身是需求的一部分。
5. **spctl 的越权风险**：Gatekeeper 拒收 ad-hoc 是预期态，若 doctor 把它
   报成故障会驱使用户做无谓（且危险）的系统变更——判读行明示「预期态，
   放行判据见 AMFI 行」，与 108 轮「不处方关 SIP」同一哲学。

## 5. 验收与诚实边界

- ✅ 已达成：R7-R12 全绿（L9 台账 var/logs/isa-diff-*.txt；audit 演练；
  DoctorTests 17/17；护栏演练链路绿）。
- ⏳ **未证明面（显式登记，防「全绿=全对」错觉）**：
  - ~~arm64 补丁的**执行级**遍历证明~~（128 轮收口：PatchTraversalTests
    ——合成控制流副本 × 真 Patcher.patch 写入 × MAP_JIT 执行，三面证明：
    pristine 可达性 / patched 无条件生效 / 毒化后继零遍历（UDF/int3 毒药
    落入即崩，patched 干净返回）；x64 对称镜像走 CI Rosetta 腿。诚实边界：
    pristine+毒药对照面需子进程骨架，不测——已登记 ROADMAP 128。124①
    （runtime.m 三武装函数可注入 base 缝）是另一独立登记项，未动。）
  - ~~L7 oracle 的变异负控「空洞绿」~~（127 轮收口：A/B 双 dump 三代
    设计，跳过洞反转+灵敏度 floor，见 ROADMAP 127）。
  - ~~L2/L6 全链 oracle 无法在 CI 跑~~（127 轮部分收口：合成 L2/L6 在 CI
    真跑同一组不变量；真切片深度覆盖仍本地 SOP——差距如实入
    SyntheticL2L6Tests docstring）。
  - `--patched` 局部性直证的对象是切片/未重签件或 __LINKEDIT 单列语义；
    全 bundle 级（多文件+Info.plist 面）未做。
- 台账索引：`var/logs/isa-diff-*.txt`（L9）；`var/logs/launch-soak-*.txt`
  （浸泡）；`var/logs/l1/l2/l6-*.txt`（既有）。
