# 路线图（待办归档）

## ㊳ 自主收口轮（2026-09-21 深夜：doctor keeptip=mixed 二义 bug 修复——㊲ 附带发现 6 闭案）

任务口径同 ㉝-㊱（能做掉的做掉）。遗留三项（drive28/M-R4）维持——均需
用户物理动作；自主可做面 = ㊲ 附带发现 6（doctor 判 keeptip=mixed，
明确标记「未修，记录」），本轮把它修掉，连带语义适配与例行巡检。

1. **根因与修复（Patcher.inspect 二义态）**：归一化恢复型条目
   （asm ∈ expected——keeptip 在 isRevokemsg 入口写恢复型条目：x64
   4e8d5d0 asm=554889E5… 双 expected 含自身、arm64 4bc4fa4
   asm=expected=40100034）打与不打**字节同形**，inspect 先判 asm 把
   pristine 态读成 patched → doctor 聚合误报 mixed。修复：字节同时
   匹配 asm 前缀与某 expected 变体时报告新态 `.ambiguous`（单条目
   无法判定是诚实语义）。
2. **聚合代判（Doctor.aggregate）**：按 ㊲ 建议「结合同 target 其他
   条目聚合」——.ambiguous 由同 target 可判定条目代判
   （[pristine, ambiguous]→pristine；[patched, ambiguous]→patched），
   全二义→unknown，可判定分歧维持 mixed/unknown。aggregate 改
   internal，DoctorTests 直接回归真实实现（删镜像副本——漂移隐患）。
3. **消费方语义适配**：① Engine.willWrite：.ambiguous=asm 已在盘
   （Patcher.patch 判 alreadyPatched）→ 不触发多余备份；②
   Verifier.verdict：.ambiguous 与 .patched 同判据（盘上就是 asm
   字节，行为=补丁态）；③ deprecatedLeftovers 维持只认 .patched：
   50a5bad 位点的 keeptip2 残留从「必报」变「不报」，但另 9 个
   非归一化 NOP 位点仍拦截全部现实场景，且该位点 expected 门接受
   keeptip2 字节、patch 即自愈；反向收益——**修掉一个既有假阳性**：
   269602 上 `patch --variant silent`（keeptip 态机器）原会把 keeptip
   写入的 32a0d9d 误判 keeptip2 残留拒绝执行（.patched 首判 +
   silent 选择集不含 keeptip 覆盖位点），现 .ambiguous 正确放行 →
   变体切换还原路径畅通。
4. **验证**：126 测全绿（+3：inspect 二义态 / 聚合代判矩阵 /
   270100 keeptip x64 实形端到端 pristine→pristine、patched→patched）；
   真机 doctor（keeptip 态）revoke=pristine/keeptip=patched/overall
   protected ✓；**真 pristine 备份件交叉验证**（python 复刻比较逻辑
   跑 bak-20260921-223343）：537e52d→pristine + 4e8d5d0→ambiguous
   →聚合 pristine（修复前 mixed）；release 构建 + 真机 verify 冒烟
   （pristine 判定正确、四探针符合 pristine 预期）。
5. **例行巡检（阴性）**：CDN 新构建探测 270101-270106 全 404、滚动件
   last-modified 仍 09-18（无变化信号）——目录无需增量；第三方无新
   提交（fzlzjerry 停 168e3e8 09-20、tanranv5 停 8f3fb95 09-19），
   var/thirdparty 快照仍新鲜；ROADMAP ④ 三个「已知小项」复核确认均
   已在前轮修掉（update-data 同口径计数、bak 只留 3 份）；
   Verifier.swift 一处 vmsize 未用编译警告顺手清除。
6. **顺带**：README 测试数 123→126。

## ㊲ AMFI 实证前置轮（2026-09-21 夜：270100 重签管线可验证性两处破坏修复 → probe 排练全绿，待 Recovery 正跑）

任务：用户发起 AMFI 原生 SIP 实证（Recovery 引导后跑
tools/amfi_sip_probe.sh）。排练（--allow-sip-off）当即复现昨晚中断点，
顺藤揭出 270100 新引入的**重签管线两处破坏**并修复——排练已全绿，
正式实证只欠用户 Recovery 动作。

1. **新知识：vk_swiftshader_icd.json 是 detached 签名的代码对象**。
   270100（4.1.15，2026-09-18 随版）XPlayer.app/Contents/Frameworks/
   vk_swiftshader_icd.json 虽是 110 字节纯 JSON，官方却用 com.apple.cs.*
   xattr 携带其 detached 代码签名（seal requirement 里的
   `identifier "vk_swiftshader_icd"` 即此来）。官方原件 verify
   --deep --strict 全绿的前提 = 这组 xattr 完好。官方 270100 全家
   （主程序/wechat.dylib/XPlayer）均为 Tencent 证书签名（5A4RE8SF68），
   ad-hoc 只是我们重签后的形态。
2. **破坏点 A（root --deep）**：Resigner 根签名带 --deep 递归重签
   未触碰嵌套（XPlayer），codesign 对非 Mach-O 的 Frameworks 文件
   生成 cdhash-only seal，--deep --strict 直接 "code object is not
   signed at all"。修复：root 改**浅签**——字节改动过的对象在 step 1
   已显式签，根无需递归；未触碰嵌套保持官方签名（实证：官方 dmg
   副本上「dylib adhoc + root 浅签」verify 全绿）。
3. **破坏点 B（xattr -cr 静默带病出厂）**：Resigner step 5 的
   `xattr -cr` 把 json 的 com.apple.cs.* detached 签名一并抹掉——
   它跑在 step 4 硬验证**之后**，管线自检绿、bundle 实坏（昨晚以来
   /Applications 的状态即此）。修复：清理收窄为 find 逐文件
   `xattr -d com.apple.provenance`，cs.* 永不触碰。
4. **连带语义修复**：① root 浅签改带主程序 resignPlist（旧设计
   root 不带 entitlements 故意剥掉、靠 drift 循环兜底回填——在浅签
   下是多一次往返且某轮失败剥空后 snapshot 把空 profile 当原始，
   entitlements 永久丢失、自我延续）；② drift 判定按对象终态
   （重签对象=原始+注入，未触碰对象=原始；root 与主可执行文件是
   同一签名对象，root 被签则主程序计入重签集）——旧语义要求全体
   =原始+注入，浅签下会把保持官方的 XPlayer 误判 drift、显式重签
   又撞回破坏点 A。/Applications 已按「官方 dmg 恢复 XPlayer（ditto
   保留 xattr）+ 官方 entitlements 提取注入重签」修复，doctor 恢复
   protected/19 键/restricted_entitlements=true。123 测全绿（含
   Resigner 端到端重构夹具）。
5. **probe 排练全绿（机制实证）**：restore→patch(keeptip)→Resigner
   verify OK→codesign 自检 OK→launch 存活 24s+(RUNS·排练语义)→
   restore→**pristine verify OK**（修复前此处 FAILED）。排练工件存
   var/amfi_probe/verdict_rehearsal_20260921.json（防与正式结论混淆）。
   官方基线 dmg 存档 var/cdn/WeChatMac_270100_candidate.dmg（506MB，
   滚动件，CFBundleVersion 实测 270100）。
6. **附带发现（✅ 已修，见 ㊳）**：doctor 判 keeptip=mixed 系
   Patcher.inspect 对归一化恢复型条目（asm∈expected，如 keeptip 的
   isRevokemsg 入口）先判 asm 的语义二义——该条目打与不打字节同形
   （asm 即 pristine 序言），pristine 态被读作 patched。不影响字节、
   patch/restore/probe 判定（均不走 patch_states），如需显示正确
   待结合同 target 其他条目聚合。

**✅ 正式实证收口（2026-09-21 22:48，本节遗留项已清）**：用户完成
Recovery 引导（csrutil enable、boot-args 已清）后正跑
`tools/amfi_sip_probe.sh`，判定 **RUNS**——原生 SIP（enabled、无
boot-arg、AMFI 活跃）下补丁态微信存活满 24s 观察窗、零 .ips，
pristine 恢复后签名 OK。verdict.json 存 var/amfi_probe/。**ROADMAP
决策 #1（2026-09-17）就此闭合：维持 doctor 的 watch 级判定**——
「字节补丁 + ad-hoc 重签（保留 restricted entitlements + 注入
disable-library-validation / allow-unsigned-executable-memory）」
在原生 SIP 下可正常运行，历史 CODESIGNING 杀机（Sep 15，配置无记录
的裸重签）不适用于现行 Resigner 管线。事后日常 keeptip 态已恢复。
研究环境提示：SIP 保持 on 时 verify worker（RWX）不可用；如需恢复
离线逆向环境按 probe 头部 runbook 第 4 步（Recovery csrutil
disabled + boot-args）。另：drive28 群聊实弹轮、M-R4 维持。

### ㊲ 补遗（2026-09-21 深夜：实证后两项环境观察）

1. **无 boot-arg 全功能态（新研究环境基线）**：正式实证收口后，
   用户将系统切至 **SIP disabled + 无 boot-args**（AMFI 保持默认
   活跃）。实测三件套全可用：补丁态微信正常运行（probe 已证
   AMFI 活跃 + adhoc 重签兼容）；`wxkeep verify` x64 worker 正常
   （22:52 实测，行为判定正确——"verify 不可用"仅限 SIP **enabled**
   时的非 hardened worker；SIP off 即可行，与 boot-arg 无关）；
   lldb attach 仅看 SIP 开关。结论：**amfi_get_out_of_my_way
   boot-arg 自本轮起不再需要**——其历史使命（让补丁态微信在
   AMFI 面前存活）已被正确的 Resigner 管线取代。研究环境定义
   简化为仅 csrutil disabled（上文收口段"第 4 步 + boot-args"
   中 boot-args 部分作废）。
2. **风控首例观察：微信「检测到连接异常」提示（偶发，验证后
   放行）**：23:29 用户自启微信（270100，keeptip 补丁态）弹
   「连接异常」，下一步数次验证通过。时间线：距 probe 反复
   launch/kill 轮约 40 分钟、距重启重登约 30 分钟——最可能为
   **行为风控**（频繁重登/进程生命周期异常画像）而非补丁态
   完整性检测（probe 刚实证该配置 AMFI 兼容；社区同款配置亦
   普遍偶发此提示）。判据约定：偶发一次 = 正常扰动，通过验证
   即无影响（撤回保留为本地逻辑，与账号风控无关）；**每次启动
   必弹** = 补丁态触发完整性风控的信号，届时以 pristine 态
   A/B 对照定位。管理动作：短期内避免反复重启微信/重登（累积
   风险评分）。仓库此前无风控现象记录，此为首例，后续复现
   在本条目下追加时间线。

## ㊱ 遗留项收口轮（2026-09-21：fzlzjerry 270100 互证 + 健康回归 + v0.2.3 发版收口）

任务口径同 ㉝/㉞/㉟（能做掉的做掉）。三项遗留（drive28 实弹轮 / M-R4 /
AMFI SIP 实证）确认均需用户物理动作；自主可做面如下，过程中发现并收口
发布链缺口（主交付）：

1. **新构建探测（阴性）**：官方 CDN 归档对 4.1.15.21-.25（270101-270105）
   与 4.1.16 线全量 HEAD 探测 404——㉟ 收口后三天无热修新构建；
   `WeChatMac.dmg` 滚动件在档但无变化信号。目录无需增量。
2. **fzlzjerry 270100 互证（11/11 逐字节 MATCH）**：其 09-20 提交
   新增 270100 arm64 全套（patches.json 29→30）——revoke cbz 翻转、
   keeptip 对（= 其 revoke-tip）、update 8 点（含访问器对）与我们目录
   全部地址/expected/asm 一致；其 runtime-tip 钩点 @4bc4d34 的 expected
   恰为我们 arm64 parse 序言，hooks 行间接互证。快照刷新
   （var/thirdparty，30 构建）。tanranv5 无新提交。详见
   related-tools-analysis.md 2026-09-21 节。
3. **健康回归（全绿）**：本地 123 测全绿；CI run 110（双 matrix）+
   arm64-verify run 4 全绿；verify_derivations 270100 抽查 7/7 PASS；
   manifest 哈希复验 VERIFIED-CLEAN；工作树干净。
4. **发布链缺口收口（v0.2.3 已发，本轮主交付）**：发现 v0.2.2/v0.2.3
   两轮以版本号命名提交（d5ec8c0/a6012dd）但 CLI 版本常量、git tag、
   GitHub release 均停在 0.2.1——v0.2.1 目录 64 构建/617 条 vs master
   77/1156（+13 构建 +539 条），㉟ 二进制能力（arm64 verify MAP_JIT 免
   relaxed 引导、fat 装机件谓词反解修复）不在任何 release。按 ⑳ 自主
   全链惯例切版：版本常量 0.2.1→0.2.3（b058d9b）→ tag v0.2.3 →
   release run 12 出双资产（wxkeep a94b5bc3… / libwxkeep_runtime.dylib
   407c94f7…——与 v0.2.1 逐字节同哈希，runtime 源未动的必然结果，
   git diff v0.2.1..v0.2.3 -- WxkeepRuntime 空集实证）→ 主仓 Formula
   副本 + tap 同步 0.2.3（2b81ff5，config/signatures 哈希按 tag 处
   raw 复核）→ brew reinstall 端到端：Cellar 0.2.3 七文件、--version
   0.2.3、hooks 表 20 行、真机 x64 verify 冒烟 pristine 判定正确。
   CI run 112 + release run 12 全绿。brew 用户自 0.2.3 起获得
   arm64 verify 与全量目录。

**遗留（维持 ㉟ 口径）**：drive28 群聊实弹轮（需用户一次真实群聊撤回，
`bash tools/dyntrace/d28_live.sh` 即进入观察窗）；M-R4（依赖 drive28
数据）；AMFI 原生 SIP 实证（硬件动作：Recovery 引导跑
tools/amfi_sip_probe.sh）。

## ㉟ 遗留项收口轮（2026-09-21：arm64 验收假绿揭穿 → MAP_JIT 路线 → 真件端到端收章）

任务口径同 ㉝/㉞（能做掉的做掉）。㉞ 遗留四项中唯一可自主项 = arm64
验收（「剩一次 workflow 触发」）。本轮把它做完，过程中揭穿一个**假绿**。

1. **假绿揭穿（关键发现）**：触发 `arm64-verify.yml` 后核查步骤级结果，
   发现 09-20/09-21 两轮 "success" run 的 **Real-dylib 端到端步骤都被
   skip**——probe exit 126（RWX 被 AMFI 拒），行为测试全 skip。根因：
   `allow-unsigned-executable-memory` 在 macOS 15 是**受限 entitlement**，
   ad-hoc 重签带不上（runner SIP 关闭也无效，日志实证）。㉞ 的
   「entitlement 路线 + 一次触发即收章」假设失效，验收实际从未闭合。
   教训：**workflow 的 success 要看到步骤级执行证据才算数**。
2. **MAP_JIT 路线落地（正确的解法）**：worker 的两处 RWX mmap 在 arm64
   改 `MAP_JIT` + `pthread_jit_write_protect_np` 包夹（映射后放开写、
   GOT 重定向完成后锁写放执行；x64 路径不动）。非 hardened 进程免
   entitlement——这是 LLVM/JSC 同款的官方 JIT 通道。**意外收获强于原
   验收目标**：stock arm64 真机（无 AMFI boot-arg）verify 行为验证直接
   可用，用户不再需要 relaxed 引导。附带：CLI verify 预检/envBlocked
   文案改口、workflow entitlement 段补 allow-jit 作纵深。
3. **解锁暴露两个夹具缺陷（worker 无错，首跑即现形）**：
   - x64 mini 镜像测试在 arm64 主机执行裸 x86_64 代码 → SIGILL；此前
     探针必败全 skip，从未真正运行过（ci.yml 矩阵 macos-14/15 全 arm64，
     f06518d 首推即红）。加 hostIsARM64 门（x64 主机照常跑）。
   - arm64 mini 夹具把参数存 **x8（caller-saved）**跨 strlen 调存活，
     libc 改写后谓词全 false（CI 实测 [false,false,false]）。改 x19 +
     序言 stp 保存（x64 孪生的 rbx 同构）；编码经 clang -target arm64
     汇编逐条核验。教训入 MAINTAINING「误改与踩坑」。
4. **验收收章（run 35595719253，f193e51，全绿）**：probe exit 0 →
   合成 arm64 行为测试 PASS → **CDN 真件端到端**：270100 fat dmg →
   lipo → catalog 定位 → MachImage 谓词反解 `site 0x47575FC`（与 ㉝
   静态地面真值逐一吻合）→ MAP_JIT worker 执行 →
   `revokemsg-predicate("revokemsg")=1 / 其余 0` 四探针全对 →
   verdictPredicate 通过。主 CI 双 matrix（macos-14/15）同步绿。
   ㉝ 遗留 1「arm64 verify 验收」正式闭合。
5. **drive28 编排脚本入库**：㉜ 交付的 `tools/dyntrace/d28_live.sh`
   （一键编排：restore→runtime 惰性安装→启动→lldb 观察窗→trap 自愈）
   漏提交，补上（5d0b299）。实弹轮万事俱备。

**回归**：本地 123 测全绿（x64 主机：arm64 行为项按 host 门 skip，
x64 行为项照常执行）+ arm64 目标交叉 typecheck 零 error + CI 全绿。

**遗留（维持 ㉞ 口径）**：drive28 群聊实弹轮（需用户一次真实群聊撤回，
`bash tools/dyntrace/d28_live.sh` 即进入观察窗）；M-R4（依赖 drive28
数据）；AMFI 原生 SIP 实证（硬件动作：Recovery 引导跑
tools/amfi_sip_probe.sh）。

## ㉞ 遗留项收口续轮（2026-09-20 深夜：arm64 verify 装机 fat 缺陷拦截 + 验收 harness 全链落地 + sweep 尾巴清欠）

任务口径同 ㉝（能做掉的做掉）。本轮把「ARM 实机验收」从**等机器**变成
**harness 就绪 + 一次 CI 触发即完成**，并在过程中拦截一个会在首次真机
验收时爆炸的真缺陷。

1. **arm64 verify 的 fat 装机件缺陷（P0，静态拦截）**：㉝ 落地的 CLI
   arm64 分支用 `Data(contentsOf:)` 原始字节按 VA 直接反解谓词 BL——
   thin 工件上 VA==文件偏移成立，但**装机 wechat.dylib 是 fat 双架构**
   （arm64 切片 0xae0c000 起），VA 直索引落在别的切片/填充上。
   真 270100 fat 实证：旧路径读 0x834802c1（非 BL → 必报
   "no bl predicate … recipe shape mismatch"）；MachImage 切片路径读
   0x97ee4997 = BL → **0x47575FC 与 ㉝ 静态反解的地面真值逐一吻合**。
   修复：`Verifier.ARM64.predicateVA(image:)`（MachImage 段表换算 +
   `word32(va:)`）+ CLI 改走切片路径；回归测试
   `arm64PredicateVAOnFatImageUsesSliceBytes` 用合成 fat 锁死
   （thin==fat 同值 + 旧路径病理证明 nil）。教训入 MAINTAINING
   「误改与踩坑」：**VA 定位禁止裸 Data+整数当偏移；thin 测过 ≠ fat
   测过**（与 ㉛ 「thin 与 fat 都要查」同源，这是它在代码侧的镜像）。
2. **worker 能力探针（诚实门）**：`Verifier.workerCanExecute(binary:)`
   ——真起一次 worker（host 架构单条 ret 的最小 blob，va=0），exit 0 =
   RWX 映射+执行可用（AMFI relaxed **或二进制带 unsigned-executable-
   memory entitlement**）；126 = AMFI 拒绝。替代两处 nvram boot-args
   猜测：CLI verify 预检（探针过 = 不打误导提示）与 VerifierTests 门
   （静态 memoize，一次 spawn 定全集）。x64 行为测试在本机（AMFI
   relaxed）新门下照常运行 = 探针阳性路径实证。
3. **arm64 合成镜像验收 harness**：手汇编 arm64 谓词镜像（x64 mini 的
   同语义孪生：strlen(GLOBAL)==len@[x8,#0x17] && memcmp==0；真 Mach-O
   arm64 thin 走 worker 的段映射+arm64 SSO 路径；adrp x16/ldr x16/br x16
   桩 → GOT 0x1C0/0x1C8）。两层测试：编码层
   （`arm64MiniImageStubEncodingsDecode`——桩解码器对镜像内真实字节，
   host 无关，x86 本机已过）+ 执行层
   （`arm64MiniPredicateClassifiesCorrectly`——host==arm64 ∧ 探针过
   才跑，ARM 机器/runner 上自动放行）。
4. **CI 验收 job（`.github/workflows/arm64-verify.yml`，workflow_dispatch）**：
   macos-15（arm64）→ 构建 → **ad-hoc 重签 wxkeep 带
   `allow-unsigned-executable-memory`**（runner SIP 关闭，entitlement
   路线让 RWX mmap 合法——与用户真机的 boot-arg 路线等效）→ 探针
   显式留痕（OK/blocked 均可见，非 0/126 判 worker bug 红）→
   `swift test --filter VerifierTests`（门后自动放行，拒则优雅 skip）→
   **CDN 真件端到端**（270100 dmg → fake app → `wxkeep verify`：fat
   lipo→catalog 定位→MachImage 谓词反解→worker→verdictPredicate 全链，
   即修复项 1 的装机形态实战）。~400MB/轮，不挂 push，push 后手动
   触发一次即完成 ㉝ 遗留 1 的验收里程碑；blocked 时降级记录不红。
5. **sweep 尾巴清欠**：09-20 11:04 sweep 里 269630 的 FileNotFoundError
   （当时缺 `_fat.dylib` 工件）——thin 双件俱在，verify_derivations
   自动 lipo 合成路径复跑 **5/5 PASS**（revoke x64 4c42b40 / arm64
   49af7f4 / guard 512c7f9 / keeptip 512cd6d / update 子集全对）。
   sweep 记录就此闭合，非数据回归。
6. **发布链对齐**：主仓 Formula 副本 0.2.0 → **0.2.1**（tap 已是 0.2.1；
   v0.2.1 config.json sha256 909efdf7… 与 tap 声明逐字节互证）。
   manifest 验签 ✓、目录 77 构建/1156 条 ✓、隔离 78（永久缺口口径
   不变）✓、COMPATIBILITY 由 gen_matrix 复核新鲜 ✓。

**回归**：123 测全绿（+3：fat 反解回归 / arm64 编码层 / arm64 执行层
——最后一项在 x86 主机按 host 门正确 skip）；release 重建 + 真机 x64
verify 冒烟（patched 全归零）✓；workflow YAML/shell 语法 + CDN 200
直链复核 ✓。

**遗留（与 ㉝ 相同口径）**：drive28 群聊实弹轮（需用户一次真实群聊
撤回，自主不可达）；M-R4（依赖 drive28 数据）；AMFI 原生 SIP 实证
（硬件动作）。arm64 验收：harness/CI 全就绪，等一次 workflow 触发或
一台 AMFI-relaxed ARM 真机。

## ㉝ 遗留项收口轮（2026-09-20：arm64 verify 落地 + 群聊静态图谱 + SIP 透明化）

对五项遗留逐一处置（用户指令：能做掉的做掉）：

1. **verify 的 arm64 版 ✅（机器就位，ARM 实机验收待一次）**：静态反解发现
   arm64 存在**独立谓词函数**（parse 内 cbz 前一条 `bl` 的目标，
   270100=0x47575FC / 270099=0x47574E8，"revokemsg" SSO 比较器，w0 返回）——
   行为验证在 arm64 由此成立。交付：
   - `tools/gen_verify_spec_arm64.py`：cbz 位点反解谓词 + 桩（adrp/ldr/br
     三件套）+ 懒初始化槽 → spec（270100/270099 双构建交叉验证，桩/槽
     跨构建稳定、谓词漂移 +0x114）
   - Verifier.swift：ImageArch 抽象（fat 按 host 架构 lipo、thin 校验、
     跨架构干净报错）；worker 双架构分支（x64 ff25 PLT / arm64 adrp+ldr
     桩解码）；**arm64 SSO 布局差异落地**（数据@0、直接长度@+0x17——与
     x64 的 size<<1@0+数据@+1 不同源！谓词反汇编实证）；gen3 配方挂
     270100 派生 spec（_verify_note 含重反解指引）
   - 语义诚实：谓词非补丁位点（补丁=cbz 翻转），arm64 probe = 家族完整性
     + harness 自检（verdictPredicate 两态同判据）；补丁效果仍由 strict
     verify 字节级证明承担（分支无条件直达 ⇒ 撤回路径不可达，等价强度）
   - 4 项纯逻辑单测（桩解码对 270100 地面真值、SSO 布局、BL 反解、
     谓词 verdict）——host 无关，跨架构可跑；worker 执行路径待 ARM 实机
     一轮验收（macos-14/15 CI runner 即可：WXKEEP_REAL_DYLIB + arm64 切片）
2. **群聊灰条 ⏩（静态收口完成，见 ㉜）**：3421BB0 三候选分类 + 毒值红线
   + drive28 就绪——剩余 = 一次真实群聊撤回的实弹轮（自主会话不可达）。
3. **verify SIP 透明化 ✅**：verify 命令预检 AMFI 状态（nvram boot-args），
   非 relaxed 引导先打说明（要什么/去哪看/strict verify 兜底），不再让
   用户面对裸崩溃或 126 退出码瞎猜。
4. **M-R4 ⛔（维持搁置）**：三方案评估不变；真正的解锁在 ㉜/㉝ 的群聊
   实弹轮（3421BB0 链路与插入漏斗 3415A30 的动态数据）。注意 ㉘ 的
   「tip_text 写标记语义」替代与 ㉒ 渲染层骨架约束相抵——tip_text 必须
   匹配 `"…" 撤回了一条消息` 骨架，自由度仅在引号内标记。
5. **AMFI 原生 SIP 实证 ⛔（维持）**：硬件动作（Recovery 引导），probe
   协议就绪（tools/amfi_sip_probe.sh）。

**回归**：120 测全绿（+4 arm64 解码器）；本机真机 verify（x64 patched
全归零）复验通过；arm64-only 切片在 Intel 宿主上干净报错（inspect 层
"no patch entry matched" 先行拦截，archMismatch 为防御纵深）。

## ㉜ 群聊灰条第二轮静态收口（2026-09-20：3421BB0 完成回调三候选分类 + drive28 就绪）

**自主静态轮（drive28 前置，全部 270100 x64 pristine 切片实测）**：

1. **解密串家族图谱（270100 全量 120 串）**：message_revoke_manager.cc ×15
   （0x392fa10..0x3963210）、mac_message_storate_impl.cc ×7（0x3a02350..），
   share_card/system/text_message_handler、base_msg_data_producer 全家族定位。
2. **3421BB0 完成回调全函数通读（0x920B，33 个直接调用）**：
   - `LOOKUP 0x3421BE0 → 0x5311B30`（0xE0，**全镜像唯一调用者=本回调**，
     rdi=[rsi]=svrid——撤回专用查库/删库入口）
   - `DBOP 0x3421C4D → 0x3680980`（0x840 大函数；rdi=&opstruct(16B)、
     rsi=[r14+0x360]、rdx=svrid、ecx=模式参。**被 UpdateCancelUpload
     (status9, ecx=2) 复用** → 通用消息 DB 操作派发器，非删除专属；
     3421BB0 内 ecx=edx 回调参数（==2 分支传 1））
   - `INSERT 0x342238E → 0x3415A30`（rsi=0x800000000 旗标；反查全镜像
     调用者 = 全消息 handler 家族的入库漏斗（text_message_handler/
     share_card/33D3100/33ED890/34766E0 等十余函数）——
     **AddMessageToDBbyWxID 同构体定性**）
   - 插入条件 `INS-COND 0x3422375`：`cmp byte [rbp-0x184],0`（= 回调
     ecx 参数低字节；≠0 → 插入）
   - 日志设施识别：6593A2D/4E5F190、659307C/53105A0 成对 + 0xCCCC…CD
     十进制格式化 = 日志对，不参与业务
3. **⚠ 毒值约束（补丁设计红线）**：DBOP 的 opstruct 由 movaps 写
   `0xAA×16` 预初始化，返回槽 [rbp-0x198] 在调用后被
   `test rax; lock inc [rax+8]` retain——**NOP 掉 DBOP call 必崩**。
   未来「保消息」补丁只能：改 svrid 入参（查无此行=良性失败，BetterWX
   SrvID+=1 同思路）/ 改模式参数 / 蹦床内让被调方照常写回结构。
4. **3680980 再定性（修正 ㉘ 假设）**：0x3421C4D 处 rdx=svrid、ecx=1；
   UpdateCancelUpload 处 ecx=2 且先写 [rdx+0x118]=9——模式参数分派，
   ecx=1 是否等于「按 svrid 删行」待 drive28 实弹回答。
5. **drive28.py 就绪**（tools/dyntrace/）：六断点
   （handlercmp/cb/lookup/dbop/inscond/insert）× 实验矩阵
   A 惰性透传（预期全链命中 + INSERT 的 rdi 应见服务端 replacemsg）
   × B 防护态（预期链路不达 = 现状群聊静默的对照组）。
   一次真实群聊撤回即可定案三分类 + 插入数据源 + 干预点。

**下一轮（实弹，需用户配合一次群聊撤回）**：drive28 惰性态跑 A →
按结果落 v2 runtime hook（保 newmsgid + DBOP 去武器化）或字节 keeptip3
变体 → P2 矩阵验证（群聊/私聊 × 他人/自己）。

## ㉛ 全版本一致性大二轮（2026-09-19 深夜：CDN 家族前段发现 ×6 + arm64 补齐 + zsbai 回填路线打通）

**任务**：以最新派生脚本对「所有 4 以上版本」复核功能点/补丁点一致性；
补齐未完成条目；与 GitHub 生态对比（用户指令原文口径）。

**1. 基线回归（30/30 全 PASS，0 FAIL）**：verify_derivations 对全部有工件
构建（4.1.13 线 21 + 4.1.15 家族 10，269602 无 CDN 工件预期除外）逐构建
7 项回归——目录数据与「CDN 原版重新派生」逐点一致（㉙ ㉚ 结论复核成立）。

**2. CDN 家族前段发现（六构建入库）**：对 4.1.15.0-.9（270080-89）补 HEAD
探测——**.4/.5/.6/.8/.9 五构建归档在**（.0-.3/.7 无）。㉙ 的「家族=.10 起」
是探边界探窄了。加上 4.1.13.64（269632 亦在档，.65+ 无），六构建全部
derive_build_from_cdn 派生（revoke 双架构 + guard + keeptip 对 + update 8
点）+ 引擎级六组往返 36/36 PASS。守卫漂移链与 call 变体链同步扩链
（269632 延续 E81E66E9FF 时代变体；270084-89 为 E83E4BE9FF 4.1.15 变体）。

**3. arm64 update 全线同构（新工具 + 152 条）**：`tools/locate_update_arm64.py`
（locate_update_x64 的 arm64 孪生：同一套 ObjC 元数据遍历 + arm64 形态校验
——栈序言 4B→ret / ldrb w0,[x0,#disp];ret→movz w0,#0;ret / strb w2,[x0,#disp]
→ret，disp 成对交叉验证）。**互证基线**：zengtianli/fzlzjerry 已登记的 11
构建 + 270090（fzlzjerry）共 12 构建逐字节 EXACT-MATCH。派生 25 构建
（4.1.13 线 10 + 4.1.15 家族 15）× 8 条 + 引擎级往返 31/31 文件 PASS。
update 域自此「四方法+访问器对 8 点双架构」贯穿 4.1.13.5-.64 + 4.1.15.4-.20
（269602 为纯 C++ 更新器时代单点，维持）。

**4. keeptip arm64 家族缺口（18 条）**：审计发现 270091-270100 九构建缺
arm64 keeptip 对（⑲ 只做了 x64；270090 来自 fzlzjerry 导入）+ 269629 缺——
全部按 gen3 几何（revoke 位点+0x7A0，store 恒 60E600F9）派生 + 往返 PASS。
**4.1.13+4.1.15 全线 keeptip 2+2（双架构）对称达成**。

**5. 270100 脏 thin 定位与修复**：全 thin pristine 审计（按 expected[0]
全位点扫描）发现 270100_arm64.dylib 是 ⑪⑪ 轮补丁实验残留（revoke 位点
82000014）——㉗ 只替换了 fat，thin 从未被验。从 pristine fat 重抽 + 复验。
教训入 MAINTAINING「工件目录惯例」：**thin 与 fat 都要查**。

**6. zsbai 回填路线（4.1.9-4.1.12 时代）：打通工程、判定源头损坏**：
⑭「zsbai 均无归档」结论半对半错——archive_index 里 4.1.9-4.1.12 全线
在档（此前从未逐 tag 探明），但逐 tag 实测后确认**老线资产系统性源头
损坏**：抽样 4.1.9.26/.27/.31/.57、4.1.10.24、4.1.11.51、4.1.12.53 全部
同签名失败——sha256 与 GitHub digest 完全一致（排除传输损坏）+ XZ 解到
99.9% 处 corrupt（上传时即坏）；dmg 尾部 UDIF footer 落在损坏段，无挂载
路径。隔离回填就此定性永久缺口（无据推定升级为 digest 级实证）。工具
`tools/derive_from_zsbai.py` 沉淀为可复用框架（digest 校验下载 + tag→build
映射 + 全条目官方字节审计 + 派生），未来第三方存档出现即续用。**坑三条**：
镜像跨源断点续传拼坏 XZ（必须整文件+digest）；镜像 content-length 不可信；
解压/挂载峰值 ~2GB×并发任务会挤爆盘（fat 删除 + arm64 切片即删纪律）。

**7. 生态对比（related-tools-analysis 同日节）**：tanranv5 09-19 新增
blockUpdate 6 点 vs 我们 8 点——四公共方法位点**逐字节同址**（独立逆向
互证），其两点额外（initSparkleConfigIfNeeded /
setAutomaticallyChecksForUpdatesIfNeeded:）为无访问器对路线的替代面，
我们 ⑬ 真机已证现有 8 点封死改写；六新构建号 GitHub 全站无覆盖（wxkeep
首发）；fzlzjerry patches.json（29 构建全带 expected）入手作第三方互证源。

**目录终态**：77 构建 / 1156 条（+6 构建 +302 条 vs ㉚ 后）；4.1.13+4.1.15
全线 revoke 2/keeptip 2+2/update 8+8 完全对称。knownHooks 20→30 行
（kMaxExtHooks 32 内）。

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

**⛔ 关闭（2026-09-20 复核：被更强机制取代）**：`git log -S` 全历史零落地
实证。设计目的（新构建快速预检）已由 signatures.json 签名配方（imm64 锚点
+ arm64 几何，锚点即带字节门）+ watch 流水线的配方自动定位承担——直接产出
全量 expected 条目而非相关性提示；verify_derivations 另有引擎级字节校验，
强度高于 12B 指纹比对。`--hashes` 的切片哈希登记（known_dylib_hashes.json）
是独立机制，保持不变。落地一套无消费者的数据通道违背「复查过不改」同款
原则，按取代关闭。

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

### ⑱ 第五轮复查（2026-09-19：工具链尾部 + 发布流水线空转修复）

1. **sign_manifest.py 幂等化（消 bot 空转提交）**：manifest 带 generated_at
   → 每次签名必然产生新字节 → manifest-sign job 每次 master 推送都生成
   bot 提交，迫使协作者反复 rebase（⑬⑭ 两轮连实历三次）。修复：现有清单
   的受保护文件哈希与当前数据一致时保留原清单不重写（时间戳仅在真实数据
   变化时刷新）。连续两次签名实测第二次跳过、git 干净。
2. **gen_matrix 补 4.1.15 家族展示版本**：270091-270100 十个构建在兼容
   矩阵里显示为「?」——按 4.1.15.N ↔ 2700(80+N)（270100 观测为 4.1.15）
   补全 KNOWN_DISPLAY，矩阵重生成。
3. 工具链尾部核对无缺陷：count_quarantined（root 相对解析 ✓）、
   merge_catalogs（SOURCES_PRI 模块级定义已由并行审计修正 ✓）、GUI 子包
   （只读状态面板，职责收窄诚实）、contribute_expected（machutil 化）。

至此五轮复查累计：3 个真缺陷（validate 跨度不变量/沙盒路径/区域扫描崩
溃）+ 半套态重签防线 + 流水线空转与故障隔离 + 若干可用性收尾，全部带
回归或实测。主源码与工具链进入低熵稳态，下一轮复查的边际收益主要来自
新功能面（M-R3 {content}、arm64 实机数据）而非存量代码。

### ⑲ 优化完善轮（2026-09-19：x64 keeptip 全家族落地）

**功能补齐**：revoke-keeptip（私聊撤回提示保留）从 270099/269602 扩展到
4.1.15 全家族——270091/93/95/96/98/100 各 2 条 x64 条目入库（12 条）。
推导方法：newmsgid 存储点（call 转换器 + `48 89 83 C8 01 00 00` store
[rbx+0x1C8]）在 parse 函数内**家族恒定偏移 +0x85d**（六个构建唯一命中、
expected 12B 逐字节相同 `E83E4BE9FF488983C8010000`——270099 亦同，此前
笔记笔误 0x65D）；恢复型条目挂同构建 isRevokemsg 入口（归一化形态）。

**harness 修正（非数据缺陷）**：BackfillRoundtripTests 原断言假设全部
为 patch 型条目——归一化恢复型条目（asm == expected[1]）在 pristine
镜像上正确地呈 .patched / 反演时 .alreadyPatched。放宽为「起始态已知
（非 .unknown）+ 终态字节恒等」，对两类条目形态都保持强保证。六构建
全 PASS。

keeptip 语义边界不变：v1 行为模型（私聊提示保留 + 消息保留；群聊静默）
为 269602/270099 实测，家族同构推定同 wrapper 诚实边界。README 限制
条目已更新。

### ⑳ 补遗（2026-09-19 晨：runtime 分发闭环）

**发现**：runtime 组件从未随 release 分发——`runtime install` 默认找
`.build/release/`，brew 用户（无源码树）实际无法使用 runtime 功能。
闭环修复：
- release.yml 构建 universal libwxkeep_runtime.dylib 并挂 release
- tap formula 加 `runtime` resource → Cellar lib/
- RuntimeInstall dylib 搜索序（--dylib > WXKEEP_RUNTIME_DYLIB > brew
  Cellar lib/（符号链接解析）> exe 同目录 > .build/release）
端到端验证：重打 v0.2.0 tag → CI 产出双资产 → tap 更新推送 →
brew reinstall（7 files 含 Cellar lib dylib）→ 免参数
`wxkeep runtime install` 自动解析 Cellar dylib → 重启微信 armed ✓。

### ㉑ 补遗（2026-09-19：改写计数器——把「等肉眼」变成「读 marker」）

撤销文案效果验证的最后盲区是「hook 武装了，但改写到底有没有发生过」。
runtime.m 加 fires/hits 双计数（needle 命中含自发跳过/放弃；实际完成改写）
随 marker 每次启动回写——打开含旧撤回提示的聊天（重解析路径）或收到新
撤回，计数即增长。本机实测：armed 起步 fires=0 hits=0（新会话无撤回
流量，符合预期），后续任意时刻读 marker 即得证据。

### ㉒ 真实撤回闭环（2026-09-19：M-R2 文案自定义实机验证完成，附关键新知识）

真实撤回事件驱动的三轮剥离（计数器 instrumentation 价值实证）：

1. **wrapper+0x130 被实机证伪**：真实他人撤回 fires=0 → 按 ⑧ 预案切
   parse 入口直挂（drive25 地面真值 rsi=XML SSO）。全家族 14 行地址表
   切换（x64 parse 序言 554889E54157415641554154、arm64
   F85FBCA9F65701A9F44F02A9FD7B03A9 各自七构建逐字节相同）→ hits=30+
   拦截成功。
2. **等长约束显形**：hits 增 fires=0 → tip_text 34B > 内文 ~31B 被拒。
   短文案解决。
3. **自发门显形**：用户自撤测试 hits 增 fires=0 → rewrite_self=false
   默认门（按设计）。开启后 **fires=14/14 全成功**。
4. **渲染层模式匹配（关键新知识）**：改写成功但界面显示英文
   "Unsupported message. View it on your phone." → 依次排除文案长度/
   自发门后，g_last_inner/g_last_fired 双样本对照证明改写字节完美 →
   渲染层按官方骨架（`"…" 撤回了一条消息`）匹配显示，非规范内容回退
   Unsupported 占位（英文 = 英文 UI 的内部串）。drive25 的「任意文本
   可显示」是当次 parse 内存路径；持久化渲染走模式匹配。
5. **最终方案与验证**：tip_text = `"⚠️" 撤回了一条消息`（官方骨架 +
   ⚠️ 替换昵称位，30B ≤ 31B）→ 用户实测界面显示该文本 ✓。三大能力
   同时成立：消息保留（silent/keeptip）+ 提示可渲染（keeptip 变体，
   silent 的 isRevokemsg 中性化会使提示渲染为 Unsupported——固有行为
   非改写破坏）+ 文案自定义（parse 直挂）。
6. **发现过程工程**：fires/hits/last/inner 四元计数器与采样随 marker
   回写 + lldb 只读附加读存活进程全局变量（静态符号 nm 偏移 + 模块基
   址）——「等肉眼」升级为「读证据」。注意 dylib 布局变更会使旧偏移
   失效（本轮 33M 假计数教训：加 g_last_fired 后偏移移动，nm 重取）。

**M-R2 文案自定义功能状态：✅ 实机验证完成**。有效配置契约：
tip_text 匹配 `"<X>" 撤回了一条消息` 骨架（X 可为 ⚠️/emoji/短标记，
或含 {from}——受长度约束），总长 ≤ 原提示内文。

### ㉘ 群聊灰条深 RE 第一轮（2026-09-19 午后：完整 XML 模型 + 状态机修正 + 三个假说排除）

**实验设计**：惰性 hook 态（keep_message=false 无 tip_text，runtime 透传）+ lldb
四断点（parse 0x537dcd0 / revoke_manager 二次分派 0x394be13 / 旧状态写
0x355abf0 / async-body 0x3951040，基址探针按 hook 桩签名 48b8…ffe0 验证——
SBModule 对手动映射的 wechat.dylib 报异常基址，UUID 解析也失败，字节探针
是唯一可靠法）。两次真实群聊撤回 + 用户界面观察。

**四大发现（其中三个推翻既有认知）**：

1. **群聊撤回 sysmsg XML 完整携带全部字段**（d27_parse_1/12.xml 实拍）：
   `<session>45845756908@chatroom</session><msgid>912805043</msgid>
   <newmsgid>462001335750234475</newmsgid><replacemsg><![CDATA["Jennifer"
   撤回了一条消息]]></replacemsg>` ——与私聊同构（私聊仅少 session 字段）。
   **灰条文案是服务端预生成并随 XML 下发的**（replacemsg 字段），不是客户端
   合成的。㉔「客户端按 newmsgid 查到原消息才合成提示」的**客户端合成假说
   被证伪**——文案根本不需要查原消息就能拿到。
2. **未防护对照组灰条正常显示**（用户截图实证）——完整流程：删除原消息 +
   显示灰条，两者同时发生。
3. **旧「状态写」0x355abf0 两次真实撤回零触发**——该函数是
   UpdateCancelUploadMessageStatus（上传取消状态机，写 +0x118=9），与撤回
   **无关**。⑥⑧ 轮把它标记为「M-R4 状态写唯一位点」是误判（drive26 在
   keeptip 态观察到零命中的真正原因：它本来就不在撤回路径上，不是
   「newmsgid=0 → 查找失败 → 不触发」）。M-R4 的对象布局结论（+0xC=type、
   +0x118=状态常态 0x3）仍有效，但 0x118=9 语义归属上传取消。
4. **撤回状态机真宿主 = share_card_message_handler 0x3444b40**（符号解密
   实证）：`cmp [msg+0x118],2` → ==2 走 3421bb0(…,1,1) 回调；≠2 写
   `[msg+0x118]=5`。消息 +0x118 状态枚举修正：0x3=常态、2=撤回已收到、
   5=待撤回。唯一的写 2 点在 0x33b1407（emoticon handler 家族的
   0x33ae670 函数内，vtable 派发无直接调用者）。文本消息的撤回状态迁移
   推测走同构的 text_message_handler（0x3453860+），待下轮实弹。

**群聊灰条缺失的机理修正**：既然文案是服务端给的、对照组能显示——清零
newmsgid 后灰条消失的原因必然在**消息链定位**环节：灰条需要插入到被撤
消息的位置（或与被撤消息行合并显示），newmsgid=0 → 定位失败 → 插入/改写
不发生。这与 zengtianli 的「newmsgid 锚定删除与群提示插入」表述一致，
但插入的内容（文案）来自 XML 而非本地合成。**推论：只保 newmsgid 的
「定位」用途而废其「删除」用途的干预点，在 parse 之后、按 newmsgid 查
库的函数上**——查库命中后把「删除」分支废掉、保「改状态/插提示」分支。
这正是 kanxue Windows 管线（GetMessageBySvrId → DeleteMessage →
AddMessageToDBbyWxID）的 Mac 对应物，干预点候选=查库函数返回后的第一个
条件分支（caller A 0x351c8b0 的 343e0d0/343c330 调用簇）。

**撤回状态机调用链（270100 全景，全部 vtable 派发无 E8 调用者）**：
```
sysmsg 到达 → parse 0x537dcd0（XML SSO 完整字段）
  → revoke_manager [0x394be13 二次分派]（d27 未捕获——vtable 内联或时机）
  → share_card_handler 0x3444b40: cmp [msg+0x118],2 分支
      ==2 → 3421bb0(…,1,1)（完成回调，内部 5311b30=查库/DB 层）
      ≠2 → [msg+0x118]=5（标记待撤回）
  → caller A [0x351c8b0..0x351db10)（message_manager 核心）:
      343e0d0 → 343c330（memset 0x118B + 序列化调用簇）
      → 0x355abf0（UpdateCancelUpload，撤回不走）
      → 0x351db10 递归 → 355bbf0/355b680 后处理
```

**工件**：var/wxarm/d27.log（全捕获日志）、d27_parse_1.xml / d27_parse_12.xml
（两次撤回的完整 XML）、runtime.json.pre-d27.bak（实验前配置备份，已恢复）。
工具沉淀：tools/dyntrace/drive27.py（四断点观察轮，hook 桩签名基址探针）。
decrypt_strings.py 修 struct 缺失 import（NameError 崩溃）。

**下一轮（第二轮）路线图**：断 0x3444b40 的 cmp [msg+0x118],2 处
（0x3445e20）+ 3421bb0 入口，防护态（keep_message=true）与惰性态各撤一次，
对比「查库命中/失败」在 0x118 状态机上的分叉——命中废删除的具体指令位置
就是 runtime 第二 hook 点（工程上与 parse hook 同款地址表+序言门）。

### ㉗ 优化完善轮二（2026-09-19 午：WeFlow 对照 + 证据闭环 + watch 4.x 判新）

**输入**：WeFlow 6.3.1 双架构 DMG 静态解剖 + 独立代理全网复查（详见
related-tools-analysis.md 2026-09-19 两节）。要点结论：无 4.1.16；WeFlow 是
聊天导出工具（Frida ccpbkdf2_hmac 深层断点提密钥 + welive 直读 WCDB +
DB 级 anti-revoke 事后回写），与本项目安全模型冲突——不吸收，归档为对照
路线；其仓库已被 Tencent 法务函清空（同 chatlog）。

**六项交付**（115 测全绿，release 构建通过）：
1. **marker 周期回写（证据闭环缺口）**：㉑ 的计数器设计意图「读 marker 即
   得证据」实际未闭环——marker 只在启动路径写，fires/hits/zero 永远停在
   启动快照 ≈0，会话内增长只有 lldb 读存活进程一条路。修复：30s 周期
   证据回写（QOS_UTILITY 定时器，write_marker 拆 loud/quiet——周期路径
   无 NSLog 防日志刷屏）；last/inner 采样改 sanitize-copy（本地副本强制
   尾 NUL，消除 hook 写/读窗口的理论越界读）。
2. **`wxkeep runtime tip` 命令（文案配置的 #1 脚枪）**：手改 plist 长路径
   → 写坏骨架 → 界面 Unsupported 是 ㉒ 发现的实测坑。新命令带校验：
   官方骨架 `"…" 撤回了一条消息` 强制（含空昵称/缺后缀/多尾巴全拒）、
   长度门按**展开后等效**评估（{from} 占位符 6B 会被昵称替换，静态等效
   >31B 或纯静态 >31B 拒）、`<>&` 剥除与 dylib 同语义（移除非替换）、
   纯 `"{from}"` 形态识别为恒等长最优解、`--rewrite-self on|off`、`--clear`；
   读路径展示当前值 + 校验状态。原子写保留 hooks 段。
3. **`runtime status` 证据面**：解析 marker 的 fires/hits/zero 显示
   （含 30s 粒度回写说明），改写效果不再依赖 lldb。
4. **update-data 新旧条目数口径**：旧值只数签名目录本体（不合并
   config.local.json），与远端 newCount 同口径——旧值虚高的展示失真修正。
5. **配方名→identifier 映射**：locate/autoLocate 硬编码 "revoke" 在
   signatures.json 未来并入 update* 配方时会静默错标（silent 才应用、
   keeptip 漏打）。按名字前缀归类（update*/multiInstance*），未知前缀
   保守归 revoke（现状行为）；mergeLocated 按 identifier+binary 双键分组。
6. **watch CI 4.x 判新（设计落地）**：④ 记录的「挂载读 Info.plist 判新」
   实施——collector 对点分 DestVersion 的 release 输出 `? <url> <tag>`
   候选行（实测最近 15 个 release 全是点分=旧收集器全漏的实证）；workflow
   下载→挂载→`plutil -extract CFBundleVersion` 判新，解析 ≤ known 即 break
   （release 倒序其后更旧，稳态每天恰好一次额外下载）；processed 计数
   输出防「无事发生还开 issue」的日频噪音。本地验证：collector 对真实
   API 实跑（15 行候选）+ bash -n + YAML 解析。
   注：zsbai 已归档 4.1.15.20（=270100）——热修构建进归档源证实。

**复查过不改**：Config.load 的 cwd 优先搜索序（随机目录的陌生 config.json
可被 manifest=legacy 载入——收紧会破源码树工作流，维持现状+已有 note）；
zero_newmsgid_digits 只处理首个 <newmsgid>（sysmsg 单消息单标签，实测形态）；
verify 仅 x64 spec（arm64 行为验证待 RE，已知限制文档化）。

**意外收获：270100 脏工件定位与修复**：verify_derivations 270100 起手 2/5
（revoke/guard 配方 FAIL）——排除代码回归（stash 前后同结果）后三方对照
（CDN 原版 / var/wxarm 存档 / 装机）定性：`var/wxarm/270100_fat.dylib` 是
⑪⑫ 轮端到端补丁实验的**全量补丁快照**（silent+guard+update 全在场，从未
还原），配方确认在补丁态字节上失败——工具与数据无回归，工件脏。已用 CDN
原版替换（`xWeChatMac_universal_4.1.15.20_270100.dmg` 入 var/cdn 缓存），
270100 verify_derivations **7/7 PASS**（含 keeptip store 与 hook 双架构行，
此前 5 项里 2 项一直被脏工件掩盖）。三条新情报：
1. **CDN 归档直链用点分 WeChatBundleVersion**：270100 的直链是
   `…_4.1.15.20_270100.dmg`（非 `…_4.1.15_270100`）——watch workflow 的
   CDN 回落 URL 用 zsbai tag（点分）构造，本就正确；裸营销版本形式会 404。
2. **装机状态解码**（非缺陷）：本机微信当前 = revoke 字节已还原 +
   update 字节在位 + runtime hook armed——正是 README「进阶配置」的
   runtime 承担防撤回形态（㉒ 轮用户实配）。
3. **热修 vs CDN 同构建号非逐字节相同**：装机（热修通道）与 CDN
   4.1.15.20 的 270100 切片 LC_UUID 相同、补丁相关位点逐字节一致
   （7/7 派生互证），但文件大小差 1.7MB（高位段布局不同）——
   expected 门按位点比对不受影响，登记为已知现象。
   工件卫生教训：**var/wxarm 的存档副本跑过补丁实验后必须还原**
   （BackfillRoundtripTests 对 fixture 有终态断言，手工会话没有）——
   本轮已把该规则写入 MAINTAINING「工件目录惯例」。

### ㉔ 补遗（2026-09-19：群聊消息保留实机验证 ✅）

用户实测群聊撤回：消息保留 ✓。计数器 zero=2（私聊 1 + 群聊 1）证明群聊
撤回指令同样流经 parse hook 并被清零——通用 keeptip 的群聊路径机制闭合。
群聊灰条提示不显示为已知限制（客户端按 newmsgid 查到原消息才合成提示，
清零后查找失败、合成不发生——与字节 keeptip 同语义，全生态皆然）。
注意：进程重启会使运行时计数器归零（marker 为启动时快照）——lldb 读
存活进程全局变量时必须按当前 dylib 的 nm 符号表重取偏移（布局随编译
变化，⑰ 轮 33M 假计数教训的完整版）。

### ㉙ 全版本一致性大回归 + 家族补齐（2026-09-19 午后：CDN 补缺口构建 ×3 + 4.1.13 对照 ×2 + 生态对比）

**任务**：用最新派生脚本（verify_derivations 全位点回归链）对「所有 4 以上版本」
逐一复核功能点/补丁点一致性；补齐未完成条目；与 GitHub 生态对比。

**1. 全家族回归（7/7 × 7 构建）**：270091/93/95/96/98/99/100 每构建 7 项
（revoke x64/arm64 配方、parse guard、keeptip store、update imps、hook 行
双架构）全部 PASS——catalog 数据与「从 CDN 原版重新派生」逐点一致。

**2. 缺口构建 CDN 回捞（关键解锁）**：270090/270094/270097 的
`xWeChatMac_universal_4.1.15.{10,14,17}_<build>.dmg` 归档直链存在（此前
④ 轮 94/97 走 zsbai gh-proxy 后未保留 dylib，270090 从未适配 x64）。
下载→提取→同款派生链，三构建全部家族一致命中：
- 守卫字节恒 `84C00F84A6000000`（je disp32=A6 家族不变）
- keeptip store 字节恒 `E83E4BE9FF488983C8010000`（call disp 家族不变）
- revoke/arm64 序言、update imp 形态全同构

**3. 条目补齐（36 条）**：270090 补整个 x64 面（revoke 配方 + guard +
keeptip×2 + update×4）；270094/97 补 keeptip×2 + update×4（guard/revoke
④ 轮已有）。**knownHooks 14→20 行**（270090/94/97 × 双架构；kMaxExtHooks
16→32 留 update-data 余量）——地址表达「4.1.15 全家族（除未发布 270092）
× 双架构」完整覆盖。x64 行按 ㉒ parse 直挂口径（270090:5374b80 /
270094:5378bc0 / 270097:537d2b0，12B 序言门全过）。

**4. 4.1.13 时代对照（269629/269631，配方跨时代命中）**：全部派生器在
4.1.13.61/63 上同样命中——revoke_x64（isRevokemsg 0x4c42480/0x4c42d50）、
guard（512c139/512ca09，disp32 仍 A6）、keeptip store（parse+0x85d 偏移
**跨时代不变**；call disp 为 E81E66E9FF 时代变体，expected 按实际字节）、
update×4（XAppUpdateManager 在 4.1.13.6x 即在场——修正「Sparkle 4.1.15
回归」的时间线：269631 arm64 的 zengtianli 8 点与此互证）。**三方位点互证**：
tanranv5 269629/631 的 x64 revoke 位（512BE50/512C720）恰为我们派生链的
parse 入口；zengtianli 269631 arm64 revoke 49afa14 与 gen3 配方命中一致。
269629/631 各补 8 条（revoke isRevokemsg 新路径 + guard + keeptip×2 +
update×4）；不加 hook 行（runtime 组件维持 4.1.15 家族口径）。

**5. 生态对比（详见 related-tools-analysis.md 2026-09-19 第三轮）**：
wxkeep 是唯一双架构 + 4.1.15 全家族仓库（X1a0He 2.10.0 同顶 270100 但
arm-only 闭源；zengtianli 止于 269631；tanranv5 止于 270098 x64）。
新情报：tanranv5 的 WCDYWrapper 完整性绕过（270098 x64 打了才活）对本
项目重签管线不适用（270100 x64 真机 ⑬ 轮全链通过）——定性为流程差异
（盲写 vs expected 门 + entitlements 保留重签）。zengtianli docs 论证群聊
提示正解 = 保真 newmsgid + NOP 下游虚派发删除调用，与 ㉘ 第二轮路线互证。

**守卫位点漂移链（全量）**：269602:50a5639 → 269629:512c139 →
269631:512ca09 → 270090:5374e69 → 270091:5376609 → 270093:5378cf9 →
270094:5378ea9 → 270095:537d5a9 → 270096:537d589 → 270097:537d599 →
270098:537ddb9 → 270099:537de29 → 270100:537dfb9（4.1.13→4.1.15 换页
+0x24B30，家族内单调爬升）。**keeptip parse+0x85d 偏移跨全部 12 构建不变**。

**补充（同日访问器对家族化）**：locate_update_x64 的访问器形态校验过严
（只认无序言 movzx/sil 形态；实拍家族形态 = `554889E5` 序言 + movsx
`0FBE47`/`mov [rdi+disp],dl` + `5DC3` 尾）——270099 上「形态不符跳过」的
真实原因是这个。修正为序言感知 + movsx/movzx、sil/dl 双形态 + 已补丁态
（ret / xor+ret）识别后，**8 点全集（四方法 + 访问器对）横跨全部 12 个
测试构建（4.1.13.61 → 4.1.15.20）全部派生成功**。访问器条目 ×44 入库
（270100 的 4 条与 ⑬ 真机验证条目同址去重），12 构建 update 组往返验证。
这是「功能点跨版本一致性」的直接成果：update 域从「270100 独享访问器
加固」升级为全家族 8 点同构。

**收尾**：269629 的 arm64 revoke 条目（gen3 命中 49af294，expected 40100034
与 269631 同字节）补入——12 个测试构建全位点验证收口：家族 7 构建 7/7、
缺口 3 构建 7/7、4.1.13 时代 2 构建 5/5（无 hook 行故 5 项）。116 测全绿，
manifest 重签验证，COMPATIBILITY 重生（64 构建）。

### ㉚ 4.1.13 全线回捞（2026-09-19 深夜：CDN 归档全探明 + 18 构建派生验证入库）

**输入**：对官方 CDN 构建归档直链做 4.1.13 线 N=1..63 全量 HEAD 探测——
归档覆盖 .5-.11（269573-579）与 .50-.63（269618-631），.1-.4 与 .12-.49
（含 269602=.34）为永久缺口；4.1.12 及更老线全线 404。线性映射
4.1.13.N ↔ 269568+N 由 20 个 200 应答逐一实证（此前 hints 表对 269578/579
的 tag 映射是错的——4.1.13.59 实为 269627 的 tag）。

**交付**：18 个构建（7 个目录外新构建 269573/618/620/621/622/625/630 +
11 个补 x64 面 269574-579/619/624/626-628）全部派生 **revoke×2 + guard +
keeptip 对 + update 8 点**（248 条），每构建六组引擎级往返验证（18×6 全
PASS，含 zengtianli 存量 arm64 条目首次对 CDN 官方原版字节的机器校验）；
269578/579 各 2 条 tanranv5 隔离条目回填放行（隔离 82→78，余量全部为
无归档老构建）。269573 把 arm64 gen3 签名代实测下界从 269574 推到 269573。
合并后目录 71 构建/854 条，抽查 verify_derivations 5/5，116 测全绿，
manifest 重签验证。

**工具沉淀**（本轮三个新脚本 + 四处改进，全部服务「其他版本补丁点」复产）：
- `tools/derive_build_from_cdn.py`：dmg→thin 抽取（省磁盘不留 fat/dmg）→
  locate 配方（fake bundle）→ guard → keeptip（expected 按实读字节）→
  update 8 点 → arm64 keeptip 几何派生（新构建）→ 隔离回填，产出 staging
- `tools/verify_staging.py`：按 target 分组的 BackfillRoundtrip 驱动
- `tools/merge_staging.py`：staging → config.json（既有条目优先/去重/回填）
- backfill_expected 的 BUILD_TO_TAG_HINTS 按实证修正；archive_index.json
  刷新（111 条，补 4.1.15.15-20）；verify_derivations 支持 thin-only
  工件（lipo 合成临时 fat，用后即删）

**方法论教训（防重蹈）**：
1. **BackfillRoundtrip harness 不可混组互斥变体**：silent 的 revoke 条目与
   keeptip 的归一化恢复型条目同址（isRevokemsg 入口）互写——混在一个
   entries 数组会在幂等步互相还原对方（真实引擎按变体二选一，不共存）。
   正确用法=按 target identifier 分组各跑各的（verify_staging 固化）。
2. **harness 环境变量用相对路径会静默跳过**：`WXKEEP_BACKFILL_DYLIB` 的
   fileExists 检查在测试进程 cwd 与调用 shell 不一致时失败，disabled 分支
   报「not set」且 suite 仍显示 passed——0.001s 的「通过」全是跳过。驱动
   脚本必须绝对路径 + 把 "skipped:" 判为失败。
3. swift-test 结果缓存不感知环境变量——同一 filter 反复跑会回放缓存结果，
   换环境变量输入的 harness 必须核对真实执行时长/失败文本。
