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
8. **runtime hooks 地址行（可选，供自定义文案功能）**：
   `python3 tools/derive_runtime_hooks.py <thin-x64.dylib> <parse-guard-site-hex> <build>`
   ——守卫位点→LC_FUNCTION_STARTS→**parse 入口直挂**（㉒ 实弹定案口径：
   rsi = sysmsg XML 裸 SSO；wrapper+0x130 旧口径已被真实撤回证伪，wrapper
   拓扑仅保留为交叉诊断），序言门 `554889E54157415641554154` 全过才产出。
   行加入 Sources/wxkeep/RuntimeConfig.swift 的 `knownHooks`（跨边界测试
   会锁 schema），并同步 arm64（arm64 行 = catalog arm64 revoke 位点所在
   函数起点，序言门 `F85FBCA9F65701A9F44F02A9FD7B03A9`，见 ㉒ 轮记录）。
   arm64 行加好后跑 `wxkeep runtime hooks` 刷新即可，无需重装 dylib。
9. **verify spec 变体（可选，行为验证的构建覆盖）**：
   `python3 tools/gen_verify_spec.py <thin-x64.dylib> <isRevokemsg-site-hex> --variant <build>`
   `python3 tools/gen_verify_spec_arm64.py <thin-arm64.dylib> <cbz-site-hex> --variant <build>`
   ——spec 的 stubs/zero_regions 是绝对 VA、**逐构建漂移**，新构建一律
   各自派生变体并追加进 signatures.json 对应配方的 `verify_variants`
   （revoke_x64 收 x64 行、revoke_arm64_gen3 收 arm64 行），不改写 legacy
   `verify`（270099 族）。位点 VA 从 config.json 该构建 revoke 条目取。
   选中规则：本构建命中变体优先，否则回落 legacy（不适用镜像由 worker
   形态门 exit 4 优雅跳过）。改 signatures.json 后必须 `sign_manifest`
   重签。本地验收：arm64 原生跑 `wxkeep verify`（thin 切片造 fake app）；
   x64 在 macOS 27 本地不可达（CLT compat 库已无 x86_64 切片）——静态
   镜像门（FF25 形态 + 槽界内 + 8 对齐）+ CI `arm64-verify.yml` 的
   Rosetta x64 端到端步骤承担。仓库数据契约由 VerifyVariantTests 锁。

**流程顺序（2026-10-17 实证，假红教训）**：`merge_staging` 改过 config.json
之后、`sign_manifest` 重签之前，CLI 的供应链门会拒绝加载数据——
verify_derivations 此时跑出 revoke `derived=None` 的 5/7 假红（locate 全空，
不是配方 miss）。正序永远是：**merge → sign_manifest → verify**。

**CDN 缺口扫描（zsbai 漏归档兜底）**：watch CI 只看 zsbai，热修通道构建若
zsbai 漏收（如 4.1.15.51/.52）就永远不会被发现。2026-10-19 起
`watch_new_builds --cdn-probe` 已自动化该兜底：老格式数字 DestVersion 锚点
多点一致定 base；现行点分 body 时代（2026-10-19 实测 body 已无数字构建号）
由最高 tag 定线 + 最新 tag 的 CDN X-搜索定真实构建号（base = X - maxN），
候选 known+1..X+8 按线性映射反推点分做 range GET bytes=0-0 探测
（404=不存在、206=在档）；线内已有 tag 的 N 排除（防与「?」点分行双重
下载 500MB dmg），探测行输出在 release 行之前（「?」行解析到 ≤ known 即
break，会截断追加在尾部的行）。手动定界/新营销线定界用
`tools/probe_cdn_line.py`（对照 4.1.15 线 22/65 精确复现已知档案集）。
.23-.50 全 404 是永久缺口，.51/.52 在档即 66 轮补入的来源。

**4.1.14 线无 Mac 归档（2026-10-19 定案）**：zsbai 全量 115 release 零
4.1.14；CDN 上 256 阶梯假设位（base=269824；阶梯 269312/269568/269824/
270080 等差 256，其中 4.1.13/4.1.15 两点 25+ 直链实证、4.1.12 段与 zsbai
.25-.29 重叠互证）0/65，全区间 base 269633..270083 × N 0..15 扫描
（7216 探测、零网络异常）零命中——该营销号在 Mac 侧无任何归档痕迹，判
永久缺口。残余盲区（记录在案）：base<269633 且公开段 N≥16 的交错布局与
观察到的单调阶梯矛盾，未扫。

## 已知签名代（arm64 revoke，几何特征）

| 代 | 构建 | cbz 字节 | delta | newmsgid 字段 |
|---|---|---|---|---|
| 1 | 268575–269136 (4.1.10–4.1.11) | E00F0034 | +0x794 | 0x168 |
| 2 | 269332–269341 (4.1.12) | 40100034 | +0x7A0 | 0x198 |
| 3 | 269573+ (4.1.13 全线；2026-09-19 实测下界从 269574 前移) | 40100034 | +0x7A0 | 0x1C8 |

x64 revoke（imm64:revokems 锚点 + padding-boundary + unique-positive-callers）：
2026-09 在 269602 验证（0x4BC5940, 9 callers；已打补丁态靠双边界推导仍可定位）；
269573-269631 全线与 4.1.15 全家族同构命中（㉚ 轮 18 构建实证）。

## 官方 CDN 构建归档（2026-09-19 全线探明；同日一致性轮扩界）

`https://dldir1v6.qq.com/weixin/Universal/Mac/xWeChatMac_universal_<点分版本>_<构建号>.dmg`
按构建号永久归档（非 XZ、无速率限制）。覆盖（HEAD 实测）：
- **4.1.15 全家族**（4.1.15.4-.20 = 270084-270100，除从未发布的
  270087=.7 与 270092=.12；.0-.3 亦无归档——家族公开段起点即 .4）
- **4.1.13 的 .5-.11 与 .50-.64 段**（= 269573-269579 与 269618-269632）
- 缺口：4.1.13.1-.4、.12-.49（含 269602=.34）、**4.1.14 整线（2026-10-19
  全区间扫描定案无归档，见上节）**、4.1.12 及更老全线
  （CDN 侧无归档；zsbai 侧见下）
- 线性映射：4.1.15.N ↔ 270080+N、4.1.13.N ↔ 269568+N（25+ 直链实证）
- ㉙ 旧结论「4.1.15 家族=.10 起」是探边界探窄了——.4-.9 段 2026-09-19
  补探才发现（六构建当即派生入库）。**教训：家族边界要向低段补探，
  不能只向高段找新**

**zsbai 归档（4.1.9-4.1.12 时代构建——2026-09-19 实测：源头损坏，路线关闭）**：
- GitHub 资产直连常超时 → gh-proxy 镜像回落可行，但**镜像的
  content-length 不可信**且大文件偶发传输损坏——下载校验必须用 GitHub
  API 的 authoritative size + sha256 digest（`tools/derive_from_zsbai.py`
  已内置，可复用于未来其他归档源）
- **老线资产系统性源头损坏**：4.1.9.26/.27/.31/.57、4.1.10.24、
  4.1.11.51、4.1.12.53 抽样全部同签名失败（sha256 与 GitHub digest
  完全一致 + XZ 解到 99.9% 处 corrupt——上传时即坏，非传输问题）；
  dmg 尾部 UDIF footer 落在损坏段，无挂载路径。4.1.13+ 时代资产正常
  （④ 轮 270094/97 实证）。**4.1.9-4.1.12 构建的隔离条目回填源就此
  确认为永久缺口**（此前是无据推定，现在是 digest 级实证）
- tag→build 映射探测框架保留（`.wxkeep-tagmap.json` 约定），未来若
  出现第三方存档可续用

**全家族回捞 SOP（㉚ 沉淀）**：`python3 tools/derive_build_from_cdn.py
--build <B> --dotted <ver> [--new-build] [--prune-dmg]`（dmg→thin 抽取→配方
locate→guard→keeptip→update→隔离回填，产出 var/staging）→
`python3 tools/verify_staging.py --build <B>`（按 target 分组的引擎级往返，
六组）→ `python3 tools/merge_staging.py`（合入 config.json，既有条目优先）
→ gen_matrix / sign_manifest / swift test。磁盘紧张时 --prune-dmg（只留
thin 切片；verify_derivations 已支持 lipo 现场合成 fat）。

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

- **构建抖动两形态（macOS 27 + Swift 6.4 连发 `swift test`）**：①
  TestingMacros「plugin not found → Build failed」（既有）；②
  `nProcPluginServer … error: fatalError`（2026-10-17 新见，可连撞 5 次耗尽
  重试）。共同特征 = 输出无 ✘ 测试失败行 + Build failed——**重跑即过**，
  verify_staging 已内置 4 档重试 + 2s 冷却；组级失败先整轮重跑再判真红。

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
- **fat 装机件上 VA ≠ fat 文件偏移**（2026-09-20 ㉞ 实证）：arm64 切片在
  fat 容器 0xae0c000 起，任何「按 VA 读指令/字节」的反解必须经 MachImage
  切片（段表换算）——CLI verify 的 arm64 谓词反解曾直接拿 fat 原始字节
  按 VA 索引，装机形态必反解失败（真 270100 fat：旧路径读 0x834802c1 非
  BL；切片路径读 0x97ee4997 = BL → 0x47575FC 与 ㉝ 地面真值吻合）。
  规则：**新代码涉及 VA 定位一律 `MachImage(file:arch:)` 入，禁止裸
  `Data(contentsOf:)` + 整数当偏移**（thin 工件上两者同值，掩盖了装机
  fat 上的病——thin 测过不等于 fat 测过，与「thin 与 fat 都要查」同源）。
- **受限 entitlement 对 ad-hoc 重签无效**（2026-09-21 ㉟ 实证）：
  `com.apple.security.cs.allow-unsigned-executable-memory` 等在 macOS 15
  是 restricted entitlement——无 provisioning 的 ad-hoc 签名带不上
  （CI runner 上 SIP 关闭 + entitlement 重签后 worker probe 仍 exit 126，
  两个镜像日各一轮）。执行动态代码的正路 = **MAP_JIT +
  `pthread_jit_write_protect_np` 包夹**（映射后放开写、执行前锁写；
  非 hardened 进程免任何 entitlement）。推论：worker 报「映射被拒」
  ≠ 需要整机 AMFI relaxed——先看本进程走的是哪条通道。
- **手汇编夹具也要守 PCS**（2026-09-21 ㉟ arm64 首跑实证）：arm64 mini
  夹具把参数存 x8（caller-saved）跨 `strlen` 调存活——libc 改写 x8 后
  谓词四探针全 false（无崩溃，纯静默走错分支）。x64 孪生用 rbx
  （callee-saved）所以从未暴露。规则：**夹具里跨 call 的活值必须放
  callee-saved 寄存器（x19-x28，序言 stp 保存）**；「编码层解码测试
  过了」≠「执行对了」——ABI 层缺陷只有真执行才暴露。
- **执行门解锁的首次运行是新缺陷高发点**（2026-09-21）：x64 镜像
  测试在 arm64 host 上的 SIGILL、x8 caller-saved 问题，都是 MAP_JIT
  让探针转阳后立刻现形——此前「skip 掩盖从未跑过」。教训：**skip 门
  转换（环境变化/门逻辑修改）后，被门挡住的测试要当作新代码对待**，
  首轮全绿之前不宣布收口。

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
- ~~**Shell.run 未读 terminationReason**~~ **已修（2026-09-22 ㊶ 轮）**：四信号
  实测（SIGKILL/SIGILL/SIGSEGV/SIGBUS）当前 Foundation 全部返回**裸信号号**
  （9/4/11/7 + uncaughtSignal）——早年「SIGILL=132」的 128+n 观测已不成立，
  Verifier 旧的 `status > 128` / `status == 137` 分支在直 exec 拓扑下不可达，
  AMFI/taskgated 的 SIGKILL 被误报成「函数摸了未建模状态」。现 Result 携带
  `signalled`（terminationReason 判读），`Verifier.interpretWorkerExit` 按矩阵
  判读（SIGKILL=环境击杀 / 126=mmap 拒绝 / 2/3=spec 越界 / SIGSEGV 族=真
  crash），退出语义有实测回归锁（shellSignalDeath + 矩阵单测）。
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

## 270099 x64 撤回链与消息管道地图（2026-09-18 凌晨，drive17-22 轮；工具 tools/xref_x64.py）

269602 全链在 270099 的重定位（同构不变，地址全漂移）：

```
isRevokemsg 0x4E8D440（9 真调用者；keeptip 态序言 554889e553504889fb = 地面真值）
isType10000 0x4E8D430（cmp [rdi+8],0x2710; sete al; ret——紧贴 isRevokemsg 之前）
解析函数 [0x537DB40..0x537EFA0)：newmsgid→[this+0x1C8] 存储点 0x537E39D（keeptip v1 位点）
wrapper [0x537D910..0x537DB40)：解析函数唯一调用者（vtable 派发，拓扑同 269602 0x50A5120）
状态写 [0x355AA90..0x355AF60)：mov [rdx+0x118],9 @0x355AB00 —— 全镜像唯一
  （269602 0x32E73A0 双子；调用方 0x351CC8F / 0x355B42D）
  （㉘ 实弹更正：该函数实为 UpdateCancelUploadMessageStatus，与撤回无关——
  本图时代把它标成「M-R4 状态写」系误判，撤回状态机见 ㉘：share_card
  handler 0x3444b40 的 cmp [msg+0x118],2 分派）
storage 解析器 [0x3952D50..0x3952DE0)："_b13e0758" 串@0x91AE9FC（__TEXT,__const）
  ← 异步撤回任务体 [0x3951040..0x3951EA0)
消息管道（decrypt_strings 270099 全量 120 串）：
  system_message_handler 0x3449100 / 0x344baa0（vtable 派发）
  text_message_handler 0x3453900 / 0x3459270
  emoticon_message_handler 0x33a61c0 家族 ×5；share_card_message_handler 0x3443e20 家族
  mac_message_storate_impl ×7（0x3a01fb0..0x3a15700）
  base_msg_data_producer 0x4db8f20 / 0x4db9ff0
23 处 ==0x2710 比较；[0x3DC9250..0x3DCD490) 兼具 type@[+0xC]==10000 + isRevokemsg 调用
```

堆内 tip 文本四种容器（drive19-21 全堆扫描实证，needle="撤回了一条消息"×42）：
protobuf 同步批缓冲 / 会话预览记录（wxid+文本连写）/ DB 页缓存（紧邻
`dialogue_id INTEGER` schema）/ UI 气泡模型（`"昵称" 撤回了一条消息\0` +
头像 URL 的 NUL 结尾 C 串三连）。

### 本轮方法论教训（防重蹈，drive17-21 实证）

- **解密循环 site ≠ 热路径**：producer/storage/syshandler 的 xlog site 断点在
  启动+登录+空闲全程零命中——符号恢复定位用可以，当断点用不行
- **SBProcess.Continue() 在无停止事件时阻塞**：空闲等待必须 listener+
  WaitForEvent 模式（drive.py 模式）；带时限的循环若先 Continue 后查时间，
  时限永远不触发（drive18 卡死实证）
- **SSO 长串反查语义**：ptr 指向串首（含昵称前缀），needle 命中在串中部——
  指针值精确反查必然失配；必须按 `ptr ≤ needle < ptr+size` 区间验证
- **本版 lldb Python API 缺口**：无 GetMemoryRegionAtIndex、无
  SBMemoryRegionList 暴露；区域枚举用 `memory region` 命令逐段解析
  （解析 `[0xbegin-0xend) perm name` 行，addr=end 前进）
- **ULEB128 经典字节序坑**（LC_FUNCTION_STARTS 解析）：`cur=(cur<<7)|low7`
  是反的；正确 `cur |= low7 << shift; shift += 7`。症状：函数边界大量非序言、
  地址越出 __text
- **E8 扫描对齐验证的正确写法**：从 site-k 起点反汇编的缓冲必须**延伸越过
  site**（如 site+16），否则 capstone 永远解不出 site 处指令、全部误拒
  （drive17 轮 9 个真调用者被误报 0 的根因）
- 全堆扫描性能：1.1GB 经 ReadMemory 1MB 分块 ≈ 4-6 分钟/遍（可用）；
  WeChat 空闲堆 ~950MB/520 区
- 后台 lldb 仍必须托管后台任务（`&` 随 shell 退出被杀——再次实证）
- **附加会话杀 lldb 的后果不确定**：多数情况微信被连带杀；偶尔存活——
  收尾后必须 pgrep 验证微信状态并按需拉起
- URL scheme `weixin://dl/chat?wxid=` 未证实能开聊天窗（无障碍受限无法确认），
  但打开后有会话物化迹象（堆内出现该账号体系 tip 串）——不可依赖为重渲染触发器

## 270099 x64 撤回活体链（2026-09-18 drive22 实捕，真实对方撤回）

全部路径汇于 wrapper [0x537d910..0x537db40)（parse 唯一调用者）：
到达解析（sysmsg 处理器 [0x4b3aee0..0x4b3db20) → 0x3559430 → 0x530ca60 →
0x530e0f0 → wrapper）、revoke_manager 二次解析（0x35594b0 → [0x394ae30..)
→ wrapper）、历史批扫（0x5cda0e2 → [0x364ee50..) → [0x3611fa0..) →
[0x3664510..) → 同一 0x530e0f0 漏斗）、异步任务体 [0x3951040..0x3951ea0)
（→ [0x5037ef0..] → tiny [0x538e690..] → isRevokemsg）。
- isRevokemsg 40+ 活体调用全部收到 "revokemsg" 字面类型串——**不是内容谓词**
- keeptip v1 活体：post-store newmsgid=0 ✓；status-write 零命中
  （㉘ 更正：0x355AB00 本就不在撤回路径上——「查找落空→不达」的旧解释
  不成立，零命中的真因是函数与撤回无关；v1 行为模型仍由消息保留实证支撑）
- M-R4 活体捕获目标已随 ㉘ 更正为撤回状态机真宿主（share_card handler
  0x3444b40 @270100 的 cmp [msg+0x118],2 分派与 3421bb0 完成回调）——
  「无 keeptip 态重跑 drive22 即可命中 status-write」的旧建议作废
- 教训补充：带时限的驱动循环里 Continue() 在安静期永久阻塞——时限判断必须
  在 Continue 之前或用事件超时驱动（drive22 第二次踩坑，d22_run2_full.log
  会话即如此结束）

## 第四轮审查（2026-09-18，工具链全量审计）

范围 `tools/` 15 个主脚本逐文件精读 + 引擎源码/CI 交叉验证，修复 7 个真实
缺陷（含修复过程中新发现的 3 个）、8 处小问题，并新增 `tools/machutil.py`
统一 Mach-O 解析口径（VA→offset 一律段表、function_starts 基址一律
`__TEXT.vmaddr`）。**完整清单、复现与验证记录见 [TOOLS-AUDIT.md](TOOLS-AUDIT.md)。**
要点：

- backfill_expected.py 的 XZ 自删 + 成功路径 finally 崩溃（每日 CI 遇 XZ
  asset 必炸）——两处同族，一并修掉，单坏归档改为跳过不中止
- push-to-github.sh 的 pipefail SSH 死分支；amfi_sip_probe.sh 的
  verdict.json 非法 JSON（RUNS 路径）
- contribute_expected.py 固定 8 字节回填在 9/12 字节 asm 条目上 restore
  残留补丁尾巴（restore 是原样写回 expected[0]，不是前缀比较）
- **xref_x64.py 的 xrefs 子命令从未工作过**（字节模式写反，实测 0 命中），
  已修正并在系统 dylib 上端到端验证
- **decrypt_strings.py 的函数基址偏大**（第一个 section addr ≠
  `__TEXT.vmaddr`）——libsystem_kernel nm 1566/1566 交叉验证后修正；
  历史 decrypted_strings.json 的 func 值需重跑刷新
- 第三轮的两个「观察未修」本轮关账：SOURCES_PRI 位置（B4）；ci.yml 的
  `versions || true` 维持原判（有意的冒烟）

## 工件目录惯例（2026-09-18 定）

**重要文件一律放仓库 `var/`，不写 `/tmp`。** 动因：`/tmp/wxarm/d22_run2_full.log`
（drive22 五断点全链捕获，ROADMAP ⑦ 的原始证据）已被系统清掉、无法找回——
研究工件随会话蒸发。

- `var/wxarm/`：dyntrace 实弹日志（d23–d26 已迁入）、对象转储 .bin、
  lipo 抽取的架构 slice（`xref_x64.py` 的输入）
- `var/amfi_probe/`：AMFI 实证取证（verdict.json / doctor 快照 / .ips）
- `var/` 已进 .gitignore：日志含真实昵称、wxid、消息内容等隐私，**绝不入库**；
  工具脚本（drive*.py / xref_x64.py / amfi_sip_probe.sh）默认输出已改为
  按 `__file__` 相对仓库根解析，无需手动建目录
- `/tmp` 只放即弃垃圾（一次性验证程序等）；`var/uuid_matches_bug_proof.c`
  是 uuid 恒假 bug 的独立复现证明（结论已入 ROADMAP ⑨ + 回归测试，仅存档）
- CI runner 上的 `/tmp` 不受此限（runner 本身即一次性）
- **存档副本补丁实验后必须还原**（2026-09-19 教训）：`var/wxarm/` 的
  dylib 存档跑过 patch/restore 实验后若不还原，就是「脏工件」——
  verify_derivations/derive_runtime_hooks 在补丁态字节上会静默失败
  （270100_fat 曾带全套补丁快档导致 2/5 FAIL 两个会话无人察觉）。
  会话收尾清单：对实验过的存档跑 restore 或从 var/cdn 的 dmg 重提一份。
  **thin 与 fat 都要查**（㉛ 轮教训：270100_fat ㉗ 已替换为 CDN 原版，
  但同名的 `_arm64.dylib` thin 仍是 ⑪⑫ 实验的补丁残留——verify 用 fat
  掩盖了 thin 的脏；派生新条目前对 thin 做 pristine 抽查
  （revoke 位点读 expected[0]）可一击检出。工具：
  按 `expected[0]` 全位点扫描的审计循环，见 derive_from_zsbai.audit_build）

## 守卫位点/keeptip call 漂移链（全量，2026-09-19 ㉚ 补全 4.1.13 线）

守卫（parse 内 test al,al; je 位点，expected `84C00F84????????`）：
269573:5062609 → 269574:5063c29 → 269575:5062a69 → 269576:5063dc9 →
269577:50c5c59 → 269578:50c5c99 → 269579:50c5c79 ‖（.12-.49 CDN 缺口，
269602:50a5639）‖ 269618:50f1019 → 269619:50f8079 → 269620:50f4d69 →
269621:50f4e19 → 269622:5116229 → 269624:512a499 → 269625:5129f49 →
269626:512a0d9 → 269627:512b909 → 269628:512c119 → 269629:512c139 →
269630:512c7f9 → 269631:512ca09 → 269632:512c9e9 → 270084:5368f49 →
270085:536f2b9 → 270086:53702e9 →（.7 无归档）270088:53708d9 →
270089:5372369 → 270090:5374e69 → … → 270100:537dfb9
（连续段内单调爬升；跨 .11→.34 缺口有一次代码重排，非单调；269632
对 269631 微降 0x20 属段内正常波动）。

keeptip store（parse+偏移处 E8 call + `488983C8010000`，asm 家族恒定，
call rel32 按时代分五变体）：.5-.8=`E81E85E9FF`、.9-.11=`E8DE67E9FF`、
.50-.54=`E8BE67E9FF`、.56-.64=`E81E66E9FF`、4.1.15=`E83E4BE9FF`——
expected 必须按实读字节入库（㉚ 轮 18 构建 + ㉛ 轮 6 构建全部如此）。

## 证据化审计工具（2026-10-20 72 轮沉淀；新构建/发版前可复跑）

- **地面真值全扫** `python3 tools/sweep_ground_truth.py --otool-sample 8`：
  var/wxarm 现存全部切片 × catalog 全条目读回比对（ExpectedPattern 通配/
  掩码语义一比一；归一化条目按「∈expected 集」分层断言）。新构建入目后
  必跑——失配=数据级 P0。证据落 var/logs/l1-ground-truth-sweep-*.txt。
- **可逆性穷举** `python3 tools/verify_reversibility.py`：真 Patcher/真切片
  lipo 合 fat → {silent, keeptip, --only 各子集, 链式切换} 全状态迁移，每态
  「位点字节∈合法集」+ restore 后整文件 sha256 == pristine。改 Engine/
  Patcher/restoreAsm 语义后必跑（比位点比对强的哈希预言）。
- **解析面模糊** `bash tools/fuzz/run_fuzz.sh 200000`：runtime.m 测试缝
  （ASan+UBSan 确定性驱动 + 20 万次随机）+ Swift 侧 FuzzParseSurfaces
  （Data(hex:)/ExpectedPattern/MachOInjector/MachImage 随机畸形注入）。
  runtime.m 或解析面改动后必跑。CLT 无 libFuzzer 运行时——runtime_random.c
  为等价自研实现（种子固定可复现）。
- **变异测试** `python3 tools/mutation_test.py`：20 个安全关键单行变异 ×
  全量测套，杀灭率 ≥90% 验收。新增安全防线（新守卫/新门）时补对应变异行。
- **确定性 oracle（L6）** `python3 tools/verify_determinism.py`：真切片
  双副本独立运行 → patch 输出 sha256 恒等（silent+keeptip 双路径）+ restore
  回 pristine；附带 codesign ad-hoc 确定性实证（informational——实证为
  每次相异 1 字节，全管线 sha 恒等不作标准）。改 Engine/Patcher 写入语义
  后必跑。证据落 var/logs/l6-determinism-*.txt。
- **启动浸泡门槛** `python3 tools/launch_soak.py [--plan]`：隔离副本全链
  patch → 浸泡 → 存活断言 → DiagnosticReports(WeChat .ips) 零新增。
  --plan（不启 GUI）可在 CI/无人值守跑；真 soak 弹登录窗属用户触发。
  发版前建议在真机上跑一次真 soak。
- **崩溃一致性 journal（WAL）**：CLI patch/restore 事务边界 = `PatchJournal`
  begin/complete（userData 目录 patch.journal.json）。改 CLI 编排/Engine
  写入路径后：确认 (a) 成功事务清 journal (b) 伪造中断（手写 journal JSON，
  app 指向假 app）doctor 给对指引 (c) restore 收敛清除。CLI e2e 模板见
  ROADMAP 73 轮第 1 条。
- **openssl 独立验签** `bash tools/verify_manifest_openssl.sh`：CryptoKit 之外
  的 Ed25519 验证（手构 SPKI DER + pkeyutl + shasum），每次重签 manifest 后
  顺手跑一次防共因。
- 本机 macOS 27 CLT 的 TestingMacros 插件间歇楔死：swift test 加
  `-Xswiftc -load-plugin-library -Xswiftc $CLT/…/libTestingMacros.dylib`
  显式装载即绕过（tools/fuzz/run_fuzz.sh 内置；清缓存只偶发缓解）。

## 270135 x64 撤回链地图与 lambda 层收口（2026-10-24 74 轮；v2 静态落点定案）

工具链：machutil + capstone 全量反汇编（`var/wxarm/vtable_slots_disasm.txt`、
`var/wxarm/hand_disasm_key4.txt`）+ `objdump --macho --indirect-symbols`（__stubs 桩
→ 导入符号名）+ 滚动密钥日志串定点解码（`var/wxarm/decode_revoke_logs.py`，与
tools/decrypt_strings.py 同族 i%20 算法交叉验证一致）+ Ghidra headless 批量转储
（B/C 两批 DumpTargets 在飞，落地 `var/wxarm/decomp_targets.c` / `decomp_targets2.c`；
LC_FUNCTION_STARTS 种子 390413 函数；本节结论全部来自 capstone/objdump/解码器
的手工验证，伪代码落地后只做参数级增量复核）。关键反证复扫：isRevokemsg 0x5008960 全文
E8 rel32 扫描 = 9 调用者（0x368bb98/0x3a72fc3/0x3a7462c/0x3f36806/0x4830922/
0x4cb4f7a/0x5503a14/0x5513a19/0x5514291）；"newmsgid" movabs 字面量 4 处
（0x36519f4/0x3654337/0x3654f8e/0x5503f3b，前缀 48b8 复核）。

```
宿主批分派器 0x4cb47e0（isRevokemsg→0x3699730 分派；同窗前台台账 var/HANDOFF-20261024.md §二）
  → 0x36997b0(0x650) → thunk 0x365f780 → 0x3a91130 异步任务体
0x3a91130（0xe60）= 任务「CoCheckRevokeMessageListReEditStatus」（任务名串解密实证；
  同函数日志 'system message list count:%_, revoke'）
  Phase3 逐 DB 命中行：FUN_036d1290(&vec,&str) 查库命中谓词（行字段比较器，
  仅调 0x56d40/0x15040 微助手）→ FUN_05546740 二次门 → memcpy 0x278 模板
  (DAT_0938d920) → FUN_010891f0 补行字段 → dynamic_cast(共享 local_298) →
  0x88 shared 控制块 functor（vtable @0xa8c4bb0，0x3aa5430 捕获批内 XML 串）→
  FUN_055132f0(msgObj,&shared{functor}) 内存层内容改写
  → FUN_05546770(row)×2 → timeMs=createTime×1000
  → FUN_05495180(&tip) 提取 tip 内容（**函数体首指令即 type-10000 过滤**：
  `cmp dword [rdi+0xc],0x2710`，走 10000 分支取串——新配方锚点）
  → FUN_03a90d60(ctx, content, ?, timeMs, &shared{msgObj}) 投递延迟任务
  → FUN_00b95600(&tip) 销毁模板副本（tip 仅提取内容后即弃）
0x55132f0（0x6f0）= **撤回内容构造/原位改写（纯内存层，全身无 DB 调用——
  无 0x7102860/0x7102b50/0x70e55a0）**：内含 0x5512dd0×3 `<a href="` HTML
  链接构造（立即数 0x3d6665726820613c = "<a href=" 实证）——即 269602 时代
  0x50B4F10（提示文本构造 + xwechat://reedit 五分钟重编辑链接）的同源体；
  对 functor 的调用语义（捕获载荷消费方式）待 decomp_targets.c 伪代码定槽
0x3a90d60（0x254）= 延迟任务投递器：0x48B functor（vtable @0xa8c4ae0）+
  任务名「RemoveOutOfDataRevokeItemAsync」（解密实证）→ FUN_04c3de40 执行队列
```

**functor vtable A @0xa8c4ae0 七槽全解**（chained-fixup 槽值 → 实际 VA 取低 32 位；
槽语义判定全部有指令级依据）：

| 槽 | 函数 | 语义 | 依据 |
|---|---|---|---|
| [0] | 0x3aa2e30 | complete dtor | 调 `__shared_weak_count::__release_weak`（桩 0x7bd5d1e） |
| [1] | 0x3aa2ea0 | deleting dtor | 同上 + `operator delete`（0x7bd5f16） |
| [2] | 0x3aa2f20 | clone() | `operator new(0x48)` + vtable 写回 + 逐字段拷贝 + `lock inc [rax+8]` |
| [3] | 0x3aa2fc0 | clone(void*) | 同拷贝入 caller 缓冲（rsi），不分配 |
| [4] | 0x3aa3030 | destroy() | 释放 shared + 长串释放，不 free this |
| [5] | 0x3aa3090 | destroy_deallocate() | 同上 + `operator delete(this,0x48)` |
| [6] | **0x3aa3100** | **operator()（invoke 体）** | 唯一业务函数（0x14b0） |

= libc++ `std::__function::__func` 标准布局（dtor 对 + clone 对 + destroy 对 +
operator()）。**v2 逐层的「lambda 体」就此定址：0x3aa3100。**

**0x3aa3100 invoke 体结构**（指令级通读 + 快路伪代码 -noanalysis 复核）：构造
0x60 存储上下文 functor（vtable @0xa8c4b50，0x3aaf540 拷贝捕获）→ 注册表
（[mgr+0x130]+0x50）查/插（0x3aa4650 命中取 shared_ptr / 0x3aa4870 未命中插入；
命中走 `is exist` 日志后直达收尾）→ 0x3aaf820(task, &msgShared) 绑定捕获消息 →
0x3aafad0(&out, task) = **RemoveRevokeItemTask 执行门**（单元名
`remove_revoke_item_task.cc`、日志 `RemoveRevokeItemTask:%_, has execute just
skip` 解密实证）：已执行则仅兑现 bool；未执行则标记 task[+0x40]=1 并
**0x3aafb96 `call 0x7102b50` 启动任务工作**（0x7102b50=协程 resume/await 入口，
真身协程体另启）→ 之后 0x3aa397b/0x3aa3a35 的 `call 0x7102860` 是**协程 await
基建**（0x7102860 内含 zlog/await/coroutine.cpp 明文基建串 + Fatal error 抛出，
非语句执行器）→ 0x25a8a10 取 awaitable bool 结果 → 0x3aa8800（带
[mgr+0x110]/[r14+0x20]/rbx）= **存储操作闭包构建器**（单元名
`message_revoke_storage_impl.cc` 解密实证）：0x68 闭包捕获 {awaitable, 16B
任务字段(msgid 类), param_3, string}，invoke 体 = **0x3aab070** →
**0x3aab0da `call 0x4196130`(msgid-shared, u64, string) → bool** → 0x70e55a0
兑现 → await#2 结果 → success/failed 日志（行号 0x5a3/0x5a7）→ 0x3aaffd0 收口
→ 0x3a92100([mgr+0x98],…) 通知 → 注册表复查 + 0xa63b20 除名（行号 0x5ad
`task has removed`）。

**0x4196130（0x520B）= 存储原语（链上最后一个未知）**：重度调用 0x5e/0x5f 区
ORM 语句 API 族（0x5f102b0/0x5f417c0/0x5f11f10×n/0x5f413c0/0x5e66810…），
无明文 SQL、无可解密串（全量 decrypt_strings 119 串已穷尽）。语句级语义
（删原消息行 / 删撤回条目行 / UPDATE）静态不可判读——出路两条：B/C 全量
伪代码认领 WCDB vtable，或 P0 A/B 行为裁决（后者本是终判）。

**行为定性（双层模型，参数级复核定案）**：
① **内存层立即改写**：0x3a91130 Phase3 查库命中后立刻 0x55132f0 把撤回内容
  （含 reedit HTML 链接）写入内存消息对象（0x50B4F10 同源体）；
② **DB/协程层延迟强制**：RemoveRevokeItemTask（dely_time_ms=createTime×1000）
  经执行门 0x3aafad0 启动（0x3aafb96），存储动作经 0x3aa8800 闭包落到
  0x4196130。v1 清零 newmsgid 使 Phase3 查空 → 两层全静默，与「私聊提示
  随流保留 / 群聊提示消失」行为模型完全自洽。

**v2 干预点（指令级地址，语义终判= P0 A/B）**：
- ~~0x3aa397b/0x3aa3a35 的 `call 0x7102860`~~ **无效候选**——那是 await 调用点，
  工作在 await 之前已由 0x3aafb96 启动；
- 候选1：**0x3aafb96**（0x3aafad0 内任务启动 `call 0x7102b50`）——NOP 后任务
  不启动，但 bool 永不兑现（await 挂起语义需 P1 设计评估）；
- 候选2：**0x3aab0da**（闭包 invoke 内 `call 0x4196130`）——NOP 后 eax 残留
  （bool 结果垃圾），P1 需「替换为良性等值操作」而非纯 NOP（BetterWX 的
  SrvID+=1 同型思路）；
- 候选3：0x3aa8800 调用点（0x3aa3100 内）——闭包不构建，await#2 语义同需评估；
- 0x7102860/0x7102b50 本体为协程基建（多链路共用），**不可**动。
可行性终判仍需 V2-PLAN P0 真机 A/B（drive35/36 双路径模型：原生撤回疑走
WCDB/存储层直写、本链是防护态重扫路径——未被本轮静态推翻）。

**源码路径解密**（0x3a90d60 内，构建机泄漏）：
`/Users/xwechat/agent/workspace/xwechat_mac_release_02/kernel/core/manager/message/revoke/message_revoke_manager.cc`
—— 与 269602/270099 时代同名单元，家族跨构建稳定。

## 270135 撤回链地图·终版判读（2026-10-24 深夜：B 批全量伪代码落地 + 快路存储族，模型升级）

> 证据：var/wxarm/decomp_targets.c（B 批 16 函数全量分析伪代码，20:59 落地）、
> decomp_storage.c（0x4196130+ORM 族快路伪代码）、E8 全扫、种子归属。
> 本节为最终口径，覆盖上文「干预点修订」等中间稿。

### 指令级新事实

1. **0x55132f0（载荷附着器）全二进制唯一调用者**（E8 rel32 全扫）：
   0x3a91b69 ∈ 0x3a91130（CoCheckRevokeMessageListReEditStatus）Phase3。
   撤回显示机制整体只挂这一条链。
2. **0x55132f0 语义落锤**（全量伪代码）：撤回载荷 shared 写消息对象 **+0x278**；
   "reeditrevoke"（明文重建 0x6572746964656572/0x656b6f76）标记入 **+0x248** 列表
   （0x78 步进）；`xwechat`+`://`+`reedit` 深链 + `<a href=` HTML 写 **+0x1D0**
   并串赋值拷 **+0x218**——与 269602 时代 0x50B4F10「写入 +0x1D0 和 +0x218」
   逐字吻合，同源体实锤，且对象字段偏移跨版本稳定（配方锚点）。
3. **0x55139e0 = `GetRevokeMessage`**（函数名明文 0xaf70a10，行号 0x440）：
   消息对象带 +0x278 载荷 && isRevokemsg(+0x1a8) && 时间窗(+0x288) → 从第二张
   0x278 模板（**DAT_09581de0**）构造 tip 消息，字段全取自载荷——
   **群聊 tip = 渲染期从载荷生成，不是 DB 新行**。0x5514280 = 同门的 bool 谓词。
4. **0x55142d0 = revokemsg XML 序列化器**（明文键 "version"/"1.0"/"sysmsg"/
   "type"/"revokemsg"）——撤回 XML 写侧（自发撤回请求方向）。
5. **0x4196130 操作 `revokemessage` 表**（表名明文内联 @0x4196416）：
   构建两条 ORM 语句（绑 param_2=u64、param_3=string）→ 0x5f393c0(db,
   "revokemessage", …) 出行列表。延迟任务管理的是**撤回条目行**。
6. **isRevokemsg(0x5008960) 9 调用者全归属**：revoke_manager 家族 3
   （0x368ba70/0x3a729b0/0x3a74030）+ 批分派器族 3（0x3f345b0/0x48307e0/
   0x4cb47e0）+ 存储读侧 2（0x55139e0/0x5514280）+ parse 1（0x5503730，
   catalog guard 同函数）。

### 模型升级（v2 决策级）

**macOS 4.x 的撤回持久层 = `revokemessage` 表；全链不存在「原消息行 DELETE」。**
撤回的显示效果 = revokemessage 行（DB 持久）+ +0x278 载荷（内存，唯一附着点
0x55132f0）+ 渲染期 tip（GetRevokeMessage）。Windows BetterWX「call DeleteMessage」
前提在本链**没有对应物**——drive35/36 的「存储层直写」即 revokemessage 行插入
（同步路径、本链之前）。

三层时序（静态实证）：
```
同步层收到撤回事件 → revokemessage 行插入（写者待定位 = 下一定位目标 P1）
  → 批分派 0x4cb47e0 → 0x3a91130 CoCheckRevokeMessageListReEditStatus
    Phase3: 按 key 查 revokemessage 行（0x36d1290 命中）→ 0x55132f0 附着载荷
    （+0x278/+0x248/+0x1D0/+0x218）→ 投递 RemoveRevokeItemTask（延迟）
渲染: 0x55139e0 GetRevokeMessage(+0x278 载荷) → 模板 DAT_09581de0 → tip 显示
清理: RemoveRevokeItemTask(0x3aa3100) → 0x4196130 操作 revokemessage 表
  → 通知 → 注册表除名
```

v1 自洽复验：newmsgid=0 → 解析层断链 → revokemessage 行不可达/不匹配 →
Phase3 查空 → 无载荷 → 无群聊 tip + 消息不受影响；私聊 tip = 服务器 in-band
type-10000，独立于本链。✓

**v2 落点校准**（替代上文中间稿候选）：
- 首选定位目标 = **revokemessage 行插入点**（同步路径写者；revoke_manager 家族
  0x3a7xxxx/0x3a8xxxx 或存储实现 AddRevokeMessage 型函数——待定点）；
- 「保消息」在 macOS 上= 让载荷/行不生效或让渲染门(0x5514280/0x55139e0)走
  「非撤回」分支，而非阻止行删除；
- BetterWX 规则2（DB 放行自造 ID）在 macOS 无对应物（tip 不入库）——V2-PLAN
  第 3 点相应作废待修；
- 0x4196130/清理链是消费侧，NOP 只影响清理不影响撤回效果。

### 75 轮增补（2026-10-25：行插入点定案 + 存储家族全图——Windows spike 反哺）

> 完整 spike 报告（Windows 4.1.15.56 官方原版独立推导 + 双平台对位表）
> 见 docs/WINDOWS-SPIKE.md。本节只记 macOS 侧结论。

1. **表名构造者全图（movabs "revokeme" 扫描，5 函数）**：macOS 表名无明文
   （movabs 立即数惰性缓存，`48 b8/bf`+`revokeme` 模式扫描）——
   0x4190130（表注册器）/0x4195490/0x4195ca0/0x4196130/0x4196650，
   与 Windows 五函数家族（.rdata 明文 xref）一一对应。
2. **四 lambda invoke→四存储操作**（rel32 扫描；winre.py 首版 capstone
   线性扫描有静默截断缺陷已修——「零调用者」结论曾假阴性；macOS 侧
   tools/xref_x64.py 核查后本就正确）：
   0x3aaa450→0x4195490 / 0x3aaae70→0x4195ca0 / 0x3aab070→0x4196130 /
   0x3aab2a0→0x4196650；ctor = 0x3aa8370/0x3aa8590/0x3aa8800/0x3aa8a90。
3. **行插入点定案（P1 前最后定位目标关账）**：
   `0x3a7a040（impl，revoke_manager 0x3a7xxxx 区）→ ctor 0x3aa8590 →
   invoke 0x3aaae70 → 0x4195ca0（INSERT 单行）`。
   伪代码四段结构与 Windows 孪生 0x182380b60 逐段同构（四谓词门→建记录
   （FUN_05546730）→异步插入→await FUN_07102860→门 FUN_025a8a10→失败 xlog
   **行号 0x589 双平台同值**=同一源码函数；日志串现场物化 "AddR"+"Data"
   =AddRevokeData 命名）。**谓词门 FUN_05006ff0 即 tip 构造器 0x55132f0 内
   self 分型函数**——撤回链与 tip 链在类型判定处交汇。证据
   var/wxarm/decomp_mac_insertimpl.c。
4. **存储语义对位表（Windows 伪代码定性反哺 macOS）**：
   | 操作 | macOS | Windows（伪代码实证） |
   |---|---|---|
   | 表注册 | 0x4190130 | 0x183224200（另发现 revokebatchmessage 第二表） |
   | SELECT | 0x4195490（0x3a91130 CoCheck Phase3 经 0x3aa8370） | 0x183229fb0 |
   | INSERT | 0x4195ca0 | 0x18322a970 |
   | 写（对位推断） | 0x4196130（RemoveRevokeItemTask 链，语句级=清理族） | 0x18322b240=DELETE 过期（cutoff=now−配置，实证） |
   | 写（对位推断） | 0x4196650 | 0x18322ace0=UPDATE 双参（实证） |
   0x4196130 的「两条语句」定案为**清理族写**（非原消息删除——与「全链无
   原消息行 DELETE」自洽）；DELETE/UPDATE 精确对位为链形推断（无双平台
   行号锚），不影响 v2 落点（清理链=消费侧）。
5. **v2 落点新增候选**：插入链四站（impl 谓词门/记录构造 FUN_05546730/
   插入 ctor 调用点 0x3a7a040→0x3aa8590/INSERT 本体）——「铸行内容」类
   干预（如记录字段改写）在此层最干净；真机 A/B 候选清单相应扩编。


### 76 轮增补（2026-10-25：270100 arm64 撤回链地图 + P0 A/B 终审）

> 实验台账 var/ab/EXPERIMENT-20261025.md（T1/T2 结果与 v2 换道三案）。
> 本节登记 arm64 新资产——下轮任何 arm64 侧工作的地址基线。

**方法论**（arm64 无 movabs，x64 锚点法失效）：arm64 编译器把短串常量以
16 字节对齐 SSO 池放 __TEXT,__const（明文："AddRevokeMessage"/"GetRevokeMessage"
/"HandleRevokeFail" 等——各自被所属函数 adrp+ldr 自引用）；全量引用索引 =
var/ab/arm64_index.py（capstone 重同步线性扫描，29M 指令 3 分钟，refs+calls
pickle 复用）；链式行走 + x64 尺寸指纹（arm64 ≈ x64 的 0.9-1.4×）+ Ghidra
快路确认。工具：var/ab/arm64re.py（movz/movk 对 + BL + ADRP 算术扫描）。

**270100 arm64 链全图**（与 x64 图逐段对位）：

```
存储族 5 ops（表名族，地址相邻）：
  0x3a3a0a0 (0x4f8B) SELECT     [x64 0x404bd60 0x620B]
  0x3a3a740 (0xb0B)  INSERT     [x64 0x404c570 0xa0B]
  0x3a3aaa8 (0x428B) DELETE过期 [x64 0x404ca00 0x520B]
  0x3a3aed0 (0x308B) UPDATE     [x64 0x404cf20 0x380B]
  0x3a3b498 (0x1dcB) 第5成员    [x64 0x4046a00 register 族]
invoke 四件套（0x3434xxx 簇）：
  0x343452c (0x320B) select-invoke  [x64 0x396a560]
  0x3434edc (0x1fcB) insert-invoke  [x64 0x396af80]  ← T1 站点 0x3434f30
  0x343516c (0x188B) cleanup-invoke [x64 0x396b180]  ← T3 站点 0x34351c8
  0x34353ac (0x138B) update-invoke  [x64 0x396b3b0]
ctor 簇：0x3432528 sel / 0x343275c ins (0x274B) / …（sel-ctor 唯一调用者
  = CoCheck，x64 不变量保持）
impl：0x3408e7c (0x780B) AddRevokeData  [x64 0x393a0b0 0x7e0B]
  —— 函数体内引用自身名 "AddRevokeMessage" @0x875ac90（16B SSO 池）
CoCheck 任务体：0x341c7c4 (0xbf0B)      [x64 0x39511a0 0xe60B]
  ← T2 站点 0x341cffc（bl attach-ctor）
attach-ctor：0x4bd1930 (0x65cB)         [x64 0x538d890 0x6f0B]
GetRevokeMessage 族：0x4bd1f8c（引用名串 @0x89390d0）
共享 statement-builder：0x342fbe4（insert-invoke 与 CoCheck 共用，同 x64
  0x3965540/0x530e280 关系）
promise 兑现原语：0x64eb294 [x64 0x6f3cb40]
```

**P0 A/B 终审**（详见台账）：T1/T2 双点闭合——本链对原生撤回显示整体
无效（真实身份 = 重新编辑资格记账）。上节「v2 落点新增候选」随之作废；
v2 换道三案见 V2-PLAN P0。x64 侧同轮验证的补丁点（0x396afde/0x3951bd9/
0x396b1ea）保留在案（Intel 面止步 macOS 27 的前提下价值有限）。

### 77 续增补（2026-10-26：函数级身份门数据入库 + 工具正化 + 两处复查修缺陷）

**hook 行函数级身份门数据**（schema 见 docs/RUNTIME-DESIGN「函数级身份门」；
RuntimeConfig.knownHooks 注释有覆盖率全景）：

- 16 行已带 `funcSize`：270100/101/102/131-135 × 双架构——本地 pristine
  切片（var/ab 270100 双架构、var/wxarm 其余）三重校验派生（hook_off 必为
  FUNCTION_STARTS 起点、切片 LC_UUID 与行全同、距离 = 到下一函数起点）。
- **家族值恒定：x64=5216 / arm64=4380**（parse 直挂函数跨构建尺寸稳定）——
  未来新构建派生行若 func_size 偏离该值，先怀疑切错函数再怀疑微信改版。
- 270084-099 十四构建无本地切片（旧 dmg 已按清理策略删除），funcSize 待
  CDN 重派生轮补齐；不带字段 = 门未启用，行为同 77 轮前。
- **CodingKeys 教训（复发第二次）**：Codable 结构新增字段必须写显式
  CodingKeys——Swift 合成键 camelCase（funcSize）与 dylib 侧 snake_case
  （func_size）漂移 = 门静默失效。68 轮 verify_variants 同坑；本轮由
  「funcSize 派生入库」复查抓出，hookRowWireKeysAreSnakeCase 测试锁死。
  **入库即跑一次 wire-format 断言应成为新字段惯例。**

**工具正化**（tools/ 新增 5 件，var/ 原件保留）：arm64re / arm64_index
（CLI：`build <slice> <idx>` / `query <idx> <va>...`，显式路径无隐式缺省）/
winre（--dll 或 WXKEEP_WIN_DLL，缺省 var/win 工件区 4.1.15.56）/
win_profile（更名避让 stdlib profile）/ sign_manifest_openssl（钥型校验后
直接 `-inkey` 原钥，源码不得含 PEM 头字面量——CI 私钥材料门会拦）。
arm64_index 端到端复验：重建索引查询复现 76 轮台账 T2 站点
（0x341cffc: bl caller 0x341c7c4）逐位一致。

**marker 候选序契约**（读/写/清三侧必须同序）：Group 容器 → 微信沙盒容器
legacy（~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application
Support/wxkeep）→ 真实 home legacy。Swift 侧唯一权威 =
RuntimeConfig.markerURLs（readMarkerText/removeAllMarkers）；dylib 侧 =
write_marker_first_writable。改任一侧必须同步另一侧（与 knownHooks 双侧
同步惯例同构）。
