# 同类工具静态分析（2026-09-17，三个样本）

> 纯静态解剖（未执行任何样本）。来源：用户提供的三个压缩包。

## ⛔ PoJie.52 — 不要安装（中间人工具，非纯防撤回）

`inject.sh`（54KB 完整审计）+ `libPoJie.52.dylib` 静态证据：

- **安装根 CA**：`security add-trusted-cert -r trustRoot -k <登录钥匙串>`，内置
  `Www.52PoJie.CN-root-ca.pem`（指纹 7B614CB1…）
- **本地 HTTPS 代理**：`PROXY_PORT=6666`，dylib 内是完整 HTTP/HTTPS 代理实现
  （CONNECT 隧道、Proxy-Agent、proxy-auth 处理）
- **拦截目标**：`channels.weixin.qq.com`（视频号），API 路径 `__vt_channels/…`
  （download/batch/clear/diagnostics），字符串含 `antiRecall`/`channelScript`
  ——其"防撤回"是**视频号动态**的撤回，实现方式=信任根 CA 后对视频号流量做中间人
- 也做常规字节适配（`SUPPORTED_BUILD_DIGESTS` = 22 个切片 SHA-256 白名单 + insert_dylib）

**风险**：信任根 CA 后，该证书可对任意站点的 TLS 流量签名拦截（不限视频号）；
代理与更新通道由作者控制。若曾运行过：`sudo ./inject.sh --uninstall` 并检查
钥匙串中 `Www.52PoJie.CN` 证书与描述文件是否残留。

**可借鉴**（仅工程手法）：切片 SHA-256 白名单作为构建准入——我们已有
archive_index 的哈希数据，可在 doctor 加「未知/被改 dylib」告警（低优先级）。

## ✅ RecallKeeper 1.8.1（吾爱 @wjz941666，arm64，闭源已解剖）

**与 wxkeep 几乎同构的设计**（独立收敛，互相验证了架构正确性）：
- 按构建号目录 + 「目标字节校验」= 我们的 expected 门；同款备份语义
  （含「恢复到旧补丁态 ≠ 原版」的诚实标注）；同款两个 entitlements 键
  （allow-unsigned-executable-memory + disable-library-validation）
- **混合路线实证**：字节补丁负责保留消息；随包 54KB 运行时 dylib 只做
  「本地系统通知」（UNUserNotificationCenter），**明确不含原文**（"不含原文的系统提示"）；
  自发撤回按原逻辑执行
- 54KB dylib 机制：读登录目录判断活跃状态（`…/app_data/login`）+ CFBundleVersion +
  发通知——「撤回事件 → 通知」的触发由字节补丁侧配合完成
- `ReleaseIntegrity.json` + `.sig`：**对发布清单做签名**（供应链防篡改）

**可借鉴**：
1. 发布清单签名——我们 watch-wechat 已自动开 PR，config/signatures 属供应链面，
   可加 CI 签名清单（sha256 + 签名），doctor 校验后消费（中等工作量，真实价值）
2. 登录态门控——v3 运行时组件发通知前先判断登录目录，避免未登录噪音

## ✅ X1a0HeWeChatPlugin v2.9.0（开源 github.com/X1a0He/X1a0HeWeChatPlugin）

- 经典注入：insert_dylib 改 wechat.dylib 的 LC_LOAD_DYLIB + `.original` 备份 + 重签；
  重装 = 先还原再注（幂等）
- **配置存微信自己的偏好域**（`X1a0HeWeChatPlugin_*` 前缀键）：注入库运行时
  CFPreferences 读取——改设置**不用重签微信**（比 fzlzjerry 的独立配置文件更优雅）
- 注入目标选 wechat.dylib 而非主程序（4.x 主程序仅是壳）

**撤回能力是 mac 4.x 注入派的天花板**（README + dylib 字符串实证）：
- 拦截类型极全（语音/表情/图片/视频/文件/名片/小程序/拍一拍/合并转发/引用），**他人+自己**都防
- "撤回消息遮罩"——在**原消息上叠加遮罩**显示 = 聊天内原位标记哪条被撤回
- **撤回内容转发**：撤回前把文字/图片/视频/文件**转发到用户指定目标**（如文件传输助手）
  ——内容保全走"转发旁路"而非"原位保留"，聪明地绕开了删除时机问题
- 自定义提示短语；覆盖 4.1.7.56–4.1.15.10
- **限制：❌ 不支持 Intel、❌ 不支持 MAS 版**（仅 Apple Silicon 原版）

**可借鉴**：v3 运行时组件（若立项）的配置通道直接用微信偏好域 + 前缀键；
"撤回内容转发到文件传输助手"是内容保全的低成本替代方案（无需原位渲染）。

## 汇总：「聊天内保留+标记」的真实格局（修正版）

| 阵营 | 代表 | 聊天内保留 | 原位标记/遮罩 | 群聊 | 内容 |
|---|---|---|---|---|---|
| **注入派**（运行时全控） | 3.x WeChatTweak / 4.x **X1a0He** | ✓ | ✓ 遮罩 | ✓ | ✓ 转发旁路 |
| **字节派·混合** | fzlzjerry / RecallKeeper | 私聊✓ | ✗ | ✗ | 部分/无 |
| **字节派·纯补丁** | 我们 v1 / zengtianli | 私聊✓ | ✗ | ✗ | ✗ |
| **字节派·外科** | BetterWX(Win) / 我们 v2(待做) | ✓ | ✓ 下方提示 | ✓ | — |

注入派做得到是因为运行时全控（拦在删除执行前）；字节派在 4.x 上的群聊/原位问题
即本仓 v2 课题。**差异化的点：X1a0He 明确不支持 Intel**——Intel mac 4.x 上
「字节路线的原位提示」至今空白，这正是 v2（不需要注入、Intel 可用）的价值所在。

## 待办采纳清单（按价值排序）

1. [ ] 发布清单签名（RecallKeeper 模式）：CI 对 config/signatures 出 sha256+签名，
      doctor 消费前校验——配合 auto-PR 的供应链闭环
2. [ ] doctor 加「dylib 切片哈希不在 archive_index」告警（PoJie 白名单思路）
3. [ ] V2-PLAN v3 节：配置通道改微信偏好域前缀键（X1a0He 思路）；通知加登录态门控
      （RecallKeeper 思路）

## 深挖补充（2026-09-17 第二轮：hook 机制核实）

### X1a0He 的真正底牌：SQLCipher 直读微信数据库

反汇编核实（7.3MB dylib，Dobby inline-hook 框架 + SQLCipher 静态链接）：
- **`showDbKeys:`** 选择子 + `{wxid}/{talkerWxid}` 模板 + `contact`/`message` 表名 +
  SQLCipher 全套 PRAGMA 字符串——插件**在进程内直接解密并查询微信的加密消息库**
- 35 个配置键（`interceptOthers*Msg` × 18 / `interceptSelf*Msg` × 17，按消息类型）
  + `configureRecalledMessageBackground`（遮罩）+ 撤回转发（文件大小上限/媒体间隔/目标）
- **这就是它"遮罩+内容转发"能成立的根**：Dobby hook 消息处理入口拿到事件后，
  从解密库里捞原文，再调 `sendTextMessage:` 等把内容转发出去——不依赖撤回 XML
  （XML 里本就没有原文），也不需要在删除前拦截
- UI 文案全部运行时解密（连中文串都无明文，同微信本体混淆手法）
- 注意：进程内持有 db key + 撤回转发 = 高敏感面；开源可审计是唯一信任基础

### 对 wxkeep 的战略启示（重要度排序）

1. **SQLCipher 直读 = v3 运行时组件的"内容"来源**。此前认为"撤回原文只有
   fzlzjerry 式进程内缓存可得"——错：**加密库里原文一直都在**（撤回只是打删除标记/
   移除 UI 引用，库里未必真删）。v3 若做"撤回内容提示"，从库读原文比消息流缓存
   可靠得多（不限本次启动、不限部分构建）。X1a0He 证明进程内拿 key + SQLCipher
   可行。⚠️ 但 wxkeep 是无注入路线——读库要么离线（拿 key 的方式完全不同，
   需独立研究）要么放弃。记录为开放课题。
2. **按消息类型的细粒度开关**（35 键）值得抄：我们的 revoke 是一刀切，加
   `--types text,image,...` 过滤是纯配置层工作。
3. RecallKeeper 客户端二进制内无配方特征字节（配方在服务端/运行时取）——
   其"构建号支持列表"机制与我们等价，无新信息。

### 本轮落地
- 细粒度类型开关：暂缓（v2 语义未定，先不加配置面）
- 文档沉淀：本节

## 2026-09-17 大范围调研（fzlzjerry issues/Docs、linux.do、52pojie）

### 生态全景（2026-09）
| 项目/帖子 | 架构 | 方法 | Intel x64 状态 |
|---|---|---|---|
| fzlzjerry/wechat-antirecall | arm64 验证 | 字节补丁（entry 翻转 + str xzr）+ 运行时自定义提示 | **#55 help-wanted：269574 x64 已 IDA 分析未验证** |
| happykeke (52pojie 2124824) | arm64 验证到 269631 | inject.sh DYLD 注入 | "x64 架构分析了对应位置，但尚未验证" |
| sunnyyoung/WeChatTweak | 注入式 | dylib 注入（3.x 时代方案，4.x 声称支持） | 未验证 4.x Intel |
| X1a0HeWeChatPlugin | arm64 | Dobby 运行时 hook | 未支持 |
| linux.do 1754779/2121933 | x64 帖 | WeChatTweak 思路 x64 适配（4.1.8.27/4.1.9） | 版本特定、无目录化 |
| **本项目 wxkeep** | **x64+arm64** | **纯字节补丁 + expected 门** | **269602 全链真机验证（全生态唯一）** |

### 关键技术情报
1. **fzlzjerry x64 silent 法（#55，269574）**：parseRevokeXML 入口 0x5063940，
   守卫分支 0x5063F87：`0F841A030000`(je) → `E91B03000090`(jmp)——翻转"非撤回
   则跳过删除"分支 = 解析级 silent。**269602 x64 同族位点已定位**：isRevokemsg
   (0x4BC5940) 的 9 个调用者中 8 个呈 `test al,al; je +disp32` 守卫形态
   （0x32d81a8/0x36bd6e3/0x36bed6c/0x3b53b26/0x4883cca/0x50a5634/0x50b5639/
   0x50b5eb1），其中 **0x50a5634 ∈ 解析函数**（解析+0x514，与 fzlzjerry 的
   解析+0x647 同族同位）。→ 未来 x64 新构建的冗余 silent 法：翻转该 je→jmp。
   配方化受阻点：DSL 的 expected 门是静态字节，call rel32 逐构建不同
   （需 expected 通配/掩码扩展，记入 DSL 扩展项）。
2. **群聊提示 = 全生态已知未解限制**：fzlzjerry #47（269079 群防撤回无提示）、
   #63（269579 自定义提示群聊无效）均无公开解法；其 arm64 tip 模式（str xzr
   写零 newmsgid）与我们 v1 同款。我们的 8 轮动态/静态分析深度超过全部公开资料。
3. **红包文档的可借鉴点**（非功能——运行时调用是本项目的 non-goal）：
   跨构建重定位方法论（LC_FUNCTION_STARTS + 函数匹配 + ADRP 解码 + 漂移表
   +0x12C8/+0xD18/+0x4000，"不是整体平移"）与我们 recipe 引擎一致；
   对象尺寸复核（Message 632B = 0x278，与批扫描器步长互证 ✓）。
4. **验证现状结论**：Intel x64 4.x 防撤回，本项目是唯一完成真机全链验证的
   实现（269602：silent/keeptip/update 全部 ✓）。

### 行动项
- [x] 本表存档
- [ ] （可选，需用户批准）向 fzlzjerry #55 贡献 269602 x64 已验证数据
- [ ] （DSL 扩展项）expected 通配/掩码 → branch-flip 配方化（未来构建冗余 silent）
- [ ] 新构建（269631+/270090 x64）出现时：watch-wechat 自动定位 + 本文档位点族作起点

### 第二轮：fzlzjerry patches.json 全量解析 + 重定位脚本 + WeChatTweak

- **patches.json（29 构建全 arm64）**：目标类型 revoke（entry 翻转 cbz→b）、
  revoke-tip（分支位还原 + str xzr，expected 同时接受补丁/原始态=可组合）、
  update（5–9 条序言→ret/w0=0）、multiInstance(+extra：tbz→nop)、
  **runtime-tip（268849+：函数序言 F85FBCA9F65701A9F44F02A9 内联改写为
  ADRP+LDR+RET——自定义提示的免注入实现）**。x86_64 条目：**零**。
  覆盖至 270090（含 runtime-tip 两处：4bbe5cc/4b5b0a0）。
- **可组合设计印证**：他们的 revoke-tip expected 同时接受两态——与本项目
  今日落地的跨变体状态登记（v1/v7 互认）同一思想。
- **重定位脚本**：IDA headless + LC_FUNCTION_STARTS 校验 + 12 字节入口指纹
  （供跨版本关联）。指纹法可纳入我们的 archive 工具链（小改进，待办）。
- **WeChatTweak（sunnyyoung）**：同为二进制补丁路线（patch/versions 命令），
  README 未列 4.x 支持细节——非更优机制，同类竞品。
- **红包运行时调用**（地址表+指纹校验+原生调用）：non-goal 不采纳；
  其"按构建选地址表、指纹不符不调用"的安全模型值得赞许。

### 最终优化判定
1. x64 keeptip 群聊提示：全生态未解，维持 v1 现状（已有全深度分析存档）。
2. 未来构建的冗余 silent：解析守卫 je→jmp 翻转（位点族已记录）——
   依赖 DSL expected 通配扩展（工作项）。
3. 可组合 expected（接受多历史状态）：本项目已实现（跨变体登记）✓。
4. 入口指纹存档：小改进，纳入 archive 工具链待办。
5. Intel x64 真机验证数据：全生态独有，可（经批准）反哺社区。

## 2026-09-18 全网生态调研（双代理调研 + 本机验证）

### 版本事实（本机 CDN 直连验证）
- **4.1.15.19（270099）仍是最新**：官网/mac.weixin.qq.com 均 4.1.15（09-15 发），
  `WeChatMac_4.1.16.dmg` 404，GitHub 全站与各工具 issue 区无 270100+ 痕迹
- **官方 CDN 存在按构建号归档的直链**（生态此前不知）：
  `https://dldir1v6.qq.com/weixin/Universal/Mac/xWeChatMac_universal_<ver>_<build>.dmg`
  ——本机实测 270091/93/95/96/97/98/99 全部 200（仅 4.1.15.12_270092 404）。
  这推翻了 MAINTAINING「历史构建 expected 回填暂无可靠免费源」与 ROADMAP
  「270091-98 永久缺口」的结论，本轮已借此回填 5 个缺口构建
- WeChatTweak 上游停更（最后 config 34371，2026-02），社区 PR 无人合并；
  X1a0He v2.9.0（09-12）支持到 270090 后**闭源化**（仓库只剩 README+dylib+pkg）

### 竞品动态
| 项目 | 状态 | 要点 |
|---|---|---|
| X1a0He/X1a0HeWeChatPlugin | v2.9.0 → 270090，arm64 only，**已闭源二进制分发** | 撤回遮罩/媒体自动下载转发/防自己撤回/退群监控仍在迭代；Intel 依旧 ❌ |
| fzlzjerry/wechat-antirecall | 2026-09-13 活跃，arm64 only | **新增自动抢红包**（269624/628/270090，0-5000ms 延迟可配）；{from}/{time}/{content} 占位符（{content} 靠 serverId 缓存预览原文） |
| WeChatTool/WeChatTool | **2026-09-18 当天出现**，1★ | 对位 wxkeep：270099 双架构验证，拷贝式多开；独有「辅助功能接口保留」实验功能 |
| a244573118/WeChatIntercept | 952★，2026-06 停更 | **内置特征码搜索**（新版本免硬编码偏移表自动定位）；双架构；撤回系统通知带原文（群聊降级） |
| zengtianli 三件套 | 2026-09-17 推送，arm64 → 269631 | **群聊提示根因文档化**：newmsgid 同时锚定删除与群提示插入，清零保消息必连群提示一起消失（与我们 v1 模型一致，互相印证） |
| MustangYM/SovietExtension | 484★，9 月极活跃，锁 269079 | 撤回媒体「同步到手机」=转发到自聊天/文件传输助手（含媒体自动下载） |

### 技术情报（对 wxkeep 有用的）
1. **WeChat 4.x 撤回管线 Windows 侧完整逆向**（看雪 thread-286611，4.0.3）：
   `CoReplaceOriginMessageByRevoke → GetMessageBySvrId → DeleteMessage（物理删行）→
   AddMessageToDBbyWxID（插提示）`——**撤回处理后原文不保留在库里**（Mac/Win 共用
   C++ 核心）。X1a0He 的「从库里捞原文」实为消息流缓存（hook 消息处理入口先存）
2. **4.1.11+ SQLCipher 密钥内存扫描已死**（堆里无 PRAGMA ASCII 串、mach_vm_read
   全区扫不到）：现行方案=进程内观测 CommonCrypto（Frida hook
   CCCryptorCreateWithMode/CCKeyDerivationPBKDF，或 lldb 断点）——对无注入
   路线不适用，记录为开放课题
3. **arm64 hook 工程事实**：wechat.dylib arm64 切片**无 PAC/BTI**（bti c/paciasp/
   autibsp 全零计数）——inline 蹦床无需签名/对齐处理；改 __TEXT 标准路径
   vm_protect(RW+COPY)→memcpy→`sys_icache_invalidate`（Dobby darwin 后端实证）。
   本仓 runtime.m 的 arm64 机器已按此落地
4. WeChatTweak 上游 issue #1036：Intel 上 patch 报成功但只处理 arm64 slice
   （静默无效）——上游 4.x 补丁仅 arm64 的又一实证；双架构仍是本仓独有优势
5. fzlzjerry {content} 占位符靠「按 serverId 的消息缓存」——M-R3 完整版的
   同款思路已在 ROADMAP（终结器缓存）

## 2026-09-19 WeFlow 6.3.1 静态解剖（用户提供的双架构 DMG）

> 样本：WeFlow-6.3.1-arm64.dmg / x64.dmg（Electron 应用，app.asar 497MB）。
> 纯静态分析：asar 解包（dist-electron/main.js 2.8MB）+ 资源串解剖，未执行。

### 定性：聊天记录导出/分析/AI 工具，不是防撤回补丁器

- 主体是 **会话导出 / 年报 / AI 分析 / 转录 / 图片解密**（agentWorker、
  annualReport、transcribe、imageDecrypt、wcdbWorker、keyRecover 等）
- 其「revoke」相关符号（RevokeLookup/RevokeContextMessages/
  RevokedOriginalMessage/RevokeFallbackContent）全是**导出侧的撤回消息展示**
  （从解密库里查撤回消息及上下文），非拦截

### 技术架构（值得关注的部分）

1. **DB 密钥提取：Frida hook `ccpbkdf2_hmac`**（libcorecrypto.dylib 内部符号，
   非公开 CommonCrypto 包装层）——比生态公开方案（Dengququ 等人的
   `CCKeyDerivationPBKDF`）更深一层：微信的 PBKDF2 走 corecrypto 内部路径时
   公开 API 断点可能漏。helper 二进制（xkey_helper_macos）内嵌 Frida JS 脚本，
   等密钥回调后 JSON 回传
2. **语义扫描定位**（image_scan_helper）：`semantic candidates → strict
   candidates → exec-range strict hit`——与我们的 recipe 引擎同向（特征定位
   免硬编码偏移）
3. **welive（Rust 单文件工具）**：自带 libWCDB.dylib/libwcdb_api.dylib 直读
   微信加密库；`monitor sse`（Server-Sent Events 流式监控 DB 变化）；
   子命令面含 `anti-revoke install/uninstall/check --session-id`
4. **anti-revoke 是 DB 级方案**：per-session 的「监控撤回 sysmsg 落库 →
   `update-message`（--local-id/--create-time/--content）回写恢复原内容」——
   事后补救而非事前拦截（与 update-message 子命令并存互证）
5. 运行时策略校验（直接运行 welive 报 `runtime policy validation failed`，
   仅 WeFlow 宿主带合法环境可拉起）

### 吸收判定：**不吸收，记录为对照路线**

- DB 级防撤回（welive 式）需要：密钥提取（Frida 注入微信进程）+ 常驻监控 +
   对微信**打开中的** WCDB 并发写——三面都与本项目「无注入、字节级、
   一次性写」的安全模型冲突；收益（可恢复历史撤回）不抵风险（库锁竞争/
   密钥驻留）
- `ccpbkdf2_hmac` 深层断点情报已归档（未来若做离线取证工具可用）
- **法律背书事实**：WeFlow 仓库 2026-08 被 Tencent 法务函清空（README 只剩
  合规声明），同 chatlog（2025-10）——微信数据解密工具链的法律风险实证，
  本项目坚持「只补丁、不解密、不读数据」路线的又一依据

## 2026-09-19 全网复查（独立代理调研 + 本机验证）

- **4.1.15 仍是最新**：官网 mac.weixin.qq.com 当前 4.1.15；`WeChatMac_4.1.16.dmg`
  CDN 404；GitHub 全站无 4.1.16 issue 痕迹；270100（热修通道）之上无任何构建号
- sunnyyoung/WeChatTweak：停更状态不变（最后 config 34371，2026-02）；社区
  PR #1042（269602 支持，2026-09-13）仍未合并
- zengtianli/WeChatTweak PR #2（vvanglro，已合并）：269602 arm64 keeptip——
  与本仓 v1 同款 newmsgid 置零，**群聊提示不显示为作者实机确认的已知限制**
  （与我们 ㉔ 的根因模型互相印证：清零 newmsgid 必连群提示一起消失）
- WeChatTool v0.1.3（2026-09-18）：修「自己撤回崩溃」——其 v0.1.2 补丁误伤
  微信自用的全局消息分类器；对本项目的启示与 rewrite_self 默认门同向
  （自发撤回路径必须显式区分）
- 新增 Mac 密钥提取仓库一批（fanrongrongrong/wechat-mac-auto-export、
  3351666087/wechat-mac-os 等，2026-09-16/17）：全部 Frida
  `CCKeyDerivationPBKDF` 路线，无新机制
- SovietExtension 1.4.1（2026-09-17）：仍锁 269079；「撤回内容转发到文件
  传输助手」路线不变
- **结论**：防撤回技术面本仓仍处生态前沿（universal keeptip 跨构建 + 双架构 +
  行为验证 + 运行时文案自定义）；无新可吸收机制，唯一开放课题仍是
  群聊灰条提示（需区分「删除查找」与「提示合成」两次 newmsgid 查询的深 RE）
- **CDN 归档直链细节修正**（本机实测）：4.1.15 家族的构建号直链用**点分
  WeChatBundleVersion**——`xWeChatMac_universal_4.1.15.20_270100.dmg` ✓ 而
  `…_4.1.15_270100.dmg` 404；热修通道装机的 270100 与 CDN 4.1.15.20 切片
  LC_UUID 相同、补丁位点逐字节一致，但整文件非逐字节相同（高位段/大小差
  1.7MB，expected 门按位点比对不受影响）

## 2026-09-19 第三轮生态对比（独立代理全网调研 + 本机验证）

**方法**：GitHub API + raw 一手抓取（WebFetch 对 github.com 超时，改 API 路径）。

### 竞品格局（关键事实）

| 仓库 | 状态 | 最新支持 | 机制 |
|---|---|---|---|
| sunnyyoung/WeChatTweak（改名自 -macOS） | 存活但停更（2026-02-08，config 止于 3.x 34371） | 3.x only | v2.0 重写为 Swift 字节补丁 CLI，**盲写**（无 expected 门/无备份）；PR #1039（zengtianli 4.x+expected）/#1042（EchoXml 269602）挂着未合并 |
| zengtianli/WeChatTweak | 活跃（09-17） | 269631（4.1.13.63） | expected 门 + 三代签名 Locator + Resigner；keeptip=newmsgid str→xzr 同构；269631 arm64 update 8 点；GUI（WeChatUnrevoke） |
| tanranv5/WeChatTweak | 活跃（09-17，v270098） | 270098 x64 | **盲写**；270098 x64 silent=parse 入口 `mov eax,1;ret`@0x537DAD0（与我们 parse 入口 0x537dad0 **逐字节同址**）；**WCDYWrapper 完整性绕过**（见下）；x64 全系 multiInstance 6×NOP |
| fzlzjerry/wechat-antirecall | 活跃（09-13） | 270090 arm64 | 四件套同族 + runtime-tip 注入（inline-hook 蹦床）；**抢红包**（269624/628/270090 实证）+ {content} 第二 hook；270090 dyld 时序坑文档 |
| X1a0He/X1a0HeWeChatPlugin | 闭源，**2.10.0 今日发布** | 270091-270100 arm64 | dylib 注入；自定义撤回提示/撤回通知/退群提示前缀 + 实时预览（文案定制面比我们宽） |
| zsbai/wechat-versions | 活跃（每日归档） | **4.1.15.20 = 270100 顶格，无 4.1.16** | 归档源 |

**wxkeep 定位**：唯一双架构 + 4.1.15 全家族（270090-270100 缺 270092）
仓库；行为级 verify（出进程调用补丁函数）与 expected 多变体字节门仍是
独有安全面。

### 技术情报（新）

1. **WCDYWrapper 完整性校验（4.1.15 新防线）**：tanranv5 在 270098 x64
   需打 `Contents/Frameworks/ld/WCDYWrapper.framework` @0x8E03B
   （`jmp +0x32` 绕过）才能活。**对本项目不适用**：⑬ 轮 270100 x64 真机
   全链（patch→resign→launch→verify）无此补丁照常运行——定性为其盲写 +
   重签流程差异（我们 entitlements 快照保留重签，库校验链未破坏）。登记
   为「若未来真机出现 WCDYWrapper 相关杀机」的备选情报。
2. **tanranv5 位点互证**：其 269629/631 x64 revoke 位（512BE50/512C720）
   = 我们派生链的 parse 入口；270098（0x537DAD0）与我们 catalog 270098
   hook 行（0x537dad0）同址——独立逆向同源。
3. **zengtianli 群聊提示路线互证**：docs 论证「保真 newmsgid + NOP 下游
   虚派发删除调用（lldb 动态定位）」是群聊灰条正解，且断言 fzlzjerry 的
   runtime 注入也解不了——与 ㉘ 第二轮路线图（0x3445e20/3421bb0 断点对
   比「查库命中/失败」分叉）同向，生态内尚无人做成。
4. **fzlzjerry 抢红包组件**（ReceiveRedEnvelope/OpenRedEnvelope 服务链，
   269624/628/270090 地址表）：非防撤回核心，未立项；其 {content} 占位符
   的第二 hook（通用 Message 绪结器）是实现参考。
5. **新仓库**：WeChatIntercept（系统通知展示撤回原文，特征码自适配）、
   WxNoRecall（离线防撤回主张）、wxRevoke（hook
   UNUserNotificationCenter.removeDeliveredNotifications… 拦通知销毁——
   独立第二防线思路）、hnan/heifenshen（沙盒多开不补丁）。
