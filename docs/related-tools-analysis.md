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
