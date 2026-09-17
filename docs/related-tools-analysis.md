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

**可借鉴**：v3 运行时组件（若立项）的配置通道直接用微信偏好域 + 前缀键，
替换 fzlzjerry 式配置文件方案。

## 汇总：三家 + 我们在「4.x 聊天内撤回提示」上的共同边界

RecallKeeper（系统通知不含原文）、X1a0He、fzlzjerry（{content} 仅部分构建且限本次
启动后消息）——**没有任何一家做到聊天窗口内原位提示**。这与本仓 v2 分析一致：
聊天内原位提示必须走 BetterWX 式字节外科（P0 卡在消费链动态定位）。
竞品格局对我们的启示：v2 若做成，将是 mac 生态独一份的能力。

## 待办采纳清单（按价值排序）

1. [ ] 发布清单签名（RecallKeeper 模式）：CI 对 config/signatures 出 sha256+签名，
      doctor 消费前校验——配合 auto-PR 的供应链闭环
2. [ ] doctor 加「dylib 切片哈希不在 archive_index」告警（PoJie 白名单思路）
3. [ ] V2-PLAN v3 节：配置通道改微信偏好域前缀键（X1a0He 思路）；通知加登录态门控
      （RecallKeeper 思路）
