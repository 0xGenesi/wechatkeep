# 269602 更新器定位结论（M2-2，2026-09-15）

## 事实
- `XAppUpdateManager` 在 269602 的 **arm64 与 x86_64 两个 slice 中都不存在**
  （zengtianli 的 signatures.json update 段适用于 269579/269627 等构建；vvanglro 的 269602 条目同样没有 update target）
- wechat.dylib（x64）`__objc_classlist` 共 66 类：Qt 平台层(QNSView/QCocoa*)、媒体(RTC*)、
  文件提供者(FileProvider*)、WeType、两个疑似更新类：
  - `MacUpgradeUtil`：类方法仅 beta/外观/代理设置 —— **不是更新器**
  - `AppUpdateStateListener`：仅 `sharedInstance` —— 状态监听桩
- app bundle 内**无独立 Sparkle.framework**；dylib 内存在 Sparkle 文案字符串
  （"Checking for updates..."、"Update available. Restart Weixin to apply."）
- 更新相关字符串为 **C++ 符号**：`check_update_nor…`、`StartCheckUpdate`、`CheckForUpdates`、
  `MacStoreUpdate.xml`、`recheck_commands`

## 结论
269602 的更新逻辑为 C++ 实现（无 ObjC 元数据可按名定位）。屏蔽更新需新的逆向：
以 `CheckForUpdates`/`MacStoreUpdate.xml` 等字符串的代码交叉引用为锚点，双架构各定位一套。
属「参考 diff + 人工 SOP」级课题（docs/MAINTAINING.md 待建章节）。

## 现实保护（当前）
- 用户侧：微信更新需手动确认（SUAutomaticallyUpdate=0），不点升级即安全
- 工具侧：`tools/locate_update_x64.py` 为通用 ObjC 定位器，任何含 ObjC 更新器类的构建
  （如 269579/269627 的 XAppUpdateManager）可直接产出 update 条目

## 工具验证记录
locate_update_x64.py 在真实 269602 x64 slice 上验证：
- chained-fixup 解码（classlist 槽位 0x0010_0000_0A53A198 → 0x0A53A198 ✓）
- relative 方法表 12B/项 + selref 间接寻址（0x40000000 direct 标志区分）✓
- 类/元类方法合并、66 类全遍历 ✓


## 后续（2026-09-15 晚）：preferences 层防护已交付

二进制逆向未完成前的实用防线：Sparkle 偏好仍在生效（真机证据：SUUpdateAlert
窗口帧、SUSkippedVersion=24456、SUEnableAutomaticChecks=1）。`wxkeep update-guard`
写三个键（关检查/关自动安装/关遥测），挂进 patch 流程与 doctor。

关键工程发现：**cfprefd 域所有权** —— 微信运行中，其沙盒域由 app 的 agent 持有，
外部 defaults 写入被静默丢弃（真机实测）；写入必须以微信退出为前提（与 patch
同约束，故挂进 patch 流程自动满足）。

## x64 keeptip 逆向进展存档（2026-09-15 晚，第二会话）

已确认的锚点链（x64 slice, F=parseRevokeXML 集群 0x328EAA0）：
- `0x5ABE310` = XML 属性 getter（被调 20+ 次）；`0x32A0972` 处即 `Attr("newmsgid")`
- `0x4E490B0` = 属性值非空检查（`test al; je` 空则跳 0x32A0B87 路径）
- `0x92310` = string→uint64 转换（arm64 `0x47F8F1C` 的同源），@0x32A0B8E
- `0x32A0B93 mov [rbp-0xB0], rax` = newmsgid 数值栈槽
- 之后：0x5AC16A0 格式化回字符串 → 0x284190 构造 → 0x4EBCAA0 → 日志(0xA1F 行号)混淆链
- **未决**：newmsgid 最终写入 this 的哪 个偏移（x64 是字符串化路径，与 arm64 整数字段
  `+0x1C8` 模型不同；this 存 [rbp-0x248]，直接 `mov [this+disp]` 存储在本函数未出现，
  疑在子函数内）。下次从 [rbp-0xB0]/0x284190 返回值的消费方继续。

## x64 keeptip 推理完成（2026-09-16，#4）

消费链闭环：newmsgid 数字 → 0x5AC16A0 格式化回字符串 → 0x284190 构造 →（解密日志混淆段）
→ 0x32A0D93 `lea rsi,[rbp-0x1e0]`（数据指针）+ 0x32A0D9D `mov rdx,rax`（长度）
→ 0x32A0DA5 `call 0x32A1090`（结果构造器，ecx=5 类型标记）。

keeptip 语义补丁（与 arm64 的 str xzr 同构思路，作用于长度传参）：
`0x32A0D9D: 4889C2 (mov rdx,rax) → 31D290 (xor edx,edx; nop)`
newmsgid 以空串到达下游删除路径 → 找不到删除目标 → 消息保留；解析/提示流程不受影响 → 提示保留。

状态：**实验条目**（语义推理链完整，expected 门已核对 4889C2 ✓，待真机撤回实测——
私聊应留消息+提示；群聊提示是否依赖 newmsgid 锚定请一并观察，参照 arm64 keeptip 的已知局限）。

## 二进制级屏蔽更新逆向档案（#5 会话，2026-09-16）

已确认路径（x64 slice）：
- 更新配置构造函数：入口 0x1C9E120（push rbp 序言，前导 0x66/0x90 padding），无直接 E8 调用者（间接调用：函数指针/调度表）
- 函数体内 0x1C9E7A0 lea 引用 "MacStoreUpdate.xml"（唯一）；构造更新 URL/路径对象
- "CheckForUpdates"(0x8C63CE0) / "StartCheckUpdate"(0x8CFC560) / "try check update"(0x8CFC570) 字符串存在但**无 lea/imm32/imm64 直接引用**——更新器日志字符串经**运行时解密拼接**（C++ constexpr 混淆），静态交叉引用断链
- ObjC 类不含更新逻辑（AppUpdateStateListener 仅 sharedInstance，MacUpgradeUtil 是设置工具类）
- 0x1C9E120 无数据段指针引用、无 chained-fixup rebase 命中——调度方式待动态（lldb）定位

结论：**二进制级 block 需 lldb 动态会话**（在 0x1C9E120 下断点，回溯调用栈拿间接调用来源），
属专项逆向。当前偏好层 UpdateGuard 三开关已在真机验证有效（不检查/不自动装/不遥测），
二进制级为纵深防御、非必需。降级为低优先级档案。
