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
