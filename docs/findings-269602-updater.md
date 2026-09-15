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
