# 运行时组件设计（可选功能，M-R 系列）

用户决策（2026-09-17）：把注入作为**额外可选功能**加入——突破纯静态补丁的能力
边界（自定义提示、消息标记等运行时才可能的能力）。与字节补丁完全独立、可随时
移除、默认不装。

## 总体架构

```
主程序(Contents/MacOS/WeChat)
  └─ LC_LOAD_DYLIB "@executable_path/../Frameworks/wxkeep_runtime.dylib"   ← 注入
Contents/Frameworks/wxkeep_runtime.dylib                                    ← 运行时组件
  └─ 构造器(启动时) → 读配置 → 按 270099 地址表 hook 目标函数
配置: Application Support/wxkeep/runtime.json（提示短语等）
```

- 注入机制：MachOInjector 在主程序 Mach-O 头部追加 LC_LOAD_DYLIB
  （头空间预检，空间不足拒绝；insert/remove 严格互逆，字节级往返测试覆盖）
- 卸载：removeLoadDylib + 删 dylib + 重签；主程序头部尾零补齐
- 微信小版本更新：注入随二进制替换消失 → `runtime install` 重装即可
  （字节补丁需要 locate 重定位，runtime 只需确认地址表——韧性更好）

## 里程碑

- **M-R1 ✅（已交付）**：注入机制 + 最小 dylib（marker 构造器）+
  `wxkeep runtime status/install/remove`
- **M-R2**：提示文本替换——drive14 定位 270099 提示渲染消费点 → dylib 内
  ObjC/C++ hook 替换为 runtime.json 固定文案（私聊先行）
- **M-R3**：{from}/{content} 占位符（消息缓存，按 serverId 终结器缓存——
  fzlzjerry 同款思路）+ 群聊适配
- **M-R4**：消息"已撤回"标记（状态写与删除分离研究）

## 信任与安全

- runtime dylib 由本项目构建、随 bundle 重签（ad-hoc）；无网络行为
- 配置只读本地 runtime.json；不上传任何内容
- `runtime remove` 完整还原；安装前自动备份主程序
