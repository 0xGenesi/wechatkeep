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
- **M-R2 ✅（工程已落地，待实弹验收）**：提示文本替换。hook 点 =
  **撤回解析汇点 wrapper 0x537d910@270099**（drive22 终验定案：A 到达
  解析 / B 二次解析 / D 历史批扫三路径的唯一公共汇点；isRevokemsg 只收
  类型串的前提已证伪，早期候选 0x538d700 只覆盖 async 路径，均被取代）。
  wrapper(rdi=信息对象, rsi=消息结构)，撤回 sysmsg XML 的 SSO 嵌在
  rsi+0x130——hook 入口处把 `<replacemsg>` 内文**等长改写**为
  runtime.json 文案（含「撤回」needle 门、超长放弃、差额空格填充、
  `<>&` 配置期剥除），SSO 结构与分配器零接触；下游解析/入库/会话预览/
  渲染/历史重扫全链一致（连 DB 持久化都是自定义文本）。引擎：UUID 门 +
  序言 12B 门 + RWX 蹦床 + `_dyld_register_func_for_add_image` 同步回调
  与既有镜像扫描双保险；6 项单测（RuntimeHookTests）。剩余：真机装
  dylib 后一轮真实撤回肉眼验收（研究语义已被 drive22 全链证明）。
  **实弹定案补遗（2026-09-18 drive25）**：调试器同语义改写已肉眼验收 ✅
  ——线上撤回 XML 的提示文本承载元素实测为 **<content>**（非
  <replacemsg>，后者为 parse 内另一分支形态），改写已补充双标签 +
  CDATA `]]>` 闭合保护（8 项单测）；且 sysmsg 会被多轮重解析，**已入库
  的旧提示亦可追溯换文案**。注：wrapper+0x130 偏移为静态推定，若实机
  hook 未生效则地址表切 parse 入口（rsi 直挂，drive25 实证）。
- **M-R3**：{from}/{content} 占位符（消息缓存，按 serverId 终结器缓存——
  fzlzjerry 同款思路）+ 群聊适配
- **M-R4 ⛔（阻塞：活体数据缺）**：消息"已撤回"标记——状态写位点已定位
  （`mov [rdx+0x118],9` @0x355ab00@270099，全镜像唯一，269602 0x32e73a0
  双子）。阻塞点：keeptip 态下该路径不达（newmsgid=0 → 状态标记零命中，
  drive22 实证），rdx 对象布局需 silent/无补丁态重跑 drive22 同轮捕获。
  位点静态唯一性已足够支撑 hook 设计，活体数据到手即可开工。
  **drive26 布局补遗（2026-09-18）**：Message 向量（async-body rsi，
  步长 0x278）活体实证 +0xC=type(1文/3图/49表情)、+0x18=talker、
  +0x30=self、+0x48=sender、+0x118=常态 0x3；async-body 为通用批处理器。
  三方案判定（ROADMAP ⑧）：A 状态位注入（语义未观察，恐触发 UI 隐藏）/
  B 存储层内容前缀打标（XML 含 <session>/<msgid> 可定位，可行性中）/
  C UI 遮罩（工程量大）。近期实用替代：M-R2 文案即标记。

## 信任与安全

- runtime dylib 由本项目构建、随 bundle 重签（ad-hoc）；无网络行为
- 配置只读本地 runtime.json；不上传任何内容
- `runtime remove` 完整还原；安装前自动备份主程序
- **宿主门（2026-09-18 复审加入）**：构造器先验证主程序 basename ==
  "WeChat" 才启用全部机制——dylib 被其他进程链接（单测 runner 为活例）
  时零副作用（不扫描、不定时器、不写 marker，避免污染 `runtime status`
  的「已加载」判定）；区域扫描只解引用**当前** protection 可读的区域
  （PROT_NONE 保留区实测会让进程 SIGSEGV）
- **安装/移除原子性（2026-09-18 复审加入）**：install 在 LC 注入后的
  dylib 拷贝/重签失败会回滚主程序并清理 dylib（不留「LC 在场但库缺失」
  的启动必崩态）；remove 对「LC 缺失 + 孤儿 dylib」做安全清理而非报错
  （LC 已实证缺失时删除 dylib 无启动风险）
