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

## 破局（2026-09-17，纯静态完成——上段「需动态」结论被推翻）

关键武器：`dyld_info -fixups` 解码 chained fixups，直接看数据段里的函数指针，
绕开「无直接 E8 调用者」的间接分发迷雾。

x64 链路（全部落定）：
- `mmui::MacStoreUpdateUIService` 字符串在服务名注册表（__data，mmui::* 字母序）
- 唯一代码引用 0x1945A0 = 按名取服务的 strcmp 链 getter（其自身在 vtable 槽 0xA149080）
- 同一 vtable 组：0xA1490D8 → **0x1C9CF60**（主工作方法）、0xA1490E0 → 0x1C9F660、
  0xA1490E8 → 0x1C9E120（此前误认的 0x1C9E120 实为小工厂；真 xml 构建器是
  0x1C9E5E0 ← 0x1C9D460 ← **0x1C9CF60**，全镜像唯一 "MacStoreUpdate.xml" 引用）
- **0x1C9CF60 = 周期检查工人**：取管理器 → 遍历待查 map → 构建 xml 配置 → 重置 GCD
  定时器（0x7595B50，返回 int 句柄）。唯一 ret，返回值 = 定时器句柄(int)
- **补丁**：`0x1C9CF60: 31C0C3`（xor eax,eax; ret），expected
  `554889E54157415641554154534881EC`。返回 0 安全（int 句柄）；配置不再构建、
  定时器不再续期；手动「检查更新」走其他入口不受影响（保留用户主动升级能力）

arm64 269602：xml 构建器定位到 0x1A89B34（FUNCTION_STARTS），但零 BL 调用者、
无 fixup vtable 槽、getter(0x17BB8C) 同样无槽——接线方式未明（疑似 BLR 计算跳转/
FUNCTION_STARTS 区间合并干扰）。**跳过**，由 update-guard 偏好层兜底；目录内其他
arm64 构建已带 zengtianli update 条目。

## arm64 破局（2026-09-17 第二会话——上段「接线未明」被推翻）

上段失败的真因：**函数入口地址差 8–16 字节**。0x17bb8c/0x1a89b34 都不是真入口，
vtable 槽和 BL 扫描自然全部落空。锚点引用点（adrp+add 唯一命中：
getter 引用点 pc=0x17bbac、xml 文件名引用点 pc=0x1a89cb0）向左找 FUNCTION_STARTS
精确入口：**getter=0x17bb94、xml 构建器=0x1a89b44**。

arm64 完整链路（与 x64 逐层同构）：
- `dyld_info -fixups`：getter 0x17bb94 在 vtable 槽 **0x9635310**（x64 getter 槽
  0xA149080 的孪生）；**+0x58 槽 → 0x1a886ec（周期工人，1320B）**、+0x60 → 0x1a8ab44、
  +0x68 → 0x1a89730（x64 上 +0x58/+0x60/+0x68 = 0x1C9CF60/0x1C9F660/0x1C9E120）
- BL 链唯一闭合：**0x1a886ec →(BL)→ 0x1a88c14 →(BL)→ 0x1a89b44**（唯一
  "MacStoreUpdate.xml" 引用）；x64 同构 0x1C9CF60→0x1C9D460→0x1C9E5E0
- 工人语义核对（llvm-objdump）：x19=this → 取管理器 → 遍历 [0x9d44488,0x9d4458c)
  4 字节步长待查表 → 函数体内 bl 0x1a88c14（xml）+ 定时器续期 → **唯一 ret**（0x1a88b40）

**补丁**：`0x1a886ec: 00008052C0035FD6`（mov w0,#0; ret），
expected `FF0306D1FC6F12A9FA6713A9F85F14A9`（sub sp,sp,#0x180; stp×3 序言）。
已入 config.json（269602 update 目标双架构齐备），真机 arm64 slice 上 expected 门
经 dry-run 验证通过。方法论沉淀：**arm64 vtable 引用静态定位 = 精确 FUNCTION_STARTS
入口 + fixup 槽扫描**，入口差一个字节就全链落空。

## v3 破局（2026-09-17 下午，动态编排实证）

v2 真机失败（提示完美但消息仍被删）后，动态三轮定位出真实活路径：

- **wrapper 0x50A5120 只在登录同步重放时走**，活撤回的 vtable 解析到别的实现
  （drive4 教训：HandleCommand 打bt会打到选中线程；必须遍历命中线程帧——drive5）
- 活路径：分发器 0x32E5D40 → **0x36D58D0**（A）→ parse(0x36d68ae→0x5039410) →
  notify(0x32ce790) → msgsvc(0x50380b0×2) → **load+mark(0x32aa7b0)** → disp(0x32e69b0)
  → enqueue(0x36d5770，仅入队)；B(0x36D9120) 同样只入队
- **删除的真身**：0x32aa7b0 → 0x32a8370 → 0x32a9060 → **0x32e73a0**
  对原消息写 `+0x118=9`（撤回状态位）并经存储接口 getter(0x30f8e50，按哈希名
  `_671c1c9e` 取接口) 调 0x31a2030 落库——**标记即删除**（UI 按状态过滤）
- 批量路 0x43d7e30 → 0x32a9060 汇入同一标记点——v2 NOP DeleteBatchByUniqueId
  无效的完整解释
- 提示 = 那条独立进来的 XML 消息本身（msgsvc 正常保存），不依赖标记步骤

**v3 补丁**：`0x32a959f: E8FCDD0300 → 9090909090`（NOP 0x32a9060 内对 0x32e73a0
的调用；返回值无消费，已核实）。一次覆盖活路径+批量路；newmsgid 全程不动 →
提示保持 v2 表现，消息保持可见。四 DeleteBatch NOP 保留（仍挡登录同步批删）。

## v4 定案（2026-09-17 傍晚）

v3（标记点 NOP）真机仍未保住群聊消息 → drive8 编排（前段链布防）抓到真实删除：

- 处理器 A 前段：0x36d5f7a 调查找执行器 0x36d4a10 → 0x36d6320 调「撤回主力」
  0x32ad4d0 → collect(0x30db570) → handler16(0x32abc90) → handler-d(0x32abd90)
  → **批扫描器 0x36dbae0**；分发器 0x32e623a 直调、0x43D 异步路同样汇入
- 扫描器内部：0x278 步长遍历消息数组，谓词 0x4d6efd0(→0x50b5ea0) 选中，
  收集 [msg+0xF8] 进 vector，循环后经存储接口 getter 0x36dd7f0（哈希名骨架
  同 0x30f8e50）执行删除
- **批扫描器全镜像仅 1 个直接调用点**：handler-d 内 0x32abdc6，返回值无消费
  （已核实）

**v4 补丁**：`0x32abdc6: E815FD4200 → 9090909090`。与 v3 标记点 NOP 叠加
（标记的 DB 状态写是独立隐藏路径，两者都拦才是完整闭合）；newmsgid 全程不动。

## v5（2026-09-17 晚）：全链条路由图与"在册隐藏"模型

drive11（12 点全链布防）实证一条活撤回的完整路由：
- A(0x36d58d0) 跑 3 轮/条（主处理+同步确认），每轮：查找执行器(0x36d5f7f) →
  主力(0x36d6320) → handler16 → handler-d(扫描器点 v4 已 NOP) →
  load-mark(0x36d838e) → mark-parent(标记点 v3 已 NOP) → **enqueue(0x36d8543)**
- 排水线程(0x3325670)独立常驻：登录重放条目出队(pop-1/pop-2)，活撤回条目入队后
  由它出队在册处理
- v4 实测（扫描器+标记全 NOP）消息仍消失 → **"删除"真身 = 排水器出队后的在册
  处理（内存撤回集合/UI 隐藏）**，DB 删除路径全部并行无关

**v5 补丁**：`0x36d853e: E82DD2FFFF → 9090909090`（NOP A 内的入队调用，
返回后直接接日志调用，已核实安全）——饿死排水器，原消息不再被在册隐藏；
newmsgid 全程不动。登录重放的旧条目仍由既有入队路径处理（行为保留）。

## v6（2026-09-17 深夜）：替换读取点 = 外科手术式 v1

v5（入队 NOP）仍未保住 → 复查 A 的未覆盖调用点，在解析点前发现关键块：
- `0x36d67f6 mov esi,0x2710` 构建 10000 类型提示对象
- `0x36d6841 mov rax,[r13+0x1C8]` ★ 读 newmsgid（v1 清零的字段）
- `0x36d6859 call 0x50b5ef0` 执行替换/隐藏
镜像内该读取模式（49 8B 85 C8 01 00 00）共 6 处：A 内 1 处 + Qt UI 区
（0x73cd-0x73ce）5 处——UI 也按 +0x1C8 匹配撤回，佐证在册隐藏模型。

**v6 补丁**：`0x36d6841: 498B85C8010000 → 4831C090909090`（xor rax,rax + 4nop）
——仅此消费者拿到 0，提示定位等其他读者仍拿真实 newmsgid = 外科手术式 v1。
