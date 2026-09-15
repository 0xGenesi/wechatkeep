# Verifier 预研 Spike 结论（M2-3，2026-09-15，269602 x64）

## 结论：迷你加载器路线可行，dlopen 路线判死

| 路线 | 结果 | 原因 |
|---|---|---|
| dlopen（RTLD_NOW/LAZY） | ✗ | wechat.dylib 依赖 app 内 WCDYWrapper 等大量框架；即使补齐依赖，Qt 初始化器在 app 外必然崩溃 |
| **迷你加载器** | ✓ | 无 dyld、无初始化器、无依赖、确定性、CI 友好 |

## 实测（269602 x64 slice，isRevokemsg @ 0x4BC5940）

- pristine：`isRevokemsg("revokemsg")=1`，`("sysmsg")=0`，`("NewMsg")=0`，`("")=0` ✓ 语义正确
- patched（xor eax,eax; ret）：全部返回 0 ✓ 补丁行为被证明

## 四项关键技术（Verifer 设计输入）

1. **映射**：本镜像 __TEXT/__DATA_CONST/__DATA 恒有 fileoff==vmaddr → 整文件 mmap RWX 后 `fn = base + VA`（__DATAS/__LINKEDIT 不恒等但不参与执行）
2. **PLT/GOT 重定向**：目标函数调用的桩 `ff 25 <rel32>` → 计算槽位 VA = 桩VA+6+disp，把槽位覆写为 harness 原生函数指针（本例 strlen/memcmp）
3. **magic-static 状态预备**：C++ 懒初始化全局在真实进程由 dyld/初始化器归零，裸映射是脏字节 → 调用前 memset 清零该区域（验证器拥有 state-prep 指令表）
4. **参数 ABI**：微信自定义 SSO 字符串（byte0=长度<<1 低位=长串标志；短串数据在 +1；长串 size@+8 ptr@+0x10）——**不是** libc++ std::string（其 size 在字节 23）。probe 需按目标 ABI 构造参数

## 工程化路径（M2 交付 `wxkeep verify`）

- verify spec（JSON）：函数 VA + 参数编码（wxstring/stdstring/u64…）+ GOT 重定向表 + state-prep 清零表 + 断言（输入→期望输出，pristine 与 patched 两套）
- 执行器：fork 子进程跑映射+调用（防崩溃影响主进程），超时保护
- 流水线用途（M6）：新构建自动定位后自动 verify，通过才生成 PR —— 适配从人工撤回实测变成自动行为验证
