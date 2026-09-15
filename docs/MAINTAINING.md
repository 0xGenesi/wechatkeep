# MAINTAINING — 维护方法论（沉淀自 M1-M6 研发与各上游经验）

> 每个地址的推导来源、置信度、验证方式都要可追溯。本文件是新代签名适配的 SOP。

## 新构建适配 SOP

1. **先自动**：`wxkeep locate` 跑全部配方（或 CI 流水线自动跑）。
   - 命中且唯一 → 进入第 4 步（expected 门会兜底）。
   - 全部 miss → 新签名代，走人工流程（第 2 步）。
2. **人工定位**（参考 diff 法，学 fzlzjerry）：
   - 从 [zsbai/wechat-versions](https://github.com/zsbai/wechat-versions) 取邻近版本官方 dmg
   - `lipo -thin` 抽对应架构 slice，记录 slice SHA-256（审计日志用）
   - 在参考版本定位同源函数，将「屏蔽地址相关立即数后的指令形状」在新 slice 滑窗匹配
   - 用 capstone 反汇编验证（`/tmp/wxre/analyze.py` 模式：带 rip/adrp 引用注解）
3. **新配方入库**：signatures.json 加一条（anchor+derive+confirm），**不是**改 Swift 代码。
4. **字节门核对**：派生 entry 必须带 expected（现场读原始字节），过不了 = 定位错了，禁止放行。
5. **行为验证**（x64，需 SIP off 机器）：`wxkeep verify`。
   - 新构建的 PLT stub VA / magic-static 区可能变化 → 重新反解 verify spec 的 stubs/zero_regions。
6. **真机实测**：撤回一条消息（dry-run/编译/测试都不能替代最后这一步）。
7. **登记**：config.json 条目带 `source`；新签名代在本文末尾登记代际特征。

## 已知签名代（arm64 revoke，几何特征）

| 代 | 构建 | cbz 字节 | delta | newmsgid 字段 |
|---|---|---|---|---|
| 1 | 268575–269136 (4.1.10–4.1.11) | E00F0034 | +0x794 | 0x168 |
| 2 | 269332–269341 (4.1.12) | 40100034 | +0x7A0 | 0x198 |
| 3 | 269574+ (4.1.13) | 40100034 | +0x7A0 | 0x1C8 |

x64 revoke（imm64:revokems 锚点 + padding-boundary + unique-positive-callers）：
2026-09 在 269602 验证（0x4BC5940, 9 callers；已打补丁态靠双边界推导仍可定位）。

## 误改与踩坑记录（防重蹈）

- **x64 结构偏移 ≠ arm64**：newmsgid 在 arm64 是 +0x1C8，x64 slice 无此访问模式——跨架构不可假设结构布局（M2 实证）。
- **fixture 代码区撞段表**：合成 Mach-O 的 0x40–0x68 是 vmsize/fileoff 字段，测试代码必须放 load command 之后（≥0x68）。
- **已打补丁状态会污染边界扫描**：补丁自己的 `ret+NOP` 构成第一个函数边界 → padding-boundary 取前两个边界（M2-1）。
- **dlopen 路线不可行**：wechat.dylib 依赖 app 内框架 + Qt 初始化器在 app 外崩溃（M2-3 spike 判死）。
- **Swift `load()` 严格对齐**：读未对齐 rel32 必须逐字节组装（Verifier 实证）。
- **Swift 数组不是 C 数组**：`withUnsafeMutableBytes(of: &array)` 传的是数组头（指针+count），必须用 Array 自己的 withUnsafeMutableBytes（Verifier 实证）。
- **macOS 15 taskgated**：见 README「AMFI 知识」——doctor 独家预检的由来。
- **漂移比对的目标态**：重签后比对「原始+注入键」而非「原始」，否则自家注入被误判永久漂移（M3-1 实证）。
- **codesign 拒绝合成 Mach-O**（"main executable failed strict validation"）：集成测试用 clang 现场编译真二进制（M3-1 实证）。
- **JSON 数字 vs 字符串**：signatures.json 的 spec 数组元素必须全字符串（Codable 严格类型，M4 实证）。

## 269602 更新器（开放项）

`XAppUpdateManager` 在 269602 双 slice 均不存在（66 个 ObjC 类里只有 Qt/媒体/FileProvider/设置类）。
更新逻辑为纯 C++（字符串证据：`StartCheckUpdate`/`CheckForUpdates`/`MacStoreUpdate.xml`，Sparkle 文案静态链入）。
下一步：以这些字符串的代码交叉引用为锚点做双架构定位。详见 `findings-269602-updater.md`。
