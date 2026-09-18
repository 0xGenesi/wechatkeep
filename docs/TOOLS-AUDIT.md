# TOOLS-AUDIT — 工具脚本全量审计与修复记录（2026-09-18）

> 范围：`tools/` 下 15 个主脚本（约 2000 行）逐文件精读 + 与引擎源码
> （Engine/Patcher/Config.swift）和 CI 工作流交叉验证；`tools/dyntrace/`
> 的一次性 lldb 研究脚本（硬编码 269602/270099 地址）确认为研究存档，
> 不在维护范围。本轮共修复 **7 个真实缺陷**（其中 3 个在修复/验证过程中
> 新发现）、8 处小问题，并完成 machutil 统一化升级。全部修改附验证记录。

## 一、真实缺陷（按严重度）

### A1. backfill_expected.py — XZ 解压自删产物【每日 CI 必崩】

`decompress_if_xz` 里 `os.unlink(path)` 删掉的是 `xz -dk` 刚解压出的 dmg，
应删 `.xz` 原件。后果链：返回不存在的路径 → `hdiutil attach` 失败 →
main 的 `finally: os.unlink(dmg.name)` 因文件已改名成 `.xz` 抛未捕获的
`FileNotFoundError` → 每日 backfill workflow 遇 XZ 压缩 asset 即崩溃且泄漏
临时 .xz。**已隔离复现**（逐行复刻函数验证：返回路径不存在、目录只剩 .xz）。

### A2. backfill_expected.py — 成功路径同样崩溃（修复中发现）

`mount_read_build_and_extract` 内部 finally 会先删 dmg，main 的
`finally: os.unlink(dmg.name)` 在**每次成功提取后**也抛 FileNotFoundError。
与 A1 同族。修复：main 的 finally 对 `dmg.name` 与 `dmg.name + ".xz"` 均
容错清理；单个归档损坏（XZ corrupt 等）改为跳过该候选继续，不中止整轮
（此前一个坏 asset 会让整轮 workflow 红掉）。

### A3. push-to-github.sh — pipefail 使 SSH 检测成为死分支

`ssh -T git@github.com` 认证成功也恒以退出码 1 结束（GitHub 不分配终端），
`set -euo pipefail` 下 `ssh ... | grep -q` 整管道非零 → `if` 永远走不到 SSH
分支。**已模拟复现**（认证成功输出被 grep 命中，条件仍判 false）。只配了
SSH key、没装 gh 的用户会被引去 HTTPS 分支要 PAT。修复：先
`ssh_out="$(ssh ... || true)"` 落变量再 grep（`<<<"$ssh_out"`）。

### A4. contribute_expected.py — 固定回填 8 字节，restore 残留补丁尾巴

原注释「引擎按 asm 长度做前缀比较，8 字节足够」只对 patch 侧成立
（`Patcher.swift` 的 `matches()` 确实前缀容忍）；**restore 侧是原样写回
`expected[0]`**（`Engine.swift restoreAsm`）。config.json 有 5 条 asm 为
9/12 字节（269602 revoke silent `31C0C3909090909090`、revoke-keeptip
`4831C06690488983C8010000`）——这些条目被回填 8 字节后 restore 只写回
8 字节，keeptip 条目永久残留 4 字节行为改写。修复：取
`max(len(asm), 8)`；同时 expected 写为数组形态（与引擎编码器/backfill 一致，
Swift 侧 ExpectedVariants 两种形态均接受）。

### A5. amfi_sip_probe.sh — RUNS/DIED-LATER 路径产出非法 JSON

`"detail": ${DETAIL:-null}` 裸内插：KILLED 路径 DETAIL 恰为 JSON 对象无恙，
RUNS/DIED-LATER 的纯文本 DETAIL 产生 `"detail": alive ≥25s…` →
verdict.json 解析失败。**已模拟复现**（JSONDecodeError）。修复：DETAIL
统一编码——空→null、已是合法 JSON（TERM_JSON）→原样嵌入保持对象形态、
纯文本→json.dumps 为字符串。三种形态均已验证可解析。

### A6. xref_x64.py — rip_xrefs 字节模式写反，xrefs 子命令从未工作（验证中发现）

旧实现搜单个 `\x8d` 再回看两字节要求 `blob[i-2:i] == 48 8d`，实际匹配的
是 `48 8d 8d …`（lea [rbp+d]）形态而非 rip-relative 的 `48 8d 05 disp32`。
对 libsystem_kernel 实测：**旧逻辑 0 命中**（该 dylib __text 实有 349 个
rip-rel lea）。修复：直接匹配 REX(48/4c)+8d+modrm(mod=00,rm=101)+disp32，
`rip = 指令末尾`。修复后 349/349 全部落入 section，端到端反查闭环
（lea@0xe11 → cstring "mach_port_construct…" → xrefs 反查命中 0xe11）。
callers/dis/find 子命令经 capstone ground truth 5/5 验证本来就正确。

### A7. decrypt_strings.py — LC_FUNCTION_STARTS 基址取错（审计新发现）

基址取了「第一个 section 的 addr」而非 `__TEXT` 段 vmaddr（dyld 语义）。
libsystem_kernel 交叉验证：正确基址命中 nm 函数符号 **1566/1566**，错误
基址仅 111。影响：`func` 字段的 VA 系统性偏大（多加 mach header + load
commands 区域大小）；`str` 字段与解密逻辑不受影响。历史
decrypted_strings.json 的 func 值如需精确引用请重跑刷新（MAINTAINING.md
270099 地图中的地址来自 xref/dyntrace，不受影响）。

## 二、小问题（均本轮修复）

| # | 位置 | 问题 | 修复 |
|---|---|---|---|
| B1 | backfill read_bytes_at | VA 直接当文件偏移（"fileoff==vmaddr" 隐含假设只在 __TEXT 成立）；且每次 lipo 起子进程、死代码 cache | 走 machutil 段表换算 + load_slices 每 dylib 一次；越界/缺架构返回 None |
| B2 | merge_catalogs entry_key | `"binary": null` 存 None、输出端按 `or ""` 查找 → 条目静默丢弃 | 键侧同样 `or ""` |
| B3 | merge_catalogs provenance | 只收集不输出（死代码） | 结尾打印全部替换决策 |
| B4 | merge_catalogs SOURCES_PRI | 全局字典在 main 定义之后才初始化（第三轮审查遗留观察项） | 改为 SOURCES 旁的推导式，模块加载即就绪 |
| B5 | sign_manifest sign_pynacl | `der[-32:]` 切片恒 32 字节，长度检查虚设——传 RSA/EC PEM 会静默签出无效签名 | 校验 PKCS8 Ed25519 DER 前缀 `302e…04220420` + 总长 48 |
| B6 | count_quarantined.py | 依赖 CWD 找 config.json（CI 恰好从仓库根跑才没炸） | 脚本相对路径解析仓库根，支持 argv 覆盖 |
| B7 | gen_verify_spec.py | `from capstone import *` + 未用导入；capstone 缺失裸 traceback | 显式导入 + 友好报错（对齐 locate_update_x64） |
| B8 | xref_x64.py / parse_guard | xref 模块顶层读死路径文件（文件不在连用法都看不了）；parse_guard 的 `import subprocess` 藏在文件尾 | xref 包进 main()，支持 `--dylib`/`WXKEEP_X64_DYLIB`；import 提顶 |

## 三、machutil 统一化升级

新增 `tools/machutil.py`（纯 stdlib），收编 7 个脚本各自手写的 Mach-O 解析：

- `load_slices / load_slice`（fat/thin，**大端** fat_arch——统一实现时一度
  抄成小端，立即被 3 架构系统 dylib 测试抓回；各原脚本此处本来是对的）
- `segments / sections / text_range / va2off`（VA→file offset 的唯一权威口径）
- `function_starts`（基址 = `__TEXT` 段 vmaddr）

改造的脚本：backfill_expected、contribute_expected、decrypt_strings、
gen_verify_spec、xref_x64、locate_x64_revoke、locate_x64_parse_guard。
`locate_update_x64.py`、`watch_new_builds.py`、`gen_matrix.py` 审计无缺陷，
保持原样。脚本以 `python3 tools/xxx.py` 运行时 `sys.path[0]` 即 tools/，
`import machutil` 零配置；CI 工作流无需改动（sign_manifest 不依赖 machutil，
venv 只装 pynacl 的路径不受影响）。

明确不做的事：
- **解释器/依赖升级**——全部脚本仅依赖 f-string 级特性（3.6+），CI 的
  macos-15 runner 自带 python3 完全兼容；capstone/pynacl 为宽松可选依赖，
  无锁定版本可升。
- **dyntrace/ 现代化**——一次性实弹研究脚本（价值在存档），翻新无收益。

## 四、验证记录（全部实跑）

| 验证项 | 结果 |
|---|---|
| 14 个 .py `py_compile` + 2 个 .sh `bash -n` | 全过 |
| xz 自删 bug 复现用例回归（修复后） | dmg 产出/内容/.xz 清理全部正确 |
| SSH 检测死分支模拟（修复后） | 认证成功正确走 SSH 分支 |
| verdict.json 三种 DETAIL 形态 | 全部合法 JSON，KILLED 保持对象形态 |
| machutil vs 系统 dylib（libsystem_kernel，3 架构 fat） | 段表/va2off/text_range 正确；function_starts 对 nm 1566/1566 全命中（错误基址 111） |
| rip_xrefs 修复后 | 349 命中全落 section；端到端 cstring 反查闭环 |
| callers_of vs capstone ground truth | 5/5 站点命中 |
| sign_manifest 正/反向 | Ed25519 签名经 PyNaCl 与 openssl pkeyutl 双路验签通过；RSA 密钥被明确拒绝 |
| gen_matrix → /tmp 与 docs/COMPATIBILITY.md | 逐字节一致（重构无行为漂移） |
| count_quarantined 双 CWD | 一致（86 条隔离） |
| merge_catalogs（单源在场） | 优雅跳过缺失源，输出写 /tmp 不碰仓库 config |
| decrypt_strings 全流程（系统 dylib） | 完整扫描路径跑通（0 串符合预期——无微信混淆循环） |
| contribute_expected --hashes | 切片哈希登记正确（/tmp 沙箱验证） |
| backfill read_bytes_at 单元 | __text/__DATA/越界/缺架构四路径全对 |

## 五、对外行为变化（使用者需知）

1. `decrypt_strings.py` 的 `func` 字段 VA 语义修正（见 A7）——历史 JSON
   请重跑刷新后再引用。
2. `contribute_expected.py` 回填长度 `max(len(asm), 8)`、expected 为数组
   形态（见 A4）。
3. `xref_x64.py` 新增 `--dylib`/`WXKEEP_X64_DYLIB` 覆盖输入路径；`xrefs`
   子命令首次真正可用（见 A6）。
4. `backfill_expected.py` 不再依赖 lipo 子进程；单坏归档跳过不中止（A2）。
5. `merge_catalogs.py` 结尾多一段替换决策报告（B3）。
