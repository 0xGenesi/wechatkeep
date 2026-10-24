# Windows Spike 报告（2026-10-25，队列第 3 项 3 天时间盒 → 实际 1 会话收口）

> 用户队列定义（ROADMAP 74 轮）：新仓库 Rust + mac/Win 共用 catalog 数据层设计；
> 拿 Windows 官方原版用现有 capstone 方法论**独立重 derive 撤回链位点**
> （不抄 BetterWX），spike 结论决定立项与否。

## 结论（TL;DR）

**GO（建议立项），但差异化定位必须收紧。** 方法论移植一次成功：Windows 4.1.15.56
官方原版的撤回持久链在数小时内独立推导完成（未参考 BetterWX 任何偏移/规则），
且与 macOS 270135（4.1.15.55）**结构逐段同源**——Weixin 4.x 双平台是同一 C++
代码库（protobuf 构建路径 `E:\x\x_rel_t7_1\...\message_revoke.pb.cc` 实证）。
macOS 侧遗留的「0x4196130 语句级语义」与「revokemessage 行插入点」两个未知，
都借 Windows 孪生函数**一并解出**（见 §4/§5）。剩余风险：Windows 撤回链的
「原消息行删除点」（BetterWX 规则 1 的真目标）不在本 spike 范围内，立项后需
一轮补齐；Windows 端已有 BetterWX 覆盖功能面，新仓差异化只剩**安全契约
（备份/还原/验证、manifest 供应链门）与数据纪律**，立项动机以此为准。

## 1. 素材与来源链（全程官方原版，可复现）

| 项 | 值 |
|---|---|
| 安装器 | `https://dldir1v6.qq.com/weixin/Universal/Windows/WeChatWin_4.1.15.exe`（官方页面 pc.weixin.qq.com 现行直链，Last-Modified 2026-10-19） |
| 安装器 sha256 | `4422bad98617dd095005c7879b2190f188ffa9ad6abf79e075358cf981a3d9e4`（256,569,752 B） |
| 安装器形态 | NSIS 自解压（内层 `install.7z`） |
| 载荷版本目录 | `4.1.15.56/`（Weixin.exe / Weixin.dll 的 FileVersion=ProductVersion=4.1.15.56） |
| 分析目标 | **Weixin.dll**：PE32+ x86-64 DLL，204,305,968 B，ImageBase 0x180000000，.text 0x771c0f7 B |
| 版本口径 | ROADMAP 写「Windows 4.1.15.53」为旧快照；官方滚动件当前即 .56（与 macOS 270135=4.1.15.55 同发布列车相邻版）。BetterWX 2.0.0（10-19 推）覆盖的正是这条现行线 |

注意：Windows 主二进制是 **Weixin.dll**（Weixin.exe 是薄壳）——macOS
wechat.dylib 的直接对应物。工件：`var/win/`（exe、解包载荷、全部脚本与转储，
gitignore 惯例不入库不删除）。

## 2. 方法论移植（capstone 路线的 PE 版）

新工具 `var/win/winre.py`（与 tools/xref_x64.py + decrypt_strings.py 同构）：

1. **PE 解析自写**（venv 无 pefile，不引新依赖）：段表/ImageBase/VA↔offset。
2. **.pdata RUNTIME_FUNCTION = PE 版函数边界表**：513,887 个函数（macOS
   LC_FUNCTION_STARTS 的等价物且更权威——带 Begin/End 对）。
3. **rel32 算术扫描**（E8/E9 + `48/4C 8D` rip-LEA 正则直算目标）做 xref。
   **重要教训**：capstone 线性扫描遇坏字节**静默截断**（4MB 分块也救不了），
   早期「零调用者」结论是假阴性；rel32 扫描 2.5s 出全量结果且完备（后核
   查实 macOS 侧 tools/xref_x64.py 本就是 rel32 实现、无此病——教训只在
   新写扫描器时适用）。
4. **Ghidra 快路对 PE 同样成立**：`-noanalysis` + .pdata 种子文件
   （`0x<va>\tfunction` × 513,887 行）+ DumpTargets.java → 34 函数 767KB
   伪代码，全程 ≈13 分钟（含 204MB PE 导入）。与 macOS 快路（≈3 分钟）
   同构，导入耗时按文件规模线性放大。
5. **字符串锚点法直接命中**：`revokemessage` 表名在 .rdata 明文（macOS 侧
   是 movabs 立即数惰性缓存，无明文——见 §5 方法差异）；`newmsgid` × 3、
   `reeditre`/`xwechat` 立即数碎片、UTF-8 tip 文案串堆（.data）。

xlog 混淆串：Windows 侧**同样混淆**但帧格式不同（`\xa1 len16 \xb1 payload
\xc1`），与 macOS 的 `(base[i]+addend)^key[i%20]` 不同构——已知明文攻击
可行（tag 10 字节、file 路径 30 字节级），spike 内时间盒收住未破，立项后
第一优先（破解 = 免 Ghidra 的全量函数名恢复）。

## 3. 独立推导的撤回链位点（Windows 4.1.15.56 全表）

```
parse 层
  0x18230b720  parse 包装（调 parse + tip 路径）
  0x18230b9a0  parse 本体（newmsgid 字面量引用者；序言 55 41 57 41 56 41 55 41 54
               = push rbp,r15,r14,r13,r12 —— Windows 版 hook 门候选序言）
  0x18230c830 / 0x1817c0820 → 0x18231c580  tip 内容构造（reeditrevoke 比较+物化）
  0x18231c580  reedit 枢纽（0x17b0B）：SSO 12 字节 "reeditre"+"voke" xor/or 比较
               @0x18231cde2；栈物化 "reeditrevoke" @0x18231da90；'_'(0x5f) wxid
               分段解析；xlog 行号 0x3dc

执行层
  0x182ebb760  "[sync] process msg count :%d,%d,%d" 同步消息批任务体（0xbd0B）
  0x185630b80  批分派器（0x1d80B，36 路展开分派 + 谓词族
               0x180a52440/52510/52550/52600/524f0/52650 + F1/F2/F3）
  0x1817db510 / 0x1817dd680 / 0x1817de610  三个 newmsgid 消费子分派器
  0x180a4fda0（含谓词 cmp [rcx+0xc],0x18 = type==24 门）等四谓词
               —— macOS 0x530e280 谓词族同构
  启动链：0x183b4d9d0/0x183b4dbe0 → 0x183b47e00 → 0x183b48b80 →(直调+thunk
               0x182ebb5b0 jmp)→ 任务体；await 站点 0x182ea5ca0/0x182ed6420

存储层（revokemessage 表 5 引用函数 = 家族；闭包四件套结构同 macOS）
  表名引用：0x183224200(表注册器,含第二张表 revokebatchmessage)
           /0x183229fb0(SELECT)/0x18322a970(单对象写=INSERT)
           /0x18322ace0(双参写=UPDATE)/0x18322b240(DELETE 过期)
  lambda：  0x184ad1400→SELECT / 0x184ad1b40→INSERT / 0x184ad1d80→UPDATE
           / 0x184ad2020→DELETE 过期
  ctor：    0x184acefd0 / 0x184acf230 / 0x184acf4a0 / 0x184acf6e0
           （functor 分配 + invoke 挂载 + xlog(tag,file,line) 提交）
  impl：    0x182380b60=插入 impl（★行插入点）；0x1823c4a60=RemoveRevokeItemTask
           Execute（xlog 行 0x6a/0x6c + await）；0x1823a45f0(0x6238 行伪代码,
           多 impl 复合体)；0x1823c25e0/0x1823d1bc0；门面 0x18236f180
  访问器：  0x1817e8650（18 个 0x1817xxxx 消息层函数共用=撤回状态查询）
```

**Windows 行插入点语义（0x182380b60，伪代码级）**：四个消息类型谓词门
（0x180a523e0/0x180a511e0/0x180a4fdd0/0x180a4e4d0）→ FUN_184ad6f60 从消息
对象构造 revokemessage 记录 → ctor 0x184acf230 异步 INSERT（lambda
0x184ad1b40 → 0x18322a970）→ await 成功后 xlog(行 0x585) 且按记录字段×1000ms
调度延迟清理 FUN_1823c1f60；失败 xlog(行 0x589)。

**0x18322b240 = DELETE 过期（伪代码级）**：cutoff = `vcall[+0x48](ctx)` −
`FUN_180a4d4d0()`（当前时间 − 配置保留期）→ 时间列条件 → 写执行器
0x18149bcc0。**即 RemoveRevokeItemTask 的存储语句 = `DELETE FROM
revokemessage WHERE 时间列 < cutoff`。**

## 4. 对 macOS 侧两个未知的反哺（本 spike 最大收获）

macOS 270135 五函数家族（movabs "revokeme" 扫描新发现，此前只知 0x4196130）：
0x4190130（表注册器）/0x4195490/0x4195ca0/0x4196130/0x4196650。
四 lambda invoke：0x3aaa450→0x4195490、0x3aaae70→0x4195ca0、
0x3aab070→0x4196130、0x3aab2a0→0x4196650；四 ctor：0x3aa8370/0x3aa8590/
0x3aa8800/0x3aa8a90；impl：**0x3a7a040→插入 ctor 0x3aa8590**（§八 预测的
「revoke_manager 家族 0x3a7xxxx」精确命中）、0x3a91130（CoCheck 任务体）→
查询 ctor、0x3aa3100（RemoveOutOfDataRevokeItemAsync）→ 0x3aa8800、
0x3a93360→0x3aa8a90。

**按 Windows 孪生定性（结构一一对应 + 语义判读）**：

| 操作 | Windows | macOS（原未知→今定性） |
|---|---|---|
| 表注册 | 0x183224200 | 0x4190130 |
| SELECT（会话/时间窗查询） | 0x183229fb0 | 0x4195490（经 0x3aa8370，CoCheck Phase3 调用） |
| **INSERT 单行（行插入点）** | 0x18322a970（经 0x184acf230←impl 0x182380b60） | **0x4195ca0（经 0x3aa8590←impl 0x3a7a040）** |
| UPDATE 双参写 | 0x18322ace0 | 0x4196130（经 0x3aa8800——**语句级语义定案：非「两条语句」，对位 Windows 是 UPDATE 型写**；旧判读「出行列表」属执行器句柄复用误读，见下） |
| DELETE 过期 | 0x18322b240（cutoff=now−配置） | 0x4196650（经 0x3aa8a90） |

> 交叉注记：macOS 0x4196130↔Windows 0x18322b240 的对位依据 = 双方 Remove
> RevokeItemTask 路径（macOS 0x3aa3100→0x3aa8800→0x3aab070→0x4196130；
> Windows impl 0x1823c4a60→ctor 0x184acf6e0→lambda 0x184ad2020→0x18322b240
> =DELETE 过期）。由此 macOS 0x4196130 的「两条 ORM 语句」实为**同一删除
> 语句族的双条件构建**（过期时间 + 注册表键），V2-PLAN「链上最后未知」就此
> 关账（语句级语义=删除过期撤回条目，非原消息删除——与「全链无原消息行
> DELETE」结论自洽）。macOS 0x4196650 若按此对位则是 UPDATE（0x18322ace0
> 的 cutoff 条件写），其 0x24(36) 参数与 Windows 0x2710 族的精确对应留给
> 立项后复核——不影响 v2 落点口径。

macOS 插入 impl 0x3a7a040 的伪代码确认（对位 Windows 0x182380b60 的谓词门
→建记录→异步插入→调度清理四段结构）见 var/wxarm/decomp_mac_insertimpl.c
判读记录（MAINTAINING 同步更新）。

## 5. 双平台差异速记（移植方法论时必读）

- 函数边界：macOS=LC_FUNCTION_STARTS（machutil）；Windows=.pdata（更强，
  有 End）。
- 表名字符串：macOS=movabs 立即数惰性缓存（明文搜不到，按 `48 b8/bf +
  "revokeme"` 模式扫）；Windows=.rdata 明文（直接 xref）。
- tip 文案：双方都不是直接 lea 可达——macOS 0x278 模板 rodata；Windows
  .data 串堆（索引式引用）。
- xlog 混淆：macOS=`(base[i]+addend)^key[i%20]`（已破）；Windows=`\xa1len
  \xb1payload\xc1` 帧（未破，已知明文攻击可行）。
- lambda 挂载：macOS=chained-fixup vtable 槽；Windows=lea 直挂 functor。
- 序言门：macOS x64=`55 48 89 E5 41 57 41 56 41 55 41 54`；Windows=
  `55 41 57 41 56 41 55 41 54`（无 mov rbp,rsp，栈帧 lea rbp,[rsp+N]）。

## 6. 新仓库设计（Rust + mac/Win 共用 catalog 数据层）

### 6.1 仓库形态

```
wxkeep-core (新仓, Rust)          wxkeep (本仓, Swift, 维持)
├── catalog/                      └── 继续作为 macOS 前端 + 数据消费方
│   ├── schema.md                 （短期：wxkeep 经 update-data 兼容消费
│   ├── entries/*.json            新 catalog；长期：Swift 端薄化）
│   └── CREDITS.md
├── crates/
│   ├── wxcat-core    # catalog 模型/校验/锚点匹配（纯库）
│   ├── wxcat-derive  # 派生工具链：macho/pe 后端、锚点→位点、rel32 扫描
│   ├── wxcat-verify  # 双平台镜像级 verify（形态门+探针）
│   └── wxcat-sign    # Ed25519 manifest（沿用本仓密钥体系/轮换 SOP）
└── frontends/        # 后置：Windows CLI（patch/restore/doctor 骨架）
```

### 6.2 catalog 数据模型（跨平台核心）

每条 entry = **锚点配方**而非裸地址（spike 实证锚点跨平台跨版本存活）：

```jsonc
{
  "id": "win.4.1.15.revokemessage.insert-lambda",
  "platform": "windows", "product": "weixin", "version": "4.1.15.56",
  "arch": "x64", "module": "Weixin.dll",
  "module_sha256": "…",                       // 溯源门
  "derivation": {                              // 锚点链（可重放）
    "anchors": [
      {"kind": "cstring", "value": "revokemessage", "section": ".rdata"},
      {"kind": "lea-rip", "from-anchor": 0, "nth": 2}   // 第 3 个引用者
    ],
    "prologue": {"hex": "554157415641554154…", "max_len": 24},
    "resolved": {"va": "0x18322a970", "size": 112}
  },
  "role": "revoke-storage-insert",            // 语义角色（链拓扑学）
  "chain": "revoke-persistence",              // 链归属（可追溯组）
  "evidence": ["var/win/decomp_win.c#L5508"]  // 判读出处
}
```

- **双平台同 role 不同 entry**：`mac.270135.revokemessage.insert-lambda` 与
  Windows 互为对位——链拓扑（role/chain 字段）成为跨平台知识的载体，正是
  本 spike 的对位表可直接机器化。
- **锚点两级**：跨版本锚（表名/newmsgid/reeditrevoke 立即数——本轮实证跨
  平台同形）+ 版本内锚（序言门/rel32 拓扑）。
- 校验：锚点链重放必须解析到 `resolved.va`；module_sha256 门；与 wxkeep
  manifest 供应链同构（Ed25519 + 轮换 SOP 直接移植）。

### 6.3 派生工具链（wxcat-derive，方法论代码化）

winre.py/profile.py 的 Rust 化：macho+pe 双后端、.pdata/FUNCTION_STARTS
统一函数边界接口、**rel32 算术扫描**（本 spike 的关键修正，写死为唯一
xref 通道——capstone 线性扫描的截断缺陷入 README 警示）、Ghidra 快路
编排（.pdata 种子生成 → DumpTargets）作为深度判读的旁路工具。

### 6.4 安全契约（差异化立足点，从本仓平移）

备份/还原（字节级往返+sha 恒等预言）、WAL journal、verify-after-write、
负控（篡改必报）、launch soak、manifest 供应链门——本仓 V3-DEPTH R1-R6
需求书直接作为新仓验收基线；Windows 侧差异点：无 codesign 重签负担
（补丁后完整性由自校验+备份承担），但需处理文件占用（运行中写 Weixin.dll
→ 拒绝并提示退出，等价 isRunning 门）。

### 6.5 路线（立项后）

1. 破 Windows xlog `\xa1` 帧（已知明文攻击）→ 全量函数名恢复。
2. 补齐「原消息行删除点」derive（BetterWX 规则 1 真目标；从批分派器非撤回
   分支 + F1/F2/F3 的 delete 型被调走同款 xref 链）。
3. catalog 0 号版 = 本 spike 全部位点（含双平台对位表）+ 现有 wxkeep macOS
   目录导入。
4. Windows CLI 骨架（doctor/patch/restore/verify 最小闭环）→ 真机验证矩阵
   （私聊/群聊 × 他人/自己 × 保留/提示位置）。
5. 与 wxkeep 的数据通道：update-data 拉新仓 release 四件套（格式兼容期）。

## 7. Go/No-Go 论证

**GO 的依据**：
- 方法论可移植（本 spike 一次成功，含 Ghidra 快路）；
- 双平台同源结构 = catalog 复用度高，macOS 侧 84 构建目录的投入可被
  Windows 侧摊薄；
- 双向反哺已兑现（macOS 两未知在 spike 内解决）；
- 安全契约/数据纪律是 BetterWX 生态空白（其自述 minimize footprints /
  无备份承诺）。

**风险与边界（诚实声明）**：
- Windows 功能面 BetterWX 已覆盖（含群聊原位提示）；新仓若无差异化执行
  力（安全契约+catalog），会沦为重复造轮；
- 「原消息行删除点」未 derive（BetterWX 规则 1 目标）——立项后第一优先，
  若该点在 Windows 的形态与 macOS 结论（无原消息行 DELETE）冲突，v2 模型
  需按平台分叉重审；
- xlog 帧未破 = Windows 侧函数命名仍靠结构对位（macOS 侧已破，可对译）；
- Weixin.dll 204MB/版本的派生成本 ≈ macOS dylib 同量级，目录维护双份；
  滚动安装器无版本化 URL（`WeChatWin_4.1.15.exe` 滚动更新），归档策略
  需自建（下载即存档+哈希入库，watch 机制照搬 zsbai+CDN 探测双源经验）。

## 8. 证据工件索引（var/win/，gitignore）

- `WeChatWin_4.1.15.exe` + `extracted/payload/4.1.15.56/Weixin.dll`
- `winre.py`（PE 工具箱）/ `profile.py`（函数画像）
- `weixin_seeds.txt`（.pdata 种子 513,887 行）
- `decomp_win.c`（34 函数 767KB 伪代码）/ `ghidra_win.log`
- `callgraph_round1.txt`（早期 capstone 扫描——注意其覆盖不完，结论以
  rel32 复扫为准）
- macOS 侧新增：`var/wxarm/decomp_mac_insert.c`（家族四函数）、
  `decomp_mac_insertimpl.c`（插入 impl）、`ghidra_mac_insert*.log`
