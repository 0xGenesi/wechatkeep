# 冒烟 Runbook（137 轮方案 v2：一场 10 分钟关三项用户窗口；141 轮修订）

> 方案 v2 依据见 ROADMAP 137 节与 RUNTIME-DESIGN「R18 合成触发边界」：
> 真实撤回事件的唯一不可合成产出 = 渲染层肉眼结果（机读代理 = calibrate
> 产品面计数）；仪器校准与 M4 采样随同一事件自动落账。

## 前置（一次性确认，命令各一条）

    wxkeep doctor              # overall=protected / hook=已武装
    wxkeep runtime status      # mr2=hook-armed；dylib 版本行 ✓（见下方红线）

> **141 轮红线（前置新增）**：`runtime status` 的 **dylib 版本行**必须显示
> `= 0.2.19 ✓（与 CLI 同版）`。显示「无自标识串（141 轮前旧件）」或任何
> ≠ 当前 CLI 的版本 = **在役 dylib 含 keyctor 崩溃面（140 续③ 真机
> SIGSEGV 事故件）**——先重装再开实验：
>
>     wxkeep runtime remove && wxkeep runtime install   # 重装后重启微信
>     wxkeep runtime clone on                            # 再开实验开关
>
> `runtime install` 本身也会按版本自标识拒装旧件（141 轮装面版本门）；
> `runtime clone on` 对旧件在役会 ⚠️ 告警——两道门都别绕过。
>
> **源码用户二进制路径红线**：brew 在役 CLI 是 0.2.17（141 轮前的旧件，
> **自身没有版本门也不认识新 dylib 串**）——`sudo wxkeep …` 会静默用旧
> CLI 装新 dylib（或用旧数据行装机）。装面一律用仓库构建件：
>
>     cd ~/dev/github/wechatkeep
>     sudo .build/release/wxkeep runtime remove
>     sudo .build/release/wxkeep runtime install
>
> 0.2.19 发版（tag + tap bump）后 `brew upgrade wxkeep` 才换回 `wxkeep`
> 短命令。装完用 `wxkeep runtime status`（**同一路径的 0.2.19 CLI**）核对
> dylib 版本行 = 0.2.19 ✓ 再进主冒烟。

## 主冒烟（约 5 分钟）

1. 终端起校准窗（保持运行）：

       mkdir -p var/logs
       wxkeep runtime calibrate --window 120 --json --label smoke-$(date +%m%d) | tee var/logs/smoke.json
       # 窗口 120s 内完成下面动作

2. **小号 → 本机大号**：私聊发一条文本（如 `smoke-<日期>`）→ 撤回。
3. 肉眼确认（合成事件唯一替代不了的格子）：
   - 原消息**仍在**（保留生效）；
   - 灰条 tip「…撤回了一条消息」（keeptip 生效）。
4. 校准窗结束，读判读（期望态）：

       ✓ 保留动作 +1（消息保留已实证——产品面）
       ✓ 克隆证据链：clone=+1 …（链路被真实事件驱动）
       summary: product+instrument（product=true instrument=true reset=false）

   - `clpub=+1` 行出现 = **M4 认证采样可行**（r8pub bootlog 行携带
     subvt/msgvt 切片偏移——pub_vt 派生输入到手，M4 实弹就此关案）；
     px0 行的 `view=1/2` 标注 r8pub 读的是主/第二接口视图（141 轮新增，
     pub_vt 派生前必看）；
   - `clkey=+1` 而 `key=<miss>` px0 行 = lu 键快照失败（keyptr 陈旧/短串
     形态）——把该行整行贴回（`lu_keyptr=`/`lu_kflag=` 即诊断面，141 轮
     新增）；克隆链此时安全退出（clmissq），不会再有旧版的崩溃形态；
   - 若 selfskip=+1 而产品面零：撤回发起方是本机自己（selfskip 门拦）
     ——换小号发起重跑。

## 顺手同场关案（各一条命令/一次动作）

- **R11① 类裁决（141 轮改口径）**：px0 行的 `src=` 字段裁决 svc 发现路径
  （lu/cm/cand/scan）——args[0]=consumer 的原始假设 117 轮已证伪，现行
  判读看 `clsvc2`/`clmissq` 增量 + px0 `src=`（计数面：parse 链计 clsvc2；
  `clsvc` 属写点缝，270135 实弹零触发）。
- **x2desc 修复验证**（138 轮已修真值 0xa3dea24，微信重启后生效）：
  校准判读出现 `clhit`/`clinner` 增量 = rd 读链真机全通（此前 clmissq
  13 连 miss 的悬案随之关闭）。
- 群聊口径（可选）：小号在群内发→撤回，确认消息保留（群聊 tip 不渲染
  = V3-M0 已知边界，非缺陷）。

## 3.x 五格（独立窗口，格 1/2/5 三次撤回 + 两条命令）

见 [3X-ACCEPTANCE-RUNBOOK.md](3X-ACCEPTANCE-RUNBOOK.md)（137 轮机械化：
格 3/4 = verify 字节证明替代、多开一条命令）。

## 登记回传

- `smoke.json`（机读账本）+ 肉眼两格结果（保留/tip）贴回仓库 issue 或
  直接告知——登记入 ROADMAP，M4 采样与 svc 发现路径裁决就此关案。

## 已知边界（非缺陷）

- 自撤不克隆（selfskip 门，T5 F1）——发起方必须是他号；
- 群聊 tip 不渲染（V3-M0 定案：渲染期从 +0x278 载荷生成，清零后行查
  找不命中）——群聊消息保留不受影响；
- clone 证据链为实验面（`clone_message` 开关控制），产品面 keep/tip
  不依赖它；键快照失败只影响该次重查（clmissq），无副作用。
