# 冒烟 Runbook（137 轮方案 v2：一场 10 分钟关三项用户窗口）

> 方案 v2 依据见 ROADMAP 137 节与 RUNTIME-DESIGN「R18 合成触发边界」：
> 真实撤回事件的唯一不可合成产出 = 渲染层肉眼结果（机读代理 = calibrate
> 产品面计数）；仪器校准与 M4 采样随同一事件自动落账。

## 前置（一次性确认，命令各一条）

    wxkeep doctor              # overall=protected / hook=已武装
    wxkeep runtime status      # mr2=hook-armed；clone_message 已开（实验开关）

## 主冒烟（约 5 分钟）

1. 终端起校准窗（保持运行）：

       wxkeep runtime calibrate --window 120 --json --label smoke-$(date +%m%d) | tee var-logs/smoke.json
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
   - 若 selfskip=+1 而产品面零：撤回发起方是本机自己（selfskip 门拦）
     ——换小号发起重跑。

## 顺手同场关案（各一条命令/一次动作）

- **R11① 裁决**（clone 链 args[0]=consumer 门）：主冒烟的真实事件同时
  驱动 clone worker——`wxkeep runtime status` 的 `clsvc`/`clmissq` 增量
  + bootlog `px0` 行即裁决（vtable 门命中 = args[0] 假设成立）。
- **x2desc 修复验证**（138 轮已修真值 0xa3dea24，微信重启后生效）：
  校准判读出现 `clhit`/`clinner` 增量 = rd 读链真机全通（此前 clmissq
  13 连 miss 的悬案随之关闭）。
- 群聊口径（可选）：小号在群内发→撤回，确认消息保留（群聊 tip 不渲染
  = V3-M0 已知边界，非缺陷）。

## 3.x 五格（独立窗口，格 1/2/5 三次撤回 + 两条命令）

见 [3X-ACCEPTANCE-RUNBOOK.md](3X-ACCEPTANCE-RUNBOOK.md)（137 轮机械化：
格 3/4 = verify 字节证明替代、多开一条命令）。撤回计数同样可用
`runtime calibrate` 留痕。

## 登记回传

- `smoke.json`（机读账本）+ 肉眼两格结果（保留/tip）贴回仓库 issue 或
  直接告知——登记入 ROADMAP，M4 采样与 R11① 裁决就此关案。

## 已知边界（非缺陷）

- 自撤不克隆（selfskip 门，T5 F1）——发起方必须是他号；
- 群聊 tip 不渲染（V3-M0 定案：渲染期从 +0x278 载荷生成，清零后行查
  找不命中）——群聊消息保留不受影响；
- clone 证据链为实验面（`clone_message` 开关控制），产品面 keep/tip
  不依赖它。
