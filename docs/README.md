# 文档索引

> 三类文档：**现行契约**（当前行为的权威描述，维护必读）· **方法论与知识**（跨轮次复用的技术积累）· **历史档案**（决策过程记录，头部有状态标注，非现行行为依据）。

## 现行契约

| 文档 | 内容 |
|---|---|
| [COMPATIBILITY.md](COMPATIBILITY.md) | 123 构建双架构兼容矩阵（`tools/gen_matrix.py` 自动生成，勿手改） |
| [MAINTAINING.md](MAINTAINING.md) | 维护 SOP：新构建适配七步、发版策略、审计方法、踩坑记录 |
| [FMEA.md](FMEA.md) | 故障模式登记册：每行 = 模式 × 触发 × 防线 × 检出 × 测试。防线退化的回归清单 |
| [RUNTIME-DESIGN.md](RUNTIME-DESIGN.md) | 运行时组件设计：hook 谱系、三重身份门、双容器配置、安装链 |
| [3X-ACCEPTANCE-RUNBOOK.md](3X-ACCEPTANCE-RUNBOOK.md) | 3.x 真机行为验收 runbook（待用户窗口执行） |
| [KEY-ROTATION.md](KEY-ROTATION.md) | 签名配方代际知识：每代锚点特征与换代判定 |

## 方法论与知识

| 文档 | 内容 |
|---|---|
| [V7-DEPTH.md](V7-DEPTH.md) | 深度证明第四代：变换单群闭包（L15）/非合作崩溃矩阵（L16）/差分引擎孪生（L17）/目录自洽审计（L18）/台账复算门（L19） |
| [V6-DEPTH.md](V6-DEPTH.md) | 深度证明第三代：证明完备性穷举轮（L11-L14） |
| [V5-DEPTH.md](V5-DEPTH.md) | 深度证明第二代：指令级结构证明（L9）+ per-site 审计（125 轮） |
| [V3-DEPTH.md](V3-DEPTH.md) | 深度证明第一代：地面真值全扫/可逆性/确定性（L1-L6） |
| [ECOSYSTEM.md](ECOSYSTEM.md) | 生态与安全态势（2026-11-07 全网调研：竞品格局/Rosetta 时间线/DMCA 打击面） |

## 历史档案（决策记录，非现行行为依据）

| 文档 | 状态 |
|---|---|
| [V2-PLAN.md](V2-PLAN.md) | V2 立项计划——已被 [V2-PIVOT-DECISION.md](V2-PIVOT-DECISION.md) 裁决换道，保留为决策链 |
| [V2-PIVOT-DECISION.md](V2-PIVOT-DECISION.md) | V2 换道终裁（revokemessage 链=重编辑记账的实证） |
| [V4-REQUIREMENTS.md](V4-REQUIREMENTS.md) | V4 需求稿——对应能力已并入 V5/V6 深度体系 |
| [V3-CHARTER.md](V3-CHARTER.md) | **半现行**：v3（克隆消息行）立项书与 R2 翻案；M0-M4 进度以 ROADMAP 为准 |
| [WINDOWS-SPIKE.md](WINDOWS-SPIKE.md) | Windows 侦察轮档案——GO 决议后建设转入 wxkeep-core 独立仓库 |
| [T5-RUNBOOK.md](T5-RUNBOOK.md) | T5 真机验证 runbook——T5/T6 已关账，保留为实验方法范例 |
| [findings-269602-updater.md](findings-269602-updater.md) | 269602 更新器逆向发现——条目已入 catalog，档案化 |
| [related-tools-analysis.md](related-tools-analysis.md) | 2026-09/10 同类工具分析——生态快照已过时，现行判断以 [ECOSYSTEM.md](ECOSYSTEM.md) 为准 |
| [TOOLS-AUDIT.md](TOOLS-AUDIT.md) | tools/ 脚本审计记录（2026-09-19 时点） |
| [spike-verifier.md](spike-verifier.md) | verify worker 可行性 spike（M2-3）——结论已产品化 |

## 全局导航

- **逐轮迭代全史**：[ROADMAP.md](ROADMAP.md)（135 轮流水账 + 头部优先级队列）
- 用户可见行为以 README 为准；维护者流程以 MAINTAINING 为准；行为安全论证以 FMEA 为准。
