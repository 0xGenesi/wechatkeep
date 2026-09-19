# 版本兼容矩阵

> 由 `tools/gen_matrix.py` 从 config.json 自动生成，请勿手改。
> `arm64/x86_64` = 该架构有条目；`⚠︎` = 条目缺 expected 溯源字节（默认隔离，需补验后放行）。

| 构建号 | 微信版本 | 防撤回(silent) | keeptip | keeptip2 | 屏蔽更新 | 多开 | 备注 |
|---|---|---|---|---|---|---|---|
| 270100 | 4.1.15 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270099 | 4.1.15.19 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270098 | 4.1.15.18 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270097 | 4.1.15.17 | x86_64/arm64 | — | — | — | — |  |
| 270096 | 4.1.15.16 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270095 | 4.1.15.15 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270094 | 4.1.15.14 | x86_64/arm64 | — | — | — | — |  |
| 270093 | 4.1.15.13 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270091 | 4.1.15.11 | x86_64/arm64 | x86_64 | — | x86_64 | — |  |
| 270090 | 4.1.15.10 | arm64 | arm64 | — | arm64 | — | merged from fzlzjerry/wechat-antirecall (runtime-tip trampolines excluded) |
| 269631 | 4.1.13.63 | x86_64/arm64 | arm64 | — | arm64 | x86_64 | 2 entries lack expected bytes (quarantined) |
| 269629 | 4.1.13 | x86_64 | — | — | — | x86_64 | 2 entries lack expected bytes (quarantined) |
| 269628 | ? | arm64 | arm64 | — | arm64 | — | merged from fzlzjerry/wechat-antirecall (runtime-tip trampolines excluded) |
| 269627 | 4.1.13 | arm64 | arm64 | — | arm64 | — |  |
| 269626 | 4.1.13 | arm64 | arm64 | — | — | — |  |
| 269624 | 4.1.13 | arm64 | arm64 | — | arm64 | — |  |
| 269619 | 4.1.13 | arm64 | arm64 | — | arm64 | — |  |
| 269602 | 4.1.13 | x86_64/arm64 | x86_64/arm64 | x86_64 | x86_64/arm64 | arm64 |  |
| 269579 | 4.1.13 | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269578 | 4.1.13 | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269577 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269576 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269575 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269574 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269365 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269341 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269340 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269338 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269337 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269335 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269334 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269333 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269332 | ? | arm64 | arm64 | — | arm64 | — |  |
| 269136 | 4.1.11 | arm64 | arm64 | — | — | — |  |
| 269111 | 4.1.11 | x86_64/arm64 ⚠︎ | arm64 | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269110 | 4.1.11 | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269079 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 269077 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268880 | 4.1.10 | arm64 | — | — | — | — |  |
| 268851 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268850 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268849 | ? | arm64 | arm64 | — | arm64 | — |  |
| 268831 | ? | x86_64/arm64 ⚠︎ | arm64 | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268602 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268601 | ? | arm64 | arm64 | — | arm64 | — |  |
| 268599 | ? | arm64 | arm64 | — | arm64 | — |  |
| 268597 | ? | arm64 | arm64 | — | arm64 | — |  |
| 268596 | ? | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 268575 | 4.1.10 | x86_64/arm64 ⚠︎ | arm64 | — | arm64 | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 37342 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 37335 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 37331 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 37303 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 37293 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 36677 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 36603 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 36559 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 34817 | ? | x86_64 ⚠︎ | — | — | — | x86_64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 34371 | 4.1.5 | arm64 ⚠︎ | — | — | — | arm64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 33480 | ? | x86_64/arm64 | — | — | — | — | 4.1.6 夹缝构建（revoke 在主程序，桩代布局）；VA 含 PIE 基址 0x100000000 |
| 32288 | 3.8.x | arm64 ⚠︎ | — | — | — | arm64 ⚠︎ | 8 entries lack expected bytes (quarantined) |
| 32281 | 3.8.x | arm64 ⚠︎ | — | — | — | arm64 ⚠︎ | 8 entries lack expected bytes (quarantined) |
| 31960 | 3.8.x | arm64 ⚠︎ | — | — | — | arm64 ⚠︎ | 2 entries lack expected bytes (quarantined) |
| 31927 | 3.8.x | arm64 ⚠︎ | — | — | — | arm64 ⚠︎ | 8 entries lack expected bytes (quarantined) |

共 64 个构建号。未知构建号可用 `wxkeep locate` / patch 时的 auto-locate 自动适配（配方签名代不变时）。
