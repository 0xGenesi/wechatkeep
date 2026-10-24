# 发布密钥轮换预案（V3-DEPTH §5 / D7 承诺项）

> 2026-10-24 成文。适用范围：`manifest.json` + `manifest.sig` 的 Ed25519
> 签名体系（守护 config.json / signatures.json 供应链，见
> [V3-DEPTH.md](V3-DEPTH.md) D7 与 README 安全模型第 8/9 条）。

## 1. 密钥资产清单（轮换必须全部同步的位点）

| 资产 | 位置 | 入库 |
|---|---|---|
| 私钥 PEM | `keys/release.key`（Ed25519，openssl 生成） | **否**（.gitignore；CI 侧从未存在过） |
| 公钥 raw 32B（base64） | `keys/release.pub` | 是 |
| 公钥内嵌常量 | `Sources/wxkeep/Manifest.swift` → `releasePublicKeyB64` | 是 |
| 签名工具 | `tools/sign_manifest.py`（PyNaCl/openssl 签名，`--key` 传私钥路径） | 是 |
| 三方互证 | `tools/verify_manifest_openssl.sh`（openssl pkeyutl，读 `keys/release.pub`） | 是 |
| 验签消费方 | ① `wxkeep manifest`（CryptoKit）② `Config.load` 隐式 config 硬门 ③ `wxkeep update-data`（OTA 验签后原子安装） | — |

只换一处 = 半套密钥态：旧公钥验新签（或反之）恒 `.invalid`，数据被自家的
门拒载。轮换 checklist 的验收步骤专门防这个。

## 2. 何时轮换（触发条件）

- **疑似泄露**（最高优先级）：私钥文件出现在非受控位置（git 历史、issue
  附件、截图、备份盘）、签名机失守、或 manifest 出现非本方签署的有效签名。
- **例行轮换**：签名机更换 / 长期项目卫生（建议 ≥2 年一次，非必须——
  Ed25519 无算法性到期）。
- **不需要轮换**：仅仅新增受保护文件（改 `PROTECTED` 列表后重签即可）、
  发版、tap 同步。

## 3. 硬切换语义（先想清楚的诚实边界）

当前是**单公钥内嵌**架构（schema 1）：`Manifest.releasePublicKeyB64` 编译
进二进制。轮换 = 新公钥随**下一次 CLI 发版**生效，没有平滑过渡：

- 切换后首个以新钥签署的 catalog 一旦发布，**旧版本 CLI 的
  `wxkeep update-data` 验签失败**（明确报错，不静默——这是设计内行为：
  宁可拒绝也不消费无法证明来源的数据）。用户指引：升级 wxkeep（brew
  upgrade / 下载新 release）后重跑 `wxkeep update-data`。
- 随二进制分发的隐式 config 不受影响：每个版本的 manifest/sig 与其内嵌
  公钥同源同批发布，自洽。
- 因此例行轮换应**贴着正常发版节奏**做（见 §4 步骤 8），把用户可见的
  update-data 窗口期缩到一次 brew upgrade 的成本。
- 若未来需要零中断过渡，再立项 schema 2 双签 manifest（`signatures:
  [{key_id, sig}, …]`，客户端对内嵌键列表逐一尝试）——设计占位记录于
  §6，当前不实现。

## 4. 轮换步骤（例行）

前置：私钥在手（`keys/release.key` 可验：能对当前 manifest 验出有效签名）；
工作区干净；`swift test` 基线绿。

1. **生成新钥对**（不覆盖旧钥，并行存放便于回退）：
   ```bash
   openssl genpkey -algorithm ed25519 -out keys/release.key.new
   openssl pkey -in keys/release.key.new -pubout -outform DER \
     | tail -c 32 | base64 > keys/release.pub.new
   # release.pub.new 应为 44 字符 base64（raw 32B），与旧文件同形制
   ```
2. **替换位点到新钥**：`keys/release.key.new → keys/release.key`、
   `release.pub.new → release.pub`、`Manifest.swift` 的
   `releasePublicKeyB64` 换成新值（一行常量，注释已写明轮换语义）。
3. **重签**：`python3 tools/sign_manifest.py --key keys/release.key`
   （重签后 `git diff` 应只见 manifest.sig + generated_at 变化；config/
   signatures 本体不动）。
4. **三方互证**（缺一不可）：
   ```bash
   bash tools/verify_manifest_openssl.sh        # openssl 家族
   swift build -c release && .build/release/wxkeep manifest   # CryptoKit 家族
   # PyNaCl 家族由 sign_manifest --dry-run 输出覆盖（第三实现）
   ```
5. **回归**：`swift test`（Manifest 测试用参数化公钥，不依赖具体键值；
   全绿证明换常量未破坏验证逻辑）。
6. **旧钥退场**：确认新钥链全绿后，离线保存旧钥至少一个版本周期（回退
   通道：若新链发现自损，旧钥可重签回滚 catalog），然后安全删除。
7. **git 卫生断言**：`git log --all --full-history -- keys/release.key`
   必须为空（任何时候都该成立；轮换时顺手复核）。
8. **发版收尾**：按 ROADMAP 队列的正常发版流程（tag → release 流水线
   挂 manifest 四件套 → Formula 哈希复算 → tap 同步）。发布说明里必须
   写明「发布密钥已轮换，旧版 update-data 需升级后使用」。

## 5. 紧急轮换（疑似泄露）

与 §4 的差异（压缩流程，目标是**先切断信任再补发**）：

1. 立即用新钥重签并推送 catalog（走 update-data 通道分发新公钥无法做到
   ——公钥在二进制里；这一步只是让「泄露的旧钥」签不出能被新链接受的
   数据，前提是用户已升级，见下）。
2. **最高优先级发版**（含新公钥常量），并在 README/release notes 置顶
   升级指引。
3. 发布 `wxkeep doctor` 侧的可观察信号（如后续版本给 manifest 状态加
   key_id 显示，帮助用户自查处于哪条信任链——当前 schema 1 无 key_id，
   记录为 schema 2 动机之一）。
4. 事后取证：git 历史、签名机审计、泄露面评估，写入 ROADMAP 存档。
   诚实边界：内嵌公钥架构下，泄露窗口内旧钥签署的恶意 catalog 对
   **未升级用户**仍然有效——这是该架构的已知残余风险（V3-DEPTH D7
   已记录），缓解 = 用户升级 + 泄露发现速度。

## 6. schema 2 双签过渡（设计占位，未实现）

- manifest 增 `key_id` 与签名数组；客户端 `releasePublicKeyB64` 变
  `[(keyId, b64)]`，验证 = 任一内嵌键对任一签名成立。
- 过渡流程：先发「同时信任新旧两键」的 CLI → 双签一个版本周期 → 收窄
  单签（新）→ 再发「只信新键」的 CLI。
- 触发立项条件：真实用户基数大到「一次 brew upgrade」成为可感知中断，
  或紧急轮换发生一次之后复盘。

## 7. 验收清单（每次轮换逐项打勾）

- [ ] `keys/release.pub` 与 `Manifest.releasePublicKeyB64` 同值（base64
      raw 32B，44 字符）
- [ ] `sign_manifest.py` 用新钥出签，`git status` 只见 manifest 两文件变化
- [ ] openssl / CryptoKit / PyNaCl 三方验签全过
- [ ] `swift test` 全绿
- [ ] `git log --all --full-history -- keys/release.key` 为空
- [ ] 发布说明含轮换告示；tap Formula 哈希按新 release 资产复算
