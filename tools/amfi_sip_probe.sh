#!/bin/bash
# amfi_sip_probe.sh — AMFI 原生 SIP 实证协议（ROADMAP 决策 #1 的收口实验）
#
# 问题：wxkeep 的「字节补丁 + ad-hoc 重签（保留全部 restricted entitlements +
#       注入 disable-library-validation / allow-unsigned-executable-memory）」
#       在原生 SIP（csrutil enabled、无 amfi boot-arg）下，微信能否正常启动？
#
# 判据（与 ROADMAP 约定一致）：
#   RUNS       补丁态微信存活 → 维持 doctor 的 watch 级判定（主流工具同配置可跑）
#   KILLED     启动即死且 .ips 显示 Namespace CODESIGNING → 恢复旧 kill_predicted 判定
#   OTHER-KILL 启动即死但非 CODESIGNING → 附上终止原因，人工定性
#   INCONCLUSIVE 环境不满足/证据不足 → 不改判定
#
# 协议：pristine 快照 → 标准 patch（完整 Resigner 管线）→ codesign 自检 →
#       启动 → 观测 ≤25s → 采集 .ips → **无条件恢复 pristine**（trap 保证）。
#
# 用法（必须在原生 SIP 已启用的系统上、以 sudo 运行）：
#   sudo tools/amfi_sip_probe.sh [--wxkeep /path/to/wxkeep] [--variant keeptip]
#                                [--allow-sip-off]   # 仅排练脚本机制，结论无效
#   结果写入仓库 var/amfi_probe/（verdict.json + 前后 doctor 快照 + .ips；
#   /tmp 会被清——重要工件一律落项目目录）
#
# 原生 SIP 引导 runbook（本机当前 SIP off + amfi_get_out_of_my_way=0x1）：
#   1. sudo nvram -d boot-args          # 先删 AMFI bypass（否则 SIP on 下仍无效）
#   2. 重启进 Recovery（Intel: Cmd+R）→ csrutil enable → 重启
#   3. sudo tools/amfi_sip_probe.sh     # 一键实证
#   4. （可选恢复研究环境）Recovery → csrutil disabled →
#      sudo nvram boot-args="amfi_get_out_of_my_way=0x1" → 重启
#   注意：SIP on 期间 verify worker（RWX）不可用，属预期。
set -uo pipefail

WXKEEP="${WXKEEP:-}"
VARIANT="keeptip"
ALLOW_SIP_OFF=0
OUT="$(cd "$(dirname "$0")/.." && pwd)/var/amfi_probe"
APP=/Applications/WeChat.app
WATCH_S=25

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wxkeep) WXKEEP="$2"; shift 2 ;;
    --variant) VARIANT="$2"; shift 2 ;;
    --allow-sip-off) ALLOW_SIP_OFF=1; shift ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

# 定位 wxkeep：参数 > 仓库构建产物 > PATH（PATH 里可能是旧版——
# 排练实证：旧版目录无 270099 keeptip 条目会让 patch/restore 双失败）
if [[ -z "$WXKEEP" ]]; then
  if [[ -x "$(dirname "$0")/../.build/debug/wxkeep" ]]; then WXKEEP="$(dirname "$0")/../.build/debug/wxkeep"
  elif [[ -x "$(dirname "$0")/../.build/release/wxkeep" ]]; then WXKEEP="$(dirname "$0")/../.build/release/wxkeep"
  elif [[ -x "$(dirname "$0")/../wxkeep" ]]; then WXKEEP="$(dirname "$0")/../wxkeep"
  elif command -v wxkeep >/dev/null 2>&1; then WXKEEP="$(command -v wxkeep)"
  else echo "wxkeep not found (pass --wxkeep)"; exit 2; fi
fi

if [[ $EUID -ne 0 && ! -w "$APP/Contents/MacOS/WeChat" ]]; then
  echo "must run with sudo (bundle not writable by current user)"; exit 2
fi
mkdir -p "$OUT"

log()  { printf '\033[1;37m[probe]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[probe]\033[0m %s\n' "$*" >&2; }

# ---------- Phase 0: preflight ----------
log "phase 0: preflight"
SIP=$(csrutil status)
BOOTARGS=$(nvram boot-args 2>/dev/null || true)
log "SIP: $SIP"
log "boot-args: ${BOOTARGS:-<none>}"

if [[ "$ALLOW_SIP_OFF" -ne 1 ]]; then
  echo "$SIP" | grep -q "enabled" || { fail "SIP not enabled — this run would prove nothing. Use the Recovery runbook in the header, or --allow-sip-off to rehearse mechanics."; exit 3; }
  echo "$BOOTARGS" | grep -q "amfi_get_out_of_my_way" && { fail "amfi_get_out_of_my_way present — AMFI is bypassed; not a native-SIP test."; exit 3; }
else
  log "⚠️  --allow-sip-off: rehearsal mode, verdict will be INCONCLUSIVE"
fi

if pgrep -x WeChat >/dev/null 2>&1; then
  fail "WeChat is running — quit it first (this probe launches and restores WeChat)."
  exit 3
fi

"$WXKEEP" doctor --json > "$OUT/doctor_before.json" 2>&1 || true
log "doctor snapshot → $OUT/doctor_before.json"

# ---------- 恢复保障：无论如何回到 pristine ----------
restore_all() {
  log "cleanup: restoring pristine + quitting WeChat"
  osascript -e 'tell application "WeChat" to quit' >/dev/null 2>&1 || true
  sleep 2
  pkill -x WeChat >/dev/null 2>&1 || true
  "$WXKEEP" restore >/dev/null 2>&1 || fail "RESTORE FAILED — run '$WXKEEP restore' manually and check!"
  codesign --verify --deep --strict "$APP" >/dev/null 2>&1 \
    && log "pristine bundle signature: OK" \
    || fail "post-restore codesign verify FAILED — inspect $APP"
}
trap restore_all EXIT

# ---------- Phase 1: baseline pristine ----------
log "phase 1: ensure pristine baseline"
"$WXKEEP" restore >/dev/null 2>&1 || true

# ---------- Phase 2: standard patch（完整重签管线）----------
log "phase 2: patch (variant=$VARIANT, full Resigner pipeline)"
"$WXKEEP" patch --variant "$VARIANT" | tee "$OUT/patch.log" || { fail "patch failed"; exit 4; }

# ---------- Phase 3: 签名自检 ----------
log "phase 3: codesign self-check"
if codesign --verify --deep --strict --verbose=2 "$APP" > "$OUT/codesign_verify.log" 2>&1; then
  log "codesign --verify --deep --strict: OK"
else
  fail "patched bundle failed codesign --verify (pipeline bug, not an AMFI question)"
  exit 4
fi
codesign -dvv "$APP/Contents/MacOS/WeChat" > "$OUT/codesign_dvv.log" 2>&1 || true

# ---------- Phase 4: 启动观测 ----------
log "phase 4: launch + observe (${WATCH_S}s)"
IPS_DIR="$HOME/Library/Logs/DiagnosticReports"
declare -i before_ips
before_ips=$(ls -1 "$IPS_DIR" 2>/dev/null | grep -ci '^WeChat-.*\.ips$' || true)
log "existing WeChat .ips count: $before_ips"

open -a "$APP"
T0=$(date +%s)
VERDICT="INCONCLUSIVE"; DETAIL=""
alive_at=0
while (( $(date +%s) - T0 < WATCH_S )); do
  if pgrep -x WeChat >/dev/null 2>&1; then alive_at=$(( $(date +%s) - T0 )); else
    if (( alive_at > 0 )); then VERDICT="DIED-LATER"; DETAIL="alive ${alive_at}s then died"; break; fi
    sleep 1; continue
  fi
  alive_at=$(( $(date +%s) - T0 ))
  sleep 1
done

if [[ "$VERDICT" == "INCONCLUSIVE" && $alive_at -gt 0 ]]; then
  VERDICT="RUNS"; DETAIL="alive ≥${alive_at}s under native SIP with wxkeep ad-hoc re-sign"
fi

# ---------- Phase 5: 采集证据 ----------
declare -i new_ips=0
if [[ "$VERDICT" != "RUNS" ]]; then
  sleep 3   # 等 ReportCrash 落盘
  while read -r f; do
    cp "$f" "$OUT/" 2>/dev/null && new_ips+=1
  done < <(ls -t "$IPS_DIR"/WeChat-*.ips 2>/dev/null | head -3)
  TERM_JSON=$(ls -t "$IPS_DIR"/WeChat-*.ips 2>/dev/null | head -1 | xargs -I{} python3 -c '
import json,sys
try:
    payload=open(sys.argv[1]).read().split("\n",1)[1]
    d=json.loads(payload)
    t=d.get("termination",{})
    e=d.get("exception",{})
    print(json.dumps({"term_ns":t.get("namespace"),"term_code":t.get("code"),
        "indicator":t.get("indicator"),"signal":e.get("signal")},ensure_ascii=False))
except Exception as ex: print("{}")' {} 2>/dev/null)
  log "termination: $TERM_JSON"
  if echo "$TERM_JSON" | grep -q '"term_ns": "CODESIGNING"'; then
    VERDICT="KILLED"; DETAIL="$TERM_JSON"
  elif [[ "$VERDICT" != "DIED-LATER" ]]; then
    VERDICT="OTHER-KILL"; DETAIL="$TERM_JSON"
  fi
fi

# ---------- Phase 6: 结论 ----------
log "verdict: $VERDICT — $DETAIL"
cat > "$OUT/verdict.json" <<EOF
{
  "ts": "$(date -Iseconds)",
  "sip": "$(echo "$SIP" | head -1)",
  "boot_args": "${BOOTARGS:-none}",
  "variant": "$VARIANT",
  "verdict": "$VERDICT",
  "detail": ${DETAIL:-null},
  "new_ips_copied": $new_ips,
  "protocol": "restore->patch(resign)->codesign verify->launch->observe->harvest->restore"
}
EOF
log "evidence dir: $OUT (verdict.json, doctor_before.json, patch.log, codesign_*, .ips)"
case "$VERDICT" in
  RUNS)       log "✅ 结论：维持 doctor watch 级判定（原生 SIP 下 ad-hoc 重签补丁态可运行）" ;;
  KILLED)     log "❌ 结论：按 ROADMAP 决策 #1 恢复 kill_predicted 旧判定（CODESIGNING 杀机实证）" ;;
  OTHER-KILL) log "⚠️  非 CODESIGNING 终止——人工定性（见 $OUT 下 .ips）" ;;
  *)          log "⚠️  证据不足——不改判定" ;;
esac
exit 0
