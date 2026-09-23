#!/bin/bash
# d28_live.sh — drive28 群聊实弹（实验 A：惰性态）的一键编排。
#
# 前提（2026-09-20 已核）：装机 WeChat=270100；drive28 六偏移对 pristine
# 工件全部复核 PASS；本机 SIP off + amfi relaxed（lldb attach 可行）。
#
# 流程：微信退出 → 字节 restore（revoke 链 pristine，实验 A 口径=d27 对照组）
#   → runtime install → 惰性配置（keep_message=false、去 tip_text；原配置备份）
#   → 启动微信 → lldb attach + drive28（≤900s 只读观察窗）
#   → trap 自愈：恢复 runtime.json；未捕获→退场到日常防护态（runtime remove
#   + patch silent）；已捕获→保留现场（微信运行+灰条可肉眼复核），分析轮收口。
#
# 用户动作：观察窗内【任意群聊】发生一次真实撤回（群友撤/手机上撤均可，
# 优先他人撤回）。工件 → var/wxarm/d28.log、d28_insert_*.bin、d28_session.log。
set -uo pipefail
cd "$(dirname "$0")/../.."   # 仓库根（lldb 相对 import 与 tee 落点）
WX="$(pwd)/.build/release/wxkeep"
RT="$HOME/Library/Application Support/wxkeep/runtime.json"
BAK="var/wxarm/runtime.json.pre-d28.bak"

log(){ printf '\033[1;36m[d28live]\033[0m %s\n' "$(date +%H:%M:%S) $*"; }

capture_p(){ ls var/wxarm/d28_insert_*.bin >/dev/null 2>&1 || grep -q '@@@ insert' var/wxarm/d28.log 2>/dev/null; }

cleanup(){
  log "cleanup: 恢复 runtime.json 用户配置"
  [[ -f "$BAK" ]] && cp "$BAK" "$RT"
  if capture_p; then
    log "cleanup: ✅ 已捕获——微信保持运行（群聊灰条可肉眼复核），runtime 保持安装，字节保持 pristine；后续分析轮收口"
  else
    log "cleanup: 窗口空转——退场到日常防护态（quit → runtime remove → patch silent）"
    osascript -e 'tell application "WeChat" to quit' >/dev/null 2>&1 || true
    sleep 2; pkill -x WeChat >/dev/null 2>&1 || true
    "$WX" runtime remove >/dev/null 2>&1 || log "⚠️ runtime remove 非零——请手动 '$WX runtime remove'"
    "$WX" patch --variant silent >/dev/null 2>&1 || log "⚠️ patch silent 非零——请手动 '$WX patch --variant silent'"
  fi
}
trap cleanup EXIT

# ---------- 0. 前置 ----------
[[ -x "$WX" ]] || { log "缺 $WX（先 swift build -c release）"; exit 2; }
"$WX" doctor 2>/dev/null | grep -q 'build: 270100' || { log "装机件不是 270100——drive28 偏移不适用，中止"; exit 2; }
if pgrep -x WeChat >/dev/null 2>&1; then
  log "微信在运行——先退出"
  osascript -e 'tell application "WeChat" to quit' >/dev/null 2>&1 || true
  sleep 3; pkill -x WeChat >/dev/null 2>&1 || true; sleep 1
fi

# ---------- 1. 字节 pristine（revoke 链 native 全通）----------
log "phase 1: restore 字节补丁 → pristine（实验 A 需要 native 链路）"
"$WX" restore || log "restore 返回非零（可能本就 pristine）——继续"

# ---------- 2. runtime 惰性安装 ----------
log "phase 2: runtime install"
"$WX" runtime install || { log "runtime install 失败"; exit 3; }
cp "$RT" "$BAK"
python3 - "$RT" <<'PY' || exit 5
import sys, plistlib
p = sys.argv[1]
with open(p,'rb') as f: d = plistlib.load(f)
d['keep_message'] = False      # 惰性：不清零 newmsgid（默认缺省=开，须显式关）
d.pop('tip_text', None)        # 无文案改写 → 全透传
with open(p,'wb') as f: plistlib.dump(d, f)
# 读回验证：实验 A 的前提必须在微信启动前成立（2026-09-23 实弹教训：
# 配置在写盘与启动之间被改回防护态 → 撤回被 hook 清零 → 六断点零命中，
# 白跑一轮——marker zero>0 即该污染的指纹）
with open(p,'rb') as f: chk = plistlib.load(f)
assert chk.get('keep_message') is False, 'keep_message=false 未生效'
assert 'tip_text' not in chk, 'tip_text 未移除'
print('lazy config ok: keep_message=false, tip_text removed; keys:', sorted(chk.keys()))
PY

# ---------- 3. 启动微信（惰性态）----------
log "phase 3: 启动微信"
open -a /Applications/WeChat.app
PID=""
for i in $(seq 1 30); do PID=$(pgrep -x WeChat | head -1); [[ -n "$PID" ]] && break; sleep 1; done
[[ -n "$PID" ]] || { log "微信 30s 内未起来"; exit 4; }
log "WeChat pid=${PID}，等 25s 稳定（自动登录 + 线程风暴平息——8s 实测会 attach 失败：attached but could not pause execution）"
sleep 25

# ---------- 4. lldb 只读观察窗（≤900s）----------
log "phase 4: lldb attach + drive28 —— 观察窗已开（≤15 分钟），请去任意群聊触发一次撤回"
osascript -e 'display notification "观察窗 15 分钟。请去任意群聊触发一次真实撤回（优先他人撤回）。期间请勿运行 wxkeep 命令或编辑 runtime.json——防护配置会污染实验。" with title "drive28 实弹观察窗已开" sound name "Glass"' >/dev/null 2>&1 || true
for ATTEMPT in 1 2 3; do
  lldb --batch -p "$PID" \
    -o 'command script import tools/dyntrace/drive28.py' \
    -o 'drive28' \
    -o 'detach' 2>&1 | tee var/wxarm/d28_session.log
  # attach 瞬态失败（could not pause execution）重试；drive28 正常跑完则退出
  if ! grep -q "attach failed" var/wxarm/d28_session.log; then break; fi
  log "attach 第 ${ATTEMPT} 次失败（瞬态）——10s 后重试"
  sleep 10
done
log "drive28 轮结束——数据在 var/wxarm/d28.log（与 d28_insert_*.bin）"
