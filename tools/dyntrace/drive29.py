import lldb
import os
import time

# drive29：群聊撤回真实链路定位轮（270100 x64）——drive28 强阴性的交叉验证轮
# （㊹ 下一轮；编排走 `bash tools/dyntrace/d28_live.sh drive29`）。
#
# 断点集 = d22 实证路径三点 + drive28 六点做交叉：
#   PARSE      0x537dcd0  parse 入口（d22/d25/d27 三轮实捕；lazy 实验态=hook 桩，
#                         字节探针双形态门同 drive28）。d25 地面真值：rsi = sysmsg
#                         XML 裸 SSO。
#   REVMGR     0x394be13  revoke_manager 二次分派 call 位（d22 B 路径；同一 XML
#                         再解析一遍）
#   ASYNCBODY  0x3951040  异步撤回任务体入口（d22 C 路径）
#   SIX        ㉜ 六断点（handlercmp/cb/lookup/dbop/inscond/insert）——2026-09-23
#              run6 强阴性（前提三重验证干净仍全零）；本轮保留做交叉：
#              parse/revokemsg 命中而六点零命中同时成立 = 排除的铁证。
#
# 判读矩阵（VERDICT 行，编排 capture_p 认 HIT）：
#   parse_revokemsg>0 且 (revmgr|asyncbody)>0 → HIT
#       活撤回链路实捕——revokemsg parse 命中的完整 bt(20 帧) 即真实调用链，
#       text handler 撤回状态机同构体的定位素材（M-R4 前置）
#   parse_revokemsg>0 且 revmgr/asyncbody 双零 → HISTORY-ONLY
#       只有登录历史批扫（d22 D 路径：历史重扫也过 parse）——活撤回未到达，
#       需复核界面现象（灰条/消息是否正常删除）
#   parse_revokemsg==0 → NEGATIVE（窗口无撤回流量）
#
# 洪峰降噪：parse 对全部消息流计数（d22「洪峰 20+ 源头」），非 revokemsg
# 命中只计数不落盘。观察期间微信间歇卡顿 = 断点往返，正常现象。
#
# 观察轮（只读不改）。工件 → var/wxarm/d29.log、d29_parse_*.xml

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

PARSE = 0x537dcd0
REVMGR = 0x394be13
ASYNCBODY = 0x3951040
SIX = ((0x3445E20, 'handlercmp'), (0x3421BB0, 'cb'), (0x3421BE0, 'lookup'),
       (0x3421C4D, 'dbop'), (0x3422375, 'inscond'), (0x342238E, 'insert'))
NEEDLE = b'revokemsg'
# 时限：DRIVE_TIME_CAP_S 环境变量可缩短（编排脚本冒烟/rehearsal 用）
TIME_CAP_S = int(os.environ.get('DRIVE_TIME_CAP_S', '900'))
MAX_XML_DUMP = 6          # revokemsg XML 落盘上限（防隐私面扩大）
MAX_CB_LOG = 4            # 六点各前 4 次详录（drive28 同款）
LOG = open(os.path.join(OUT, 'd29.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=12):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def rd(proc, addr, n):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, n, err)
    return blob if err.Success() else None


def u64(blob, off):
    return int.from_bytes(blob[off:off+8], 'little') if blob and len(blob) >= off+8 else None


def read_sso(proc, addr, cap=300):
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    tag = hdr[0]
    if tag & 1:
        size = int.from_bytes(hdr[8:16], 'little')
        ptr = int.from_bytes(hdr[16:24], 'little')
        if size == 0 or size > (1 << 20) or ptr < 0x10000:
            return None
        d = proc.ReadMemory(ptr, min(size, cap), err)
        return (size, d if err.Success() else b'')
    n = tag >> 1
    return (n, hdr[1:1 + min(n, cap)]) if n else None


counts = {}
NAMES = {}


def bump(nm):
    counts[nm] = counts.get(nm, 0) + 1
    return counts[nm]


def drive29(debugger, command, result, internal_dict):
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()

    # 地面真值（drive27/28 同款字节探针）：parse 位点 = 原始序言或 hook 桩
    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() != 'wechat.dylib':
            continue
        cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if cand in (0, lldb.LLDB_INVALID_ADDRESS):
            continue
        head = proc.ReadMemory(cand, 4, err)
        if not err.Success() or head.hex() != 'cffaedfe':
            continue
        d = proc.ReadMemory(cand + PARSE, 12, err)
        if not err.Success():
            continue
        h = d.hex()
        if h == '554889e54157415641554154' or (h.startswith('48b8') and h.endswith('ffe0')):
            base = cand
            log(f'DRIVE29: base={base:#x} parse12={h[:16]}…')
            break
    if base is None:
        log('DRIVE29: parse 位点地面真值未匹配 — 放弃')
        proc.Detach()   # 显式分离：lldb 退出时停止态目标会被 kill（实证）
        return

    for off, nm in [(PARSE, 'parse'), (REVMGR, 'revmgr'), (ASYNCBODY, 'asyncbody')] + list(SIX):
        NAMES[base + off] = nm
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    # 同步模式（实证基线：drive22/25/27 均同步跑满热 parse 断点）。async
    # 轮询在 CLT lldb-1700 有崩溃 bug——2026-09-23 冒烟实证：高频
    # stop/resume 下 lldb 自身在 WillPublicStop SIGSEGV（已落盘数据不受影响，
    # 但会话中断）。时限安全性：parse 断点对全部消息流计数，登录历史批扫
    # 保证早且频繁的命中 → 主循环必然推进、TIME_CAP_S 必达（drive28 六死
    # 断点的「零命中永久阻塞」病理在本断点集不成立）；极端全静默场景由
    # 编排层人工收口兜底（kill lldb 后微信存活，run5/run6 实证）。
    proc.Continue()
    log('DRIVE29: 已恢复——请触发【群聊】撤回（只读观察；微信间歇卡顿=parse '
        '断点对所有消息流计数，正常现象）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE29: 进程退出/脱离')
            break
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            key = pc - 1 if (pc - 1) in NAMES else (pc if pc in NAMES else None)
            if not key:
                continue
            nm = NAMES[key]
            rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
            rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
            rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
            if nm == 'parse':
                bump('parse')
                sso = read_sso(proc, rsi, 1024) if rsi > 0x10000 else None
                head = sso[1][:200] if sso else b''
                if NEEDLE not in head:
                    continue   # 洪峰降噪：非撤回 XML 只计数
                rv = bump('parse_revokemsg')
                el = time.monotonic() - t0
                log(f'\n@@@ parse/revokemsg #{rv} t=+{el:.0f}s len={sso[0] if sso else 0}')
                log('   bt: ' + bt(t, base, 20))
                if rv <= MAX_XML_DUMP and sso:
                    open(os.path.join(OUT, f'd29_parse_{rv}.xml'), 'wb').write(sso[1])
                    log(f'   xml dump → d29_parse_{rv}.xml')
            elif nm == 'revmgr':
                n = bump('revmgr')
                if n <= MAX_CB_LOG:
                    log(f'@@@ revmgr #{n} rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x} bt: {bt(t, base, 10)}')
            elif nm == 'asyncbody':
                n = bump('asyncbody')
                if n <= MAX_CB_LOG:
                    log(f'@@@ asyncbody #{n} rdi={rdi:#x} rsi(vec)={rsi:#x} bt: {bt(t, base, 10)}')
            elif nm == 'handlercmp':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    msg = rd(proc, rax := f0.FindRegister('rax').GetValueAsUnsigned(), 0x120)
                    s118 = u64(msg, 0x118) if msg else None
                    typ = int.from_bytes(msg[0xc:0x10], 'little', signed=True) if msg else None
                    log(f'\n@@@ handlercmp #{n} msg={rax:#x} type={typ} +0x118={s118:#x} bt: {bt(t, base)}')
            elif nm == 'cb':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    rcx = f0.FindRegister('rcx').GetValueAsUnsigned()
                    sv = u64(rd(proc, rsi, 8), 0) if rsi > 0x10000 else None
                    log(f'\n@@@ cb #{n} rdi={rdi:#x} rsi=[{rsi:#x}]→svrid={sv} '
                        f'edx(mode)={rdx:#x} ecx(inscond)={rcx:#x}')
                    log('   bt: ' + bt(t, base))
            elif nm == 'lookup':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    log(f'@@@ lookup #{n} rdi(svrid)={rdi:#x}')
            elif nm == 'dbop':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    blob = rd(proc, rdi, 16)
                    log(f'@@@ dbop #{n} rdi=&opstruct({blob.hex() if blob else "?"}) '
                        f'rsi={rsi:#x} rdx(svrid)={rdx:#x}')
            elif nm == 'inscond':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    rbp = f0.FindRegister('rbp').GetValueAsUnsigned()
                    cond = rd(proc, rbp - 0x184, 1)
                    log(f'@@@ inscond #{n} [rbp-0x184]={cond.hex() if cond else "?"}')
            elif nm == 'insert':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    log(f'\n@@@ insert #{n} rdi={rdi:#x} rsi(flags)={rsi:#x}')
                    log('   bt: ' + bt(t, base))
        proc.Continue()

    # 判读矩阵收尾（含进程提前退出的路径）
    rv = counts.get('parse_revokemsg', 0)
    cluster = counts.get('revmgr', 0) + counts.get('asyncbody', 0)
    six = {nm: counts.get(nm, 0) for _, nm in SIX}
    if rv and cluster:
        v = 'HIT'
    elif rv:
        v = 'HISTORY-ONLY'
    else:
        v = 'NEGATIVE'
    log(f'DRIVE29 VERDICT: {v} parse_revokemsg={rv} revmgr={counts.get("revmgr", 0)} '
        f'asyncbody={counts.get("asyncbody", 0)} six={six} total_parse={counts.get("parse", 0)}')
    if v == 'HIT':
        log('DRIVE29: 活撤回链路实捕——revokemsg parse bt 即真实调用链（M-R4 定位素材）')
    elif v == 'HISTORY-ONLY':
        log('DRIVE29: 仅历史批扫——活撤回未到达（复核：界面灰条/被撤消息是否正常删除）')
    else:
        log('DRIVE29: 窗口无撤回流量')
    # 显式 detach（恢复目标运行）：不能依赖 batch 的 -o detach——lldb 在
    # detach 失败/异常退出时会 SIGKILL 停止态目标（2026-09-24 冒烟实证，
    # 微信被连带杀死）
    log('DRIVE29: 收工——detach 恢复微信运行')
    proc.Detach()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive29.drive29 drive29')
