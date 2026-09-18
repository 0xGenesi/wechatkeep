import lldb
import time

# drive24：断点诊断（270099 x64）。
# drive23 实弹结果：撤回提示已渲染但 parse/async-body/drain 三断点零命中
# ——需要判定是 (a) 断点未解析（locations/resolved 问题）还是
# (b) 函数确实不在实时撤回路径上。
# 本脚本：打印每个断点的 locations/resolved/enabled + 原样打印此后
# 【任何】停止的线程级 stop reason / pc / 一段回溯，不做任何改写。

ISREVOKEMSG = 0x4e8d440
SITES = [
    (0x538d700, 'drain'),
    (0x3951040, 'async-body'),
    (0x537db40, 'parse'),
    (0x50342e0, 'pred10000'),   # 对照组：普通消息流应命中（drive22 实证）
]
TIME_CAP_S = 600
LOG = open('/tmp/wxarm/d24.log', 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=10):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def drive24(debugger, command, result, internal_dict):
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()

    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() != 'wechat.dylib':
            continue
        cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if cand in (0, lldb.LLDB_INVALID_ADDRESS):
            continue
        if proc.ReadMemory(cand + ISREVOKEMSG, 9, err).hex() == '554889e553504889fb':
            base = cand
            break
    if base is None:
        log('DRIVE24: 地面真值未匹配 — 放弃')
        return
    log(f'DRIVE24: base={base:#x}')

    sites = {}
    for off, nm in SITES:
        bp = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        log(f'  bp {nm}@{off:#x} id={bp.GetID()} enabled={bp.IsEnabled()} '
            f'locs={bp.GetNumLocations()} resolved={bp.GetNumResolvedLocations()}')
        for i in range(bp.GetNumLocations()):
            loc = bp.GetLocationAtIndex(i)
            log(f'    loc[{i}] addr={loc.GetLoadAddress():#x} resolved={loc.IsResolved()}')

    proc.Continue()
    log('DRIVE24: 已恢复运行——等待任何停止（发消息/撤回均可）')

    stops = 0
    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE24: 进程退出/脱离')
            return
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        stops += 1
        for t in proc:
            reason = t.GetStopReason()
            f0 = t.GetFrameAtIndex(0) if t.GetNumFrames() else None
            pc = f0.GetPC() if f0 else 0
            key = pc - 1 if (pc - 1) in sites else (pc if pc in sites else None)
            tag = f' [{sites[key]}]' if key else ''
            log(f'#{stops} tid={t.id} reason={reason}{tag} pc={pc:#x}'
                + (f' bt: {bt(t, base)}' if reason == lldb.eStopReasonBreakpoint else ''))
        proc.Continue()
    log(f'DRIVE24: 时间到（共 {stops} 次停止）——脱离')
    debugger.HandleCommand('process detach')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive24.drive24 drive24')
