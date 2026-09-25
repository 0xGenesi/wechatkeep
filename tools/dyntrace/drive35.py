import lldb
import os
import time

# drive35：apply（0x35103d0）内部子调用定位轮（270100 x64，NATIVE 模式——
# 编排 `NATIVE=1 bash tools/dyntrace/d28_live.sh drive35`）。
#
# 54 轮实证：apply 尾部投递分支在真实流未走——本轮在 apply 的子调用
# 返回位布点，一次撤回判定哪些子调用真实发生，删除/tip 各归其位：
#   APPLY     0x35103d0  apply 入口（rcx=查库命中对象）
#   C1_RET    0x351042a  call 0x369c620（apply 专属被调，头号嫌疑）返回
#   C2_RET    0x35106a1  call 0x5310620(out, r13串) 返回
#   C3_RET    0x3510b7f  call 0x334fc50(out, r13) 返回
#   C4_RET    0x3510ba0  call 0x351f4e0(ctx, wxid, out) 返回（54 轮预期不命中）
#   C5_FLAGW  0x3510baf  call 0x2c900f0 返回 + [obj+0x278]=1 状态位
#   LOOKUP_RET 0x394bfbb 查库结果（关联点）
#   APPLY_CALL_RET 0x394c4ee revoke_manager 的 apply 调用返回（apply 真的跑了）
# 只读观察。工件 → var/wxarm/d35.log

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

SITES = ((0x35103D0, 'apply'), (0x351042A, 'c1_ret_369c620'),
         (0x35106A1, 'c2_ret_5310620'), (0x3510B7F, 'c3_ret_334fc50'),
         (0x3510BA0, 'c4_ret_351f4e0'), (0x3510BAF, 'c5_flagw'),
         (0x394BFBB, 'lookup_ret'), (0x394C4EE, 'apply_call_ret'))
TIME_CAP_S = int(os.environ.get('DRIVE_TIME_CAP_S', '900'))
MAX_CB_LOG = 8
LOG = open(os.path.join(OUT, 'd35.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=10):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


counts = {}
NAMES = {}


def bump(nm):
    counts[nm] = counts.get(nm, 0) + 1
    return counts[nm]


def drive35(debugger, command, result, internal_dict):
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
        head = proc.ReadMemory(cand, 4, err)
        if not err.Success() or head.hex() != 'cffaedfe':
            continue
        d = proc.ReadMemory(cand + 0x537DCD0, 12, err)
        if not err.Success():
            continue
        if d.hex() == '554889e54157415641554154':
            base = cand
            log(f'DRIVE35: base={base:#x} (native pristine confirmed)')
            break
    if base is None:
        log('DRIVE35: parse 原始序言未匹配 — 放弃')
        proc.Detach()
        return

    for off, nm in SITES:
        NAMES[base + off] = nm
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE35: 已恢复——请触发【群聊】撤回（原生观察）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE35: 进程退出/脱离')
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
            n = bump(nm)
            if n <= MAX_CB_LOG:
                rcx = f0.FindRegister('rcx').GetValueAsUnsigned()
                rax = f0.FindRegister('rax').GetValueAsUnsigned()
                log(f'@@@ {nm} #{n} t=+{time.monotonic()-t0:.0f}s rcx={rcx:#x} rax={rax:#x} '
                    f'bt: {bt(t, base)}')
        if time.monotonic() - t0 >= TIME_CAP_S:
            break
        proc.Continue()

    log(f'DRIVE35 VERDICT-COUNTS: ' + ' '.join(f'{nm}={counts.get(nm, 0)}' for _, nm in SITES))
    log('DRIVE35: 收工——detach 恢复微信运行')
    proc.Detach()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive35.drive35 drive35')
