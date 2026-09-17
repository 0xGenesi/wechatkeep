import lldb

# drive11：全链条路由图。一次撤回，看清每个阶段是否执行、在哪个线程。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000

CHAIN = [
    (0x36d58d0, 'A-entry'),
    (0x36d9120, 'B-entry'),
    (0x36d5770, 'enqueue'),
    (0x3325670, 'drain-entry'),
    (0x3325733, 'pop-1'),
    (0x3325911, 'pop-2'),
    (0x32abd90, 'handler-d'),
    (0x32abc90, 'handler16'),
    (0x32a9060, 'mark-parent'),
    (0x32aa7b0, 'load-mark'),
    (0x36d4a10, 'lookup-exec'),
    (0x32ad4d0, 'main-force'),
]
CAP = 3
GLOBAL_CAP = 90


def _bt(t, n):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        f = t.GetFrameAtIndex(i)
        pc = f.GetPC()
        out.append(f'wechat+0x{pc-BASE:x}' if BASE <= pc < TEXT_END else '[ext]')
    return ' <- '.join(out)


def drive11(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print('DRIVE11: slide mismatch!', flush=True)
        return
    print('DRIVE11: ground truth OK', flush=True)
    armed = {}
    counts = {}
    for va, name in CHAIN:
        b = target.BreakpointCreateByAddress(BASE + va)
        armed[b.GetID()] = (name, va)
        counts[name] = 0
    print(f'DRIVE11: armed {len(armed)} chain points', flush=True)
    stops = 0
    while stops < 300000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE11: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            for bid, (name, va) in armed.items():
                if counts[name] >= CAP or pc != BASE + va:
                    continue
                counts[name] += 1
                f0 = t.GetFrameAtIndex(0)
                regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                for n in ('rdi', 'rsi'))
                print(f'>> [{name}] #{counts[name]} tid={t.id} {regs}  bt:{_bt(t,6)}', flush=True)
                if counts[name] >= CAP:
                    b = target.FindBreakpointByID(bid)
                    if b: b.SetEnabled(False)
                break
        if all(v >= CAP for v in counts.values()) or stops > 150000:
            for bid in armed:
                b = target.FindBreakpointByID(bid)
                if b: b.SetEnabled(False)
            print(f'\nDRIVE11: CAPTURE COMPLETE counts={counts}', flush=True)
            r = lldb.SBCommandReturnObject()
            debugger.GetCommandInterpreter().HandleCommand('process detach', r)
            return
    print('DRIVE11: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive11.drive11 drive11')
