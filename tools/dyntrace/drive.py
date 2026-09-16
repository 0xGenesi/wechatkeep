import lldb

BASE = 0x11b008000   # lldb 关 ASLR 下 wechat.dylib __TEXT 滑移（两轮实测）
SITES = [
    (0x4bc5940, 'isRevokemsg'),
    (0x4bc59e0, 'isQyRevokemsg'),
    (0x50a5350, 'TryParseMessage'),
    (0x50a5120, 'wrapper'),
    (0x50b5ea0, 'revoke-predicate'),
    (0x4bc7400, 'isTipMsg-A'),
    (0x4d6efd0, 'isTipMsg-B'),
    (0x36dbae0, 'executor'),
    (0x50b4f10, 'tip-builder'),
    (0x36db710, 'tip-insert'),
]

def drive(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE: slide mismatch! got={gt.hex() if err.Success() else "READ-FAIL"}', flush=True)
        return
    print('DRIVE: ground truth OK', flush=True)
    bps = {}
    for va, name in SITES:
        bp = target.BreakpointCreateByAddress(BASE + va)
        bps[bp.GetID()] = (name, va)
        print(f'DRIVE: bp#{bp.GetID()} {name} @0x{BASE+va:x} locs={bp.GetNumLocations()}', flush=True)
    listener = lldb.SBListener('drivelog')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()
    rounds = 0
    hits = 0
    while rounds < 2000:
        proc.Continue()
        if not listener.WaitForEvent(120, event):
            print('DRIVE: idle 120s, waiting on', flush=True)
            continue
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid):
            print(f'DRIVE: process exited after {hits} hits', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        rounds += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            bnum = t.GetStopReasonDataAtIndex(0)
            name, va = bps.get(bnum, (f'bp{bnum}', 0))
            hits += 1
            print(f'===== HIT {name} (tid {t.id}) =====', flush=True)
            r = lldb.SBCommandReturnObject()
            debugger.GetCommandInterpreter().HandleCommand('thread backtrace 20', r)
            if r.Succeeded():
                print(r.GetOutput(), flush=True)
            break
    print(f'DRIVE: rounds exhausted, {hits} hits', flush=True)

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive.drive drive')
