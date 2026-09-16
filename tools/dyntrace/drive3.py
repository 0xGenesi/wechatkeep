import struct
import lldb

BASE = 0x11b008000
ISREVOKEMSG = BASE + 0x4bc5940

def _sso(proc, addr):
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    tag = hdr[0]
    if tag & 1:
        size = struct.unpack_from('<Q', hdr, 8)[0]
        ptr = struct.unpack_from('<Q', hdr, 16)[0]
        if size > 65536 or ptr == 0:
            return None
        d = proc.ReadMemory(ptr, size, err)
        return d if err.Success() else None
    return hdr[1:1 + (tag >> 1)]

def drive3(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE: slide mismatch: {gt.hex() if err.Success() else "FAIL"}', flush=True)
        return
    print('DRIVE: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(ISREVOKEMSG)
    print(f'DRIVE: isRevokemsg bp#{bp.GetID()} @0x{ISREVOKEMSG:x} locs={bp.GetNumLocations()}', flush=True)
    n = 0
    revoke = 0
    while n < 4000 and revoke < 10:
        proc.Continue()      # 阻塞到下一次停止——本身就是等待机制
        if proc.GetState() in (lldb.eStateExited, lldb.eStateInvalid):
            print(f'DRIVE: exited ({n} stops, {revoke} revoke)', flush=True)
            return
        if proc.GetState() != lldb.eStateStopped:
            continue
        n += 1
        found = False
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            found = True
            rdi = t.GetFrameAtIndex(0).FindRegister('rdi').GetValueAsUnsigned()
            s = _sso(proc, rdi) if rdi else None
            txt = (s or b'')[:120].decode('utf-8', 'replace')
            if n <= 20 or (s and b'revokemsg' in (s or b'')):
                print(f'[stop#{n}] rdi=0x{rdi:x} str={txt!r}', flush=True)
            if s and b'revokemsg' in s:
                revoke += 1
                print(f'######## REVOKE #{revoke} (tid {t.id}) ########', flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand('thread backtrace 24', r)
                if r.Succeeded():
                    print(r.GetOutput(), flush=True)
            break
    print(f'DRIVE: done ({n} stops, {revoke} revoke)', flush=True)

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive3.drive3 drive3')
