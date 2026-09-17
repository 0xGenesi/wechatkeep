import lldb

# drive12：自定义提示研究第一步——入队字符串内容捕获。
# 断在 enqueue(0x36d5770)，读 rsi 处的 SSO std::string，看撤回体系里流动的
# 是不是提示文本（replacemsg），为"消费点定位"提供锚。
BASE = 0x11b008000
ENQUEUE = BASE + 0x36d5770
MAX_HITS = 6


def read_cstr(proc, addr, maxlen=200):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, maxlen, err)
    if not err.Success() or not blob:
        return b''
    return blob.split(b'\0')[0]


def read_sso(proc, addr):
    """libc++ std::string：tag&1 → 长串{size@+8, ptr@+0x10}；否则内联 len=tag>>1"""
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return b''
    tag = hdr[0]
    if tag & 1:
        size = int.from_bytes(hdr[8:16], 'little')
        ptr = int.from_bytes(hdr[16:24], 'little')
        if size == 0 or size > 65536 or ptr == 0:
            return b''
        d = proc.ReadMemory(ptr, min(size, 400), err)
        return d if err.Success() else b''
    return hdr[1:1 + (tag >> 1)]


def drive12(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print('DRIVE12: slide mismatch!', flush=True)
        return
    print('DRIVE12: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(ENQUEUE)
    print(f'DRIVE12: enqueue bp#{bp.GetID()}', flush=True)
    hits = 0
    stops = 0
    while stops < 200000 and hits < MAX_HITS:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE12: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        if stops <= 30 or stops % 50 == 0:
            t0 = proc.GetSelectedThread()
            pc0 = t0.GetFrameAtIndex(0).GetPC() if t0.GetNumFrames() > 0 else 0
            print(f'[stop#{stops}] state={state} pc0={pc0:#x} tids={[(t.GetThreadID(), int(t.GetStopReason())) for t in proc][:4]}', flush=True)
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            if pc != ENQUEUE:
                continue
            hits += 1
            f0 = t.GetFrameAtIndex(0)
            rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
            rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
            txt = read_sso(proc, rsi)
            try:
                shown = txt.decode('utf-8', 'replace')
            except Exception:
                shown = repr(txt)
            print(f'\n>> ENQUEUE #{hits} tid={t.id} owner={rdi:#x} straddr={rsi:#x}', flush=True)
            print(f'   text ({len(txt)}B): {shown}', flush=True)
            if hits >= MAX_HITS:
                bp.SetEnabled(False)
                print('DRIVE12: CAPTURE COMPLETE — detaching', flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                return
            break
    print('DRIVE12: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive12.drive12 drive12')
