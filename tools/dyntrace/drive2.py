import lldb

BASE = 0x11b008000
WRAPPER = BASE + 0x50a5120     # TryParseMessage 的唯一调用者（vtable 虚方法）

def _read_cstr(proc, addr, maxlen=96):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, maxlen, err)
    if not err.Success() or not blob:
        return ''
    return blob.split(b'\0')[0].decode('utf-8', 'replace')

def _read_sso_string(proc, sso_addr):
    """libc++ std::string @sso_addr: tag&1 → long {.., size@+8, ptr@+0x10}, else inline len=tag>>1"""
    err = lldb.SBError()
    hdr = proc.ReadMemory(sso_addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return ''
    tag = hdr[0]
    if tag & 1:
        import struct
        size = struct.unpack_from('<Q', hdr, 8)[0]
        ptr = struct.unpack_from('<Q', hdr, 16)[0]
        if size > 4096 or ptr == 0:
            return ''
        data = proc.ReadMemory(ptr, size, err)
        return data.decode('utf-8', 'replace') if err.Success() else ''
    return hdr[1:1 + (tag >> 1)].decode('utf-8', 'replace')

def drive2(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE: slide mismatch: {gt.hex() if err.Success() else "FAIL"}', flush=True)
        return
    print('DRIVE: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(WRAPPER)
    print(f'DRIVE: wrapper bp#{bp.GetID()} @0x{WRAPPER:x} locs={bp.GetNumLocations()}', flush=True)
    wcm = target.BreakpointCreateByAddress(BASE + 0x182b0)
    print(f'DRIVE: WeChatMain bp#{wcm.GetID()} @0x{BASE+0x182b0:x} locs={wcm.GetNumLocations()} (对照,应启动即命中)', flush=True)
    listener = lldb.SBListener('drive2')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()
    stops = 0
    revoke_hits = 0
    while revoke_hits < 8 and stops < 6000:
        proc.Continue()
        got = listener.WaitForEvent(30, event)
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid):
            print(f'DRIVE: process exited ({revoke_hits} revoke hits)', flush=True)
            return
        if state != lldb.eStateStopped:
            if not got:
                continue   # 30s 无事件：空转等待
            continue
        stops += 1
        handled = False
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            handled = True
            frame = t.GetFrameAtIndex(0)
            rsi = frame.FindRegister('rsi').GetValueAsUnsigned()
            rdi = frame.FindRegister('rdi').GetValueAsUnsigned()
            xml = _read_sso_string(proc, rsi + 0x130) if rsi else ''
            if stops <= 30:
                print(f'  [hit#{stops}] rsi=0x{rsi:x} xml[:80]={xml[:80]!r}', flush=True)
            if 'revokemsg' in xml:
                revoke_hits += 1
                print(f'######## REVOKE HIT #{revoke_hits} (tid {t.id}) ########', flush=True)
                print(f'xml: {xml[:400]}', flush=True)
                print(f'rdi=0x{rdi:x} rsi=0x{rsi:x}', flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand('thread backtrace 24', r)
                if r.Succeeded():
                    print(r.GetOutput(), flush=True)
            break
        if not handled:
            pass   # 非断点停止（信号等）：下一轮 Continue 放行
    print(f'DRIVE: done ({revoke_hits} revoke hits, {stops} stops)', flush=True)

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive2.drive2 drive2')
