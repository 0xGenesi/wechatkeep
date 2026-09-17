import lldb

# drive14：附加模式（不重启微信）+ 动态滑移。用于自定义提示研究——
# 断在 dispatch(任何消息)/A-entry/enqueue，捕获入队字符串内容。
WECHATMAIN_FILE_VA = 0x182b0     # WeChatMain 在切片内的 VA（slide = 符号地址 - 此值）
ENQUEUE_OFF = 0x36d5770
DISPATCH_OFF = 0x32e5d40
A_ENTRY_OFF = 0x36d58d0
MAX_HITS = 8


def read_sso(proc, addr):
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


def drive14(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    # 自校验：同名模块可能多个（主程序/WeChatAppEx 内嵌），用 v1 序言真值挑对的那个
    err = lldb.SBError()
    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() != 'wechat.dylib':
            continue
        cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if cand == 0 or cand == lldb.LLDB_INVALID_ADDRESS:
            continue
        gt = proc.ReadMemory(cand + 0x4bc5940, 9, err)
        if err.Success() and gt.hex() == '554889e553504889fb':
            base = cand
            break
        print(f'DRIVE14: candidate {cand:#x} rejected (gt={gt.hex() if err.Success() else "FAIL"})', flush=True)
    if base is None:
        print('DRIVE14: no wechat.dylib module matched ground truth', flush=True)
        return
    print(f'DRIVE14: wechat.dylib base = {base:#x}', flush=True)
    err = lldb.SBError()
    gt = proc.ReadMemory(base + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE14: ground truth mismatch: {gt.hex() if err.Success() else "FAIL"}', flush=True)
        return
    print('DRIVE14: ground truth OK (v1 prologue)', flush=True)

    names = {ENQUEUE_OFF: 'enqueue', DISPATCH_OFF: 'dispatch', A_ENTRY_OFF: 'A-entry'}
    armed = {}
    for off, nm in names.items():
        b = target.BreakpointCreateByAddress(base + off)
        armed[b.GetID()] = (nm, off)
        print(f'DRIVE14: {nm} bp#{b.GetID()} locs={b.GetNumLocations()}', flush=True)

    hits = 0
    stops = 0
    while stops < 400000 and hits < MAX_HITS:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE14: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            va = pc - base
            nm = names.get(va)
            if nm is None:
                continue
            hits += 1
            f0 = t.GetFrameAtIndex(0)
            rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
            rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
            extra = ''
            if nm == 'enqueue':
                txt = read_sso(proc, rsi)
                try:
                    extra = f' text({len(txt)}B): {txt.decode("utf-8", "replace")}'
                except Exception:
                    extra = f' text: {txt!r}'
            print(f'\n>> [{nm}] #{hits} tid={t.id} rdi={rdi:#x} rsi={rsi:#x}{extra}', flush=True)
            if hits >= MAX_HITS:
                print('DRIVE14: CAPTURE COMPLETE — detaching', flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                return
            break
    print('DRIVE14: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive14.drive14 drive14')
