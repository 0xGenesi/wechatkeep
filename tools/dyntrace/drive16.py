import lldb

# drive16：M-R2 研究——定位提示文本（replacemsg）消费点。
# 1) 断在 newmsgid 存储之后（0x537e3a9）
# 2) 转储撤回信息对象的 SSO 字符串字段（找含"撤回"的 replacemsg）
# 3) 对该字段下读取监视点 → 捕获消费链回溯（= runtime hook 落点）
BASE = None
POST_STORE = 0x537e3a9
NEEDLE = "撤回".encode("utf-8")
MAX_WP_HITS = 4


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
        d = proc.ReadMemory(ptr, min(size, 300), err)
        return d if err.Success() else b''
    return hdr[1:1 + (tag >> 1)]


def drive16(debugger, command, result, internal_dict):
    global BASE
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    for m in target.modules:
        if m.GetFileSpec().GetFilename() == "wechat.dylib":
            BASE = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
            break
    if BASE is None:
        print('DRIVE16: base not found', flush=True)
        return
    print(f'DRIVE16: base={BASE:#x}', flush=True)
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4e8d440, 4, err)
    print(f'DRIVE16: isRevokemsg 前4B={gt.hex() if err.Success() else "FAIL"}'
          f'（31c0c390=silent 已应用）', flush=True)

    bp = target.BreakpointCreateByAddress(BASE + POST_STORE)
    print(f'DRIVE16: post-store bp#{bp.GetID()}', flush=True)
    ci = debugger.GetCommandInterpreter()
    r = lldb.SBCommandReturnObject()

    wp_set = False
    wp_hits = 0
    dumps = 0
    stops = 0
    while stops < 300000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE16: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            reason = t.GetStopReason()
            pc = t.GetFrameAtIndex(0).GetPC() if t.GetNumFrames() else 0

            if reason == lldb.eStopReasonBreakpoint and pc == BASE + POST_STORE and dumps < 2:
                dumps += 1
                rbx = t.GetFrameAtIndex(0).FindRegister('rbx').GetValueAsUnsigned()
                obj = rbx
                nm = int.from_bytes(proc.ReadMemory(obj + 0x1C8, 8, err), 'little') \
                    if err.Success() else -1
                print(f'\n@@@@@@ POST-STORE #{dumps} obj={obj:#x} [+0x1C8 newmsgid]={nm:#x} @@@@@@', flush=True)
                # 完整 hex 转储（离线分析用）
                blob = proc.ReadMemory(obj, 0x1000, err)
                if err.Success():
                    open(f'/tmp/wxarm/obj_{dumps}.bin', 'wb').write(blob)
                    print(f'  hex dump → /tmp/wxarm/obj_{dumps}.bin (0x1000B)', flush=True)
                # 指针解引用扫描：找含"撤回"的堆文本字段
                found = []
                for off in range(0, 0x1000, 8):
                    pv = int.from_bytes(proc.ReadMemory(obj + off, 8, err), 'little')
                    if pv < 0x10000: continue
                    txt = proc.ReadMemory(pv, 150, err)
                    if err.Success() and NEEDLE in txt:
                        found.append((off, pv))
                # 内联扫描
                blob2 = proc.ReadMemory(obj, 0x1000, err)
                io = blob2.find(NEEDLE) if err.Success() else -1
                if io >= 0: found.insert(0, (io, obj + io))
                if found:
                    for off, pv in found[:4]:
                        txt = proc.ReadMemory(pv, 100, err)
                        print(f'  ★ 字段 @+{off:#x} → {pv:#x}: {txt[:60]!r}', flush=True)
                    waddr = found[0][1]
                    ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{waddr:x}', r)
                    print(f'  read-WP @0x{waddr:x} armed', flush=True)
                    wp_set = True
                else:
                    print('  （本轮无含"撤回"的字段——可能提示文本在别处构建）', flush=True)
                caught = True
                break

            if reason == lldb.eStopReasonWatchpoint and wp_set:
                wp_hits += 1
                f0 = t.GetFrameAtIndex(0)
                pc = f0.GetPC()
                regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                for n in ('rdi', 'rsi', 'rdx'))
                print(f'\n>> WP READ #{wp_hits} tid={t.id} pc=wechat+0x{pc-BASE:x} {regs}', flush=True)
                nf = min(t.GetNumFrames(), 12)
                frames = []
                for i in range(nf):
                    fa = t.GetFrameAtIndex(i).GetPC()
                    frames.append(f'wechat+0x{fa-BASE:x}' if BASE <= fa < BASE + 0x9f40000 else '[ext]')
                print('   bt: ' + ' <- '.join(frames), flush=True)
                caught = True
                if wp_hits >= MAX_WP_HITS:
                    ci.HandleCommand('watchpoint delete', r)
                    print('DRIVE16: CAPTURE COMPLETE — detaching', flush=True)
                    ci.HandleCommand('process detach', r)
                    return
                break
        if not wp_set and stops > 100000:
            print('DRIVE16: no trigger — loop end', flush=True)
            return
    print('DRIVE16: end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive16.drive16 drive16')
