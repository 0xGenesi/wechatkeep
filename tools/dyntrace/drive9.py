import lldb

# drive9：抓撤回队列的异步排水器。
# 断在入队 0x36d5770 首次命中 → 对队列 owner+8(尾指针)/owner+0x10(计数) 下硬件写监视点
# → 之后每一次写入都停：pc 不在入队函数内的就是排水器（或其他写者）。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000
ENQUEUE = 0x36d5770
MAX_WP_HITS = 8


def _bt(t, n):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        f = t.GetFrameAtIndex(i)
        pc = f.GetPC()
        if BASE <= pc < TEXT_END:
            out.append(f'wechat+0x{pc-BASE:x}')
        else:
            m = f.GetModule()
            nm = m.GetFileSpec().GetFilename() if m.IsValid() else '?'
            out.append(f'[{nm}]')
    return ' <- '.join(out)


def drive9(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print('DRIVE9: slide mismatch!', flush=True)
        return
    print('DRIVE9: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(BASE + ENQUEUE)
    print(f'DRIVE9: enqueue bp#{bp.GetID()}', flush=True)
    wp_set = False
    wp_addr = 0
    wp_hits = 0
    stops = 0
    while stops < 200000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE9: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        caught = False
        for t in proc:
            reason = t.GetStopReason()
            if reason == lldb.eStopReasonBreakpoint and not wp_set:
                pc = t.GetFrameAtIndex(0).GetPC()
                if pc != BASE + ENQUEUE:
                    continue
                owner = t.GetFrameAtIndex(0).FindRegister('rdi').GetValueAsUnsigned()
                wp_addr = owner + 8
                wp_addr2 = owner + 0x10
                r = lldb.SBCommandReturnObject()
                ci = debugger.GetCommandInterpreter()
                ci.HandleCommand(f'watchpoint set expression -w write -s 8 -- 0x{wp_addr:x}', r)
                print(f'DRIVE9: wp1 on owner+8 @0x{wp_addr:x}: {r.GetOutput().strip()}', flush=True)
                ci.HandleCommand(f'watchpoint set expression -w write -s 8 -- 0x{wp_addr2:x}', r)
                print(f'DRIVE9: wp2 on owner+0x10 @0x{wp_addr2:x}: {r.GetOutput().strip()}', flush=True)
                bp.SetEnabled(False)
                wp_set = True
                print(f'DRIVE9: owner=0x{owner:x} armed, waiting for drain...', flush=True)
                caught = True
                break
            if reason == lldb.eStopReasonWatchpoint:
                wp_hits += 1
                pc = t.GetFrameAtIndex(0).GetPC()
                tag = 'IN-ENQUEUE' if (BASE + ENQUEUE) <= pc < BASE + 0x36d58d0 else '*** OTHER WRITER ***'
                print(f'\n>> WP hit #{wp_hits} tid={t.id} pc=wechat+0x{pc-BASE:x} {tag}', flush=True)
                print(f'   bt: {_bt(t, 14)}', flush=True)
                if tag.startswith('***'):
                    wp_hits = MAX_WP_HITS   # 抓到排水器即收工
                caught = True
                break
        if wp_set and wp_hits >= MAX_WP_HITS:
            ci = debugger.GetCommandInterpreter()
            ci.HandleCommand('watchpoint list', lldb.SBCommandReturnObject())
            ci.HandleCommand('watchpoint delete', lldb.SBCommandReturnObject())
            print(f'\nDRIVE9: CAPTURE COMPLETE ({wp_hits} wp hits)', flush=True)
            r = lldb.SBCommandReturnObject()
            debugger.GetCommandInterpreter().HandleCommand('process detach', r)
            return
    print('DRIVE9: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive9.drive9 drive9')
