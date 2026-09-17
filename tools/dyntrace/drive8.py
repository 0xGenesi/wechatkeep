import lldb

# drive8：断在处理器 A 入口，布防其「前段」删除嫌疑链
# （0x36d4a10 查找执行器 / 0x32ad4d0 撤回主力 / 收集 / 批扫描器及其内部）
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000

TRIGGER = (0x36d58d0, 'processor-A')
ARSENAL = [
    (0x36d4a10, 'lookup-executor'),
    (0x32ad4d0, 'main-force'),
    (0x30db570, 'collect'),
    (0x32abc90, 'handler16'),
    (0x32abd90, 'handler-d'),
    (0x36dbae0, 'batch-scanner'),
    (0x36db710, 'scanner-a'),
    (0x36dc940, 'scanner-b'),
    (0x36dd7f0, 'scanner-c'),
    (0x36ef870, 'scanner-d'),
    (0x36efe80, 'scanner-e'),
    (0x4d6efd0, 'msg-helper'),
    (0x50b4f10, 'tip-builder'),
    (0x329cb80, 'load-by-ids'),
    (0x32a9060, 'mark-parent'),
]
CAP = 2
GLOBAL_CAP = 70


def _bt(t, n):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        f = t.GetFrameAtIndex(i)
        pc = f.GetPC()
        out.append(f'wechat+0x{pc-BASE:x}' if BASE <= pc < TEXT_END else '[ext]')
    return ' <- '.join(out)


def drive8(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print('DRIVE8: slide mismatch!', flush=True)
        return
    print('DRIVE8: ground truth OK', flush=True)
    tva, tname = TRIGGER
    tbp = target.BreakpointCreateByAddress(BASE + tva)
    print(f'DRIVE8: trigger {tname} bp#{tbp.GetID()}', flush=True)
    armed = {}
    counts = {}
    stops = 0
    phase = 1
    while stops < 200000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE8: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            if phase == 1 and pc == BASE + tva:
                phase = 2
                print(f'\n@@@@@@ {tname} ENTERED (tid {t.id}) @@@@@@', flush=True)
                for va, name in ARSENAL:
                    b = target.BreakpointCreateByAddress(BASE + va)
                    armed[b.GetID()] = (name, va)
                    counts[name] = 0
                print(f'  armed {len(armed)}', flush=True)
                tbp.SetEnabled(False)
                break
            if phase == 2:
                for bid, (name, va) in armed.items():
                    if counts[name] >= CAP or pc != BASE + va:
                        continue
                    counts[name] += 1
                    f0 = t.GetFrameAtIndex(0)
                    regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                    for n in ('rdi', 'rsi', 'rdx'))
                    print(f'>> [{name}] #{counts[name]} tid={t.id} {regs}  bt:{_bt(t, 5)}', flush=True)
                    if counts[name] >= CAP:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    break
                total = sum(counts.values())
                if total >= GLOBAL_CAP or all(v >= CAP for v in counts.values()):
                    for bid in armed:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    print(f'\nDRIVE8: CAPTURE COMPLETE counts={counts}', flush=True)
                    r = lldb.SBCommandReturnObject()
                    debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                    return
                break
    print('DRIVE8: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive8.drive8 drive8')
