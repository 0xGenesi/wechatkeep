import lldb

# drive10：排水函数 [0x3325670,0x3326000) 内部全编排。
# 布防其非日志 E8 站点，记录处理一个撤回条目的完整次序。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000

TRIGGER = (0x3325670, 'drain')
SITES = [
    (0x3325702, 'odd-a'),
    (0x3325713, 'build-list-1'),
    (0x3325733, 'pop-1'),
    (0x332574e, 'proc-1'),
    (0x332582f, 'call-328b5b0'),
    (0x33258f4, 'build-list-2'),
    (0x3325911, 'pop-2'),
    (0x332592c, 'proc-2'),
    (0x33259c5, 'call-50372f0'),
    (0x33259d3, 'call-f9f7a0'),
    (0x3325a5b, 'query-32a3600'),
    (0x3325c44, 'odd-b'),
    (0x3325ee8, 'call-296c480'),
    (0x3325f05, 'call-31b1430'),
    (0x3325f08, 'odd-c'),
    (0x3325f32, 'odd-d'),
    (0x3325fc7, 'odd-e'),
    (0x3325ff4, 'odd-f'),
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


def drive10(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print('DRIVE10: slide mismatch!', flush=True)
        return
    print('DRIVE10: ground truth OK', flush=True)
    tva, tname = TRIGGER
    tbp = target.BreakpointCreateByAddress(BASE + tva)
    print(f'DRIVE10: trigger {tname} bp#{tbp.GetID()}', flush=True)
    armed = {}
    counts = {}
    stops = 0
    phase = 1
    while stops < 200000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE10: gone at stop#{stops}', flush=True)
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
                for site, name in SITES:
                    b = target.BreakpointCreateByAddress(BASE + site)
                    armed[b.GetID()] = (name, site)
                    counts[name] = 0
                print(f'  armed {len(armed)} sites', flush=True)
                tbp.SetEnabled(False)
                break
            if phase == 2:
                for bid, (name, site) in armed.items():
                    if counts[name] >= CAP or pc != BASE + site:
                        continue
                    counts[name] += 1
                    f0 = t.GetFrameAtIndex(0)
                    regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                    for n in ('rdi', 'rsi', 'rdx'))
                    print(f'>> [{name}] #{counts[name]} tid={t.id} {regs}  bt:{_bt(t,4)}', flush=True)
                    if counts[name] >= CAP:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    break
                total = sum(counts.values())
                if total >= GLOBAL_CAP or all(v >= CAP for v in counts.values()):
                    for bid in armed:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    print(f'\nDRIVE10: CAPTURE COMPLETE counts={counts}', flush=True)
                    r = lldb.SBCommandReturnObject()
                    debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                    return
                break
    print('DRIVE10: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive10.drive10 drive10')
