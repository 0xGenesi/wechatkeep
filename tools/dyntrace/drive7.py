import lldb

# 无噪音编排：直接断在两个撤回处理器入口（只处理撤回类消息，无登录噪音），
# 命中后布防处理器内部的 8 个调用点，记录撤回执行的完整次序。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000

PROCS = [(0x36d58d0, 'processor-A'), (0x36d9120, 'processor-B')]
# 处理器 A 内部的调用点（site=调用指令地址, target=被调者）
SITES = [
    (0x36d68ae, 0x5039410, 'parse'),
    (0x36d68f6, 0x32ce790, 'notify'),
    (0x36d6e29, 0x329cb80, 'load-by-ids'),
    (0x36d6e56, 0x2a7c360, 'helper-1'),
    (0x36d6fde, 0x5038130, 'msgsvc-A1'),
    (0x36d7166, 0x2a7a150, 'query-1'),
    (0x36d7187, 0x2a7a150, 'query-2'),
    (0x36d7ba3, 0x32e6930, 'disp-x1'),
    (0x36d7bb6, 0x2a7c360, 'helper-2'),
    (0x36d7dbc, 0x5038130, 'msgsvc-A2'),
    (0x36d7f60, 0x32aa7b0, 'msgload'),
    (0x36d811e, 0x5038130, 'msgsvc-A3'),
    (0x36d82ac, 0x50b5ef0, 'predicate'),
    (0x36d8309, 0x50380b0, 'msgsvc-B1'),
    (0x36d8389, 0x32aa7b0, 'msgload-2'),
    (0x36d8462, 0x32e69b0, 'disp-x2'),
    (0x36d8528, 0x50380b0, 'msgsvc-B2'),
    (0x36d853e, 0x36d5770, 'family-h'),
]
CAP = 3
GLOBAL_CAP = 60


def _bt(t, n):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        f = t.GetFrameAtIndex(i)
        pc = f.GetPC()
        out.append(f'wechat+0x{pc-BASE:x}' if BASE <= pc < TEXT_END else '[ext]')
    return ' <- '.join(out)


def drive7(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE7: slide mismatch!', flush=True)
        return
    print('DRIVE7: ground truth OK', flush=True)
    pbps = {}
    for va, name in PROCS:
        b = target.BreakpointCreateByAddress(BASE + va)
        pbps[b.GetID()] = (name, va)
        print(f'DRIVE7: {name} bp#{b.GetID()} @wechat+0x{va:x}', flush=True)
    armed = {}
    counts = {}
    stops = 0
    phase = 1
    while stops < 200000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE7: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            if phase == 1:
                for bid, (name, va) in pbps.items():
                    if pc == BASE + va:
                        phase = 2
                        print(f'\n@@@@@@ {name} ENTERED (tid {t.id}) @@@@@@', flush=True)
                        print(f'  bt: {_bt(t, 22)}', flush=True)
                        for site, tgt, sname in SITES:
                            b = target.BreakpointCreateByAddress(BASE + site)
                            armed[b.GetID()] = (sname, site)
                            counts[sname] = 0
                        print(f'  armed {len(armed)} in-processor sites', flush=True)
                        for bid2 in pbps:
                            b2 = target.FindBreakpointByID(bid2)
                            if b2: b2.SetEnabled(False)
                        break
                break
            if phase == 2:
                for bid, (sname, site) in armed.items():
                    if counts[sname] >= CAP or pc != BASE + site:
                        continue
                    counts[sname] += 1
                    f0 = t.GetFrameAtIndex(0)
                    regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                    for n in ('rdi', 'rsi', 'rdx'))
                    print(f'>> [{sname}] #{counts[sname]} tid={t.id} {regs}  bt:{_bt(t,4)}', flush=True)
                    if counts[sname] >= CAP:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    break
                total = sum(counts.values())
                if total >= GLOBAL_CAP or all(v >= CAP for v in counts.values()):
                    for bid in armed:
                        b = target.FindBreakpointByID(bid)
                        if b: b.SetEnabled(False)
                    print(f'\nDRIVE7: CAPTURE COMPLETE counts={counts}', flush=True)
                    r = lldb.SBCommandReturnObject()
                    debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                    return
                break
    print('DRIVE7: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive7.drive7 drive7')
