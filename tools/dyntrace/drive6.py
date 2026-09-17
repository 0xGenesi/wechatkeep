import lldb

# 编排捕获：平时只有 wrapper 一个断点；wrapper 命中（=撤回 XML 开始解析）后才
# 布防一组嫌疑断点，记录此后命中的先后次序 + 参数 + 短回溯。
# 删除步骤 = 编排中那个存储改动出口。每断点限 4 次、全局 80 停，防冻结。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000
WRAPPER = BASE + 0x50a5120

ARSENAL = [
    (0x329cb80, 'load-by-ids hub'),
    (0x30f8e50, 'storage-mutate outlet'),
    (0x5038130, 'msg-service-A'),
    (0x50380b0, 'msg-service-B'),
    (0x32abc90, '16-caller handler'),
    (0x36d4a10, 'family-lookup-executor'),
]
CAP = 4
GLOBAL_CAP = 80


def _bt6(t):
    out = []
    for i in range(min(t.GetNumFrames(), 6)):
        f = t.GetFrameAtIndex(i)
        pc = f.GetPC()
        if BASE <= pc < TEXT_END:
            out.append(f'wechat+0x{pc-BASE:x}')
        else:
            m = f.GetModule()
            n = m.GetFileSpec().GetFilename() if m.IsValid() else '?'
            out.append(f'[{n}]')
    return ' <- '.join(out)


def drive6(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE6: slide mismatch! got={gt.hex() if err.Success() else "READ-FAIL"}', flush=True)
        return
    print('DRIVE6: ground truth OK', flush=True)
    wbp = target.BreakpointCreateByAddress(BASE + WRAPPER)
    print(f'DRIVE6: wrapper bp#{wbp.GetID()} armed', flush=True)
    armed = {}
    counts = {}
    stops = 0
    phase = 1
    while stops < 200000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE6: gone at stop#{stops}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        hit_any = False
        done = False
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            if phase == 1 and pc == BASE + WRAPPER:
                phase = 2
                hit_any = True
                print(f'\n@@@@@@ REVOKE PARSE — arming {len(ARSENAL)} watchpoints @@@@@@', flush=True)
                for va, name in ARSENAL:
                    b = target.BreakpointCreateByAddress(BASE + va)
                    armed[b.GetID()] = (name, va)
                    counts[name] = 0
                    print(f'  arm {name} bp#{b.GetID()} @wechat+0x{va:x}', flush=True)
                wbp.SetEnabled(False)
                break
            if phase == 2:
                for bid, (name, va) in armed.items():
                    b = target.FindBreakpointByID(bid)
                    if b is None or not b.IsEnabled() or counts[name] >= CAP:
                        continue
                    if pc == BASE + va:
                        counts[name] += 1
                        hit_any = True
                        f0 = t.GetFrameAtIndex(0)
                        regs = ' '.join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                        for n in ('rdi', 'rsi', 'rdx'))
                        print(f'\n>> [{name}] #{counts[name]} tid={t.id} {regs}', flush=True)
                        print(f'   bt: {_bt6(t)}', flush=True)
                        if counts[name] >= CAP:
                            b.SetEnabled(False)
                        break
        total = sum(counts.values())
        if phase == 2 and (total >= GLOBAL_CAP or all(v >= CAP for v in counts.values())):
            done = True
        if done:
            for bid in armed:
                b = target.FindBreakpointByID(bid)
                if b: b.SetEnabled(False)
            print(f'\nDRIVE6: CAPTURE COMPLETE counts={counts}', flush=True)
            r = lldb.SBCommandReturnObject()
            debugger.GetCommandInterpreter().HandleCommand('process detach', r)
            return
    print('DRIVE6: loop end', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive6.drive6 drive6')
