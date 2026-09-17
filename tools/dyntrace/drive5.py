import lldb

# drive4 修正版：backtrace 必须遍历「命中断点的那个线程」的帧（SBThread API），
# 不能用 HandleCommand（它作用于 lldb 当前选中线程，drive4 因此全打到 poll 线程上）。
BASE = 0x11b008000
TEXT_END = BASE + 0x9f40000
WRAPPER = BASE + 0x50a5120
MAX_HITS = 3


def drive5(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE5: slide mismatch! got={gt.hex() if err.Success() else "READ-FAIL"}', flush=True)
        return
    print('DRIVE5: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(WRAPPER)
    print(f'DRIVE5: wrapper bp#{bp.GetID()} @0x{WRAPPER:x} locs={bp.GetNumLocations()}', flush=True)
    hits = 0
    stops = 0
    while stops < 40000 and hits < MAX_HITS:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE5: process gone at stop#{stops}, hits={hits}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            hits += 1
            frame0 = t.GetFrameAtIndex(0)
            regs = ' '.join(f"{n}={frame0.FindRegister(n).GetValueAsUnsigned():#x}"
                            for n in ('rdi', 'rsi', 'rdx'))
            print(f'\n######## WRAPPER HIT #{hits} (tid {t.id}) {regs} ########', flush=True)
            nf = t.GetNumFrames()
            for i in range(min(nf, 34)):
                f = t.GetFrameAtIndex(i)
                pc = f.GetPC()
                name = f.GetFunctionName() or ''
                if BASE <= pc < TEXT_END:
                    print(f'  #{i:2d} 0x{pc:x} = wechat+0x{pc-BASE:x}  {name}', flush=True)
                else:
                    mod = f.GetModule()
                    mname = mod.GetFileSpec().GetFilename() if mod.IsValid() else '?'
                    print(f'  #{i:2d} 0x{pc:x} [{mname}] {name}', flush=True)
            if hits >= MAX_HITS:
                bp.SetEnabled(False)
                print('DRIVE5: CAPTURE COMPLETE — detaching', flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                return
            break
    print(f'DRIVE5: loop end stops={stops} hits={hits}', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive5.drive5 drive5')
