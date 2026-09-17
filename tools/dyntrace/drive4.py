import lldb

# 活路径捕获：断在撤回 XML 解析 wrapper（TryParseMessage 的唯一 vtable 调用者）。
# 一次命中 → thread backtrace 30 → 整条「分发→解析→删除」链现身。
# 与 drive3 同款骨架（真值校验 + 阻塞 Continue 循环 + HandleCommand 通道）。
BASE = 0x11b008000   # lldb 关 ASLR 下 wechat.dylib __TEXT 滑移（多轮实测恒定）
WRAPPER = BASE + 0x50a5120
MAX_HITS = 5


def drive4(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()
    gt = proc.ReadMemory(BASE + 0x4bc5940, 9, err)
    if not (err.Success() and gt.hex() == '554889e553504889fb'):
        print(f'DRIVE4: slide mismatch! got={gt.hex() if err.Success() else "READ-FAIL"}', flush=True)
        return
    print('DRIVE4: ground truth OK', flush=True)
    bp = target.BreakpointCreateByAddress(WRAPPER)
    print(f'DRIVE4: wrapper bp#{bp.GetID()} @0x{WRAPPER:x} locs={bp.GetNumLocations()}', flush=True)
    hits = 0
    stops = 0
    while stops < 20000 and hits < MAX_HITS:
        proc.Continue()          # 阻塞到下一次停止
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE4: process gone at stop#{stops}, hits={hits}', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            hits += 1
            frame = t.GetFrameAtIndex(0)
            regs = ' '.join(
                f"{n}={frame.FindRegister(n).GetValueAsUnsigned():#x}"
                for n in ('rdi', 'rsi', 'rdx', 'rcx', 'r8'))
            print(f'\n######## WRAPPER HIT #{hits} (tid {t.id}) {regs} ########', flush=True)
            r = lldb.SBCommandReturnObject()
            debugger.GetCommandInterpreter().HandleCommand('thread backtrace 30', r)
            if r.Succeeded():
                print(r.GetOutput(), flush=True)
            if hits >= MAX_HITS:
                bp.SetEnabled(False)
                print('DRIVE4: CAPTURE COMPLETE — detaching', flush=True)
                debugger.GetCommandInterpreter().HandleCommand('process detach', r)
                return
            break
    print(f'DRIVE4: loop end stops={stops} hits={hits}', flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive4.drive4 drive4')
