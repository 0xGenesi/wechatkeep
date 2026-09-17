import lldb

# drive15：270099 解析函数全编排捕获（含临时恢复原生流程）。
# 进入解析函数 → 调试器写回 newmsgid 转换原始字节（本次撤回按完整原生流程：
# 标记+删除+提示）→ 记录全部内部调用点命中序列 → 结束后恢复 keeptip 字节。
BASE = None          # 附加模式：动态解析
ENTRY = 0x537db40
FUNC_END = 0x537efa0
KEEP_SITE = 0x537e39d
KEEP_ORIG = bytes.fromhex("E83E4BE9FF488983C8010000")
KEEP_TIP = bytes.fromhex("4831C06690488983C8010000")
SITES = [
    0x537dbd7,
    0x537dbe2,
    0x537dc38,
    0x537dc4b,
    0x537dc8a,
    0x537dc9d,
    0x537dcb0,
    0x537dcec,
    0x537dd39,
    0x537dd4c,
    0x537dd64,
    0x537dd71,
    0x537ddad,
    0x537ddc0,
    0x537ddd7,
    0x537de24,
    0x537de3c,
    0x537de80,
    0x537de93,
    0x537dea5,
    0x537deb9,
    0x537deda,
    0x537df1d,
    0x537df30,
    0x537df47,
    0x537dfbc,
    0x537dfcf,
    0x537dfe6,
    0x537e06e,
    0x537e081,
    0x537e098,
    0x537e123,
    0x537e136,
    0x537e151,
    0x537e180,
    0x537e1c9,
    0x537e1dc,
    0x537e1f1,
    0x537e205,
    0x537e269,
    0x537e27c,
    0x537e2c9,
    0x537e2dc,
    0x537e2f7,
    0x537e305,
    0x537e376,
    0x537e389,
    0x537e39d,
    0x537e3ef,
    0x537e402,
    0x537e420,
    0x537e433,
    0x537e4aa,
    0x537e500,
    0x537e513,
    0x537e553,
    0x537e56c,
    0x537e57d,
    0x537e5b7,
    0x537e5ca,
    0x537e5e5,
    0x537e5f8,
    0x537e76b,
    0x537e82b,
    0x537e837,
    0x537e868,
    0x537e901,
    0x537e90e,
    0x537e94e,
    0x537e964,
    0x537ea50,
    0x537eb10,
    0x537eb1c,
    0x537eb68,
    0x537eb82,
    0x537eb92,
    0x537eba5,
    0x537ebaf,
    0x537ebbf,
    0x537ebfb,
    0x537ec0e,
    0x537ec2a,
    0x537ec7d,
    0x537ec91,
    0x537ed8a,
    0x537ee37,
    0x537ee43,
    0x537ee77,
    0x537eecc,
    0x537ef17,
    0x537ef38,
    0x537ef8c,
]
CAP = 2
GLOBAL_CAP = 70


def drive15(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    global BASE
    # 动态基址：WeChatMain 符号
    for m in target.modules:
        if m.GetFileSpec().GetFilename() == "wechat.dylib":
            BASE = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
            break
    if BASE is None:
        print("DRIVE15: base not found", flush=True)
        return
    print(f"DRIVE15: base={BASE:#x}", flush=True)
    bp = target.BreakpointCreateByAddress(BASE + ENTRY)
    print(f"DRIVE15: entry bp#{bp.GetID()}", flush=True)
    armed = {}
    counts = {}
    stops = 0
    phase = 1
    while stops < 300000:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f"DRIVE15: gone at stop#{stops}", flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        stops += 1
        done = False
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            if phase == 1 and pc == BASE + ENTRY:
                phase = 2
                err = lldb.SBError()
                proc.WriteMemory(BASE + KEEP_SITE, KEEP_ORIG, err)
                print(f"DRIVE15: entered (tid {t.id}) — 原生流程已临时启用, err={err.Success()}", flush=True)
                for site in SITES:
                    b = target.BreakpointCreateByAddress(BASE + site)
                    armed[b.GetID()] = site
                    counts[site] = 0
                tbp = [b for b in [target.FindBreakpointByID(bp.GetID())] if b]
                if tbp: tbp[0].SetEnabled(False)
                print(f"DRIVE15: armed {len(armed)} sites", flush=True)
                break
            if phase == 2:
                if pc in [BASE + s for s in SITES]:
                    counts[pc] = counts.get(pc, 0) + 1
                    f0 = t.GetFrameAtIndex(0)
                    regs = " ".join(f"{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}"
                                    for n in ("rdi", "rsi", "rdx"))
                    print(f">> [{pc:#x}] #{counts[pc]} tid={t.id} {regs}", flush=True)
                    if counts[pc] >= CAP:
                        b = target.FindBreakpointByID(
                            [bid for bid, s in armed.items() if s == pc][0])
                        if b: b.SetEnabled(False)
                    break
        if phase == 2:
            active_hits = sum(counts.values())
            if active_hits >= GLOBAL_CAP:
                for bid in armed:
                    b = target.FindBreakpointByID(bid)
                    if b: b.SetEnabled(False)
                proc.WriteMemory(BASE + KEEP_SITE, KEEP_TIP, err)
                print(f"DRIVE15: CAPTURE COMPLETE — keeptip 恢复, detaching", flush=True)
                r = lldb.SBCommandReturnObject()
                debugger.GetCommandInterpreter().HandleCommand("process detach", r)
                return
    print("DRIVE15: loop end", flush=True)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f drive15.drive15 drive15")
