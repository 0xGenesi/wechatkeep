import lldb
import time

# drive18：M-R2 消费点定位——启动模式（270099 x64）。
# drive17 教训：解密循环 site 是冷路径，附加后管道零命中。改为 spawn 模式：
# 1) WeChatMain 哨兵（wechat.dylib 就绪）→ 2) 地面真值解析基址 →
# 3) 布防消息管道/撤回链 → 4) 捕获启动期初始同步+会话列表渲染的消息流 →
# 5) 找到含"撤回"的 10000 消息内容串 → 读监视点捕获消费链 = hook 落点。

ISREVOKEMSG = 0x4e8d440   # keeptip 态原始序言 554889e553504889fb
KEEP_SITE = 0x537e39d
NEEDLE = "撤回".encode("utf-8")

PIPELINE = [
    (0x4db9019, 'producer-A'),
    (0x4dba029, 'producer-B'),
    (0x3a022c9, 'storage-A'),
    (0x3a043e9, 'storage-B'),
    (0x3a07a49, 'storage-C'),
    (0x3a0fbb9, 'storage-D'),
    (0x3a12579, 'storage-E'),
    (0x3a14ae9, 'storage-F'),
    (0x3a163b9, 'storage-G'),
    (0x3449259, 'syshandler-A'),
    (0x344bcd9, 'syshandler-B'),
]
REVOKE = [
    (0x3951040, 'async-body'),
    (0x355aa90, 'status-write'),
    (0x537db40, 'parse'),
]

BOOT_CAP_S = 180    # 等待 WeChatMain/模块就绪
TIME_CAP_S = 480    # 主循环总时长
BT_PER_SITE = 3
MAX_WP_HITS = 5
DUMP_BUDGET = 40


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


def sso_data_addr(proc, addr):
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    if hdr[0] & 1:
        ptr = int.from_bytes(hdr[16:24], 'little')
        return ptr if 0x10000 < ptr else None
    return addr + 1


def bt(t, base, n=14):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def scan_msg_objects(proc, regs, log):
    err = lldb.SBError()
    found = []
    for name, val in regs.items():
        if val < 0x10000:
            continue
        blob = proc.ReadMemory(val, 0x300, err)
        if not err.Success():
            continue
        for toff in (0x8, 0xC):
            if int.from_bytes(blob[toff:toff+4], 'little') != 10000:
                continue
            for off in range(0, 0x300 - 24, 8):
                d = read_sso(proc, val + off)
                if NEEDLE in d:
                    found.append((val, toff, off, d))
                    log.append(f'  ★ msg@{val:#x} type@+{toff:#x} content@+{off:#x}: {d[:60]!r}')
                    break
    return found


def main_loop(debugger, target, proc, base):
    t0 = time.monotonic()
    ci = debugger.GetCommandInterpreter()
    r = lldb.SBCommandReturnObject()
    err = lldb.SBError()
    ks = proc.ReadMemory(base + KEEP_SITE, 12, err)
    print(f'DRIVE18: keep-site={ks.hex() if err.Success() else "FAIL"}', flush=True)

    sites = {}
    for off, nm in PIPELINE + REVOKE:
        b = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        print(f'DRIVE18: bp {nm} @0x{off:x} #{b.GetID()} locs={b.GetNumLocations()}', flush=True)

    listener = lldb.SBListener('d18log')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()

    bt_used, counts = {}, {}
    dumps = 0
    wp_hits = 0
    wp_armed = False
    hits = 0
    last_hb = time.monotonic()
    while time.monotonic() - t0 < TIME_CAP_S:
        proc.Continue()
        got = listener.WaitForEvent(2, event)
        if time.monotonic() - last_hb > 30:
            last_hb = time.monotonic()
            print(f'DRIVE18: [hb] elapsed={int(time.monotonic()-t0)}s hits={hits} '
                  f'per-site={ {k: counts[k] for k in sorted(counts) } }', flush=True)
        if not got:
            state = proc.GetState()
            if state == lldb.eStateRunning:
                continue
            if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
                print(f'DRIVE18: gone (hits={hits})', flush=True)
                return
            continue
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE18: gone (hits={hits})', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        for t in proc:
            reason = t.GetStopReason()
            if reason == lldb.eStopReasonWatchpoint and wp_armed:
                wp_hits += 1
                f0 = t.GetFrameAtIndex(0)
                pc = f0.GetPC()
                print(f'\n>> WP READ #{wp_hits} pc=wechat+0x{pc-base:x}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
                if wp_hits >= MAX_WP_HITS:
                    ci.HandleCommand('watchpoint delete', r)
                    print('DRIVE18: 消费链捕获完成 — detaching', flush=True)
                    ci.HandleCommand('process detach', r)
                    return
                break
            if reason != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            nm = sites.get(pc)
            if nm is None:
                continue
            hits += 1
            counts[nm] = counts.get(nm, 0) + 1
            if counts[nm] > BT_PER_SITE:
                break
            f0 = t.GetFrameAtIndex(0)
            regs = {n: f0.FindRegister(n).GetValueAsUnsigned()
                    for n in ('rdi', 'rsi', 'rdx', 'rcx', 'rbx')}
            rstr = ' '.join(f'{k}={v:#x}' for k, v in regs.items())
            print(f'\n>> [{nm}] #{counts[nm]} tid={t.id} {rstr}', flush=True)
            print('   bt: ' + bt(t, base), flush=True)
            log = []
            cands = []
            if nm != 'parse' and dumps < DUMP_BUDGET:
                dumps += 1
                cands = scan_msg_objects(proc, regs, log)
                for line in log:
                    print(line, flush=True)
            if nm == 'parse':
                rbx = regs.get('rbx', 0)
                nmv = int.from_bytes(proc.ReadMemory(rbx + 0x1C8, 8, err), 'little') \
                    if err.Success() and rbx else -1
                print(f'   parse-hit obj(rbx)={rbx:#x} [+0x1C8 newmsgid]={nmv:#x}', flush=True)
            if cands and not wp_armed:
                obj, toff, coff, data = cands[0]
                da = sso_data_addr(proc, obj + coff)
                if da:
                    ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{da:x}', r)
                    wp_armed = True
                    print(f'  ★ read-WP armed @0x{da:x}', flush=True)
            break
    print(f'DRIVE18: 时限到达（hits={hits} wp={wp_hits}）— detaching', flush=True)
    ci.HandleCommand('process detach', r)


def drive18(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    ci = debugger.GetCommandInterpreter()
    r = lldb.SBCommandReturnObject()
    t0 = time.monotonic()

    # 阶段 1：WeChatMain 哨兵（pending 断点，模块加载后解析）
    bp = target.BreakpointCreateByName('WeChatMain')
    bp.SetAllowExternalSearch(True) if hasattr(bp, 'SetAllowExternalSearch') else None
    print(f'DRIVE18: WeChatMain sentinel bp#{bp.GetID()} pending', flush=True)

    base = None
    listener = lldb.SBListener('d18boot')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()
    while time.monotonic() - t0 < BOOT_CAP_S:
        proc.Continue()
        got = listener.WaitForEvent(3, event)
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid):
            print('DRIVE18: exited before module ready', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        hit_sentinel = False
        for t in proc:
            if t.GetStopReason() == lldb.eStopReasonBreakpoint:
                hit_sentinel = True
                break
        # 每次停止都尝试解析基址（哨兵或早期信号均可）
        for m in target.modules:
            if m.GetFileSpec().GetFilename() != 'wechat.dylib':
                continue
            cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
            if cand in (0, lldb.LLDB_INVALID_ADDRESS):
                continue
            err = lldb.SBError()
            gt = proc.ReadMemory(cand + ISREVOKEMSG, 9, err)
            if err.Success() and gt.hex() == '554889e553504889fb':
                base = cand
                break
        if base is not None:
            print(f'DRIVE18: module ready base={base:#x}'
                  f'{" (sentinel hit)" if hit_sentinel else ""}', flush=True)
            break
    if base is None:
        print('DRIVE18: 模块未就绪/地面真值未匹配 — 放弃', flush=True)
        ci.HandleCommand('process detach', r)
        return
    bp.SetEnabled(False)
    main_loop(debugger, target, proc, base)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive18.drive18 drive18')
