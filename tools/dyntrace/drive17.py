import lldb
import time

# drive17：M-R2 消费点定位（270099 x64，附加模式）。
# 思路：历史撤回提示（10000 消息）存在于会话数据中——producer/storage 管道
# 读取会话消息时必经。断管道函数 → 扫描消息对象（[obj+8] 或 [obj+0xC]==10000）
# → 定位含"撤回"的内容 SSO → 读监视点捕获消费链回溯 = runtime hook 落点。
# 同时保留撤回链断点（async-body/status-write/parse），真实撤回发生时一并捕获。

ISREVOKEMSG = 0x4e8d440   # 地面真值：keeptip 态下应为原始序言 554889e553504889fb
KEEP_SITE = 0x537e39d     # 变体自报：4831c06690... = keeptip v1 已应用
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
    (0x3951040, 'async-body'),    # 异步撤回任务体（resolver 调用方）
    (0x355aa90, 'status-write'),  # +0x118=9 撤回状态写（M-R4 标记位点）
    (0x537db40, 'parse'),         # 270099 解析入口
]

TIME_CAP_S = 420      # 总时长上限
BT_PER_SITE = 2       # 每位点回溯配额
MAX_WP_HITS = 4
DUMP_BUDGET = 24


def read_sso(proc, addr):
    """微信自定义 SSO：byte0=len<<1|isLong；短串数据+1；长串 size@+8 ptr@+0x10"""
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
    """返回 SSO 数据区地址（长串=堆指针，短串=内联首字节）"""
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    if hdr[0] & 1:
        ptr = int.from_bytes(hdr[16:24], 'little')
        return ptr if 0x10000 < ptr < (1 << 64) else None
    return addr + 1


def bt(t, base, n=14):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def scan_msg_objects(proc, regs, log):
    """在寄存器指向的对象附近找 10000 消息结构，返回 (obj, off, needle_ptr) 列表"""
    err = lldb.SBError()
    found = []
    for name, val in regs.items():
        if val < 0x10000:
            continue
        blob = proc.ReadMemory(val, 0x300, err)
        if not err.Success():
            continue
        # 类型字段候选：[+8] / [+0xC] == 10000
        for toff in (0x8, 0xC):
            tv = int.from_bytes(blob[toff:toff+4], 'little')
            if tv != 10000:
                continue
            # 在结构内找 SSO 字段：扫每个 8 字节对齐偏移试 SSO 解释
            for off in range(0, 0x300 - 24, 8):
                d = read_sso(proc, val + off)
                if NEEDLE in d:
                    found.append((val, toff, off, d))
                    log.append(f'  ★ msg@{val:#x} type@+{toff:#x}=10000 content@+{off:#x}: {d[:60]!r}')
                    break
    return found


def drive17(debugger, command, result, internal_dict):
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()

    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() != 'wechat.dylib':
            continue
        cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if cand in (0, lldb.LLDB_INVALID_ADDRESS):
            continue
        gt = proc.ReadMemory(cand + ISREVOKEMSG, 9, err)
        if err.Success() and gt.hex() == '554889e553504889fb':
            base = cand
            break
    if base is None:
        print('DRIVE17: no wechat.dylib matched ground truth (isRevokemsg prologue)', flush=True)
        return
    print(f'DRIVE17: base={base:#x}', flush=True)
    ks = proc.ReadMemory(base + KEEP_SITE, 12, err)
    print(f'DRIVE17: keep-site={ks.hex() if err.Success() else "FAIL"}'
          f'（4831c06690...=keeptip v1）', flush=True)

    sites = {}
    for off, nm in PIPELINE + REVOKE:
        b = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        print(f'DRIVE17: bp {nm} @0x{off:x} #{b.GetID()} locs={b.GetNumLocations()}', flush=True)

    listener = lldb.SBListener('d17log')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()
    ci = debugger.GetCommandInterpreter()
    r = lldb.SBCommandReturnObject()

    bt_used = {}
    dumps = 0
    wp_hits = 0
    wp_armed = False
    waddr = 0
    hits = 0
    while time.monotonic() - t0 < TIME_CAP_S:
        proc.Continue()
        if not listener.WaitForEvent(2, event):
            state = proc.GetState()
            if state == lldb.eStateRunning:
                continue
            if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
                print(f'DRIVE17: gone (hits={hits})', flush=True)
                return
            continue
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE17: gone (hits={hits})', flush=True)
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
                    print('DRIVE17: 消费链捕获完成 — detaching', flush=True)
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
            f0 = t.GetFrameAtIndex(0)
            regs = {n: f0.FindRegister(n).GetValueAsUnsigned()
                    for n in ('rdi', 'rsi', 'rdx', 'rcx', 'rbx')}
            rstr = ' '.join(f'{k}={v:#x}' for k, v in regs.items())
            print(f'\n>> [{nm}] #{hits} tid={t.id} {rstr}', flush=True)
            if bt_used.get(nm, 0) < BT_PER_SITE:
                bt_used[nm] = bt_used.get(nm, 0) + 1
                print('   bt: ' + bt(t, base), flush=True)
            log = []
            cands = []
            if nm not in ('parse', 'status-write') and dumps < DUMP_BUDGET:
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
                    waddr = da
                    ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{da:x}', r)
                    wp_armed = True
                    print(f'  ★ read-WP armed @0x{da:x}（tip 内容数据区）', flush=True)
            break
    print(f'DRIVE17: 时限到达（hits={hits} wp_hits={wp_hits}）— detaching', flush=True)
    ci.HandleCommand('process detach', r)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive17.drive17 drive17')
