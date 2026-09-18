import lldb
import time

# drive26：M-R4 侦察——撤回消息对象/状态写布局（270099 x64）。
# 前置：drive24 已证 async-body(0x3951040) 在实时撤回路径；
# ⑥ 静态定位状态写 [0x355aa90..0x355af60)，mov [rdx+0x118],9 @0x355ab00。
# 本轮只观察不改：
#  1) async-body 入口：rsi=[start,end) 消息向量（步长 0x278）→
#     逐条转储（type@+0xC / content SSO / 状态位扫描）
#  2) 状态写入口：rdx 对象全量 hex → /tmp/wxarm/d26_status_obj_N.bin，
#     记录 +0x118 入口前值；返回后再读一次（写到文件，靠 offline 对比）
# 目标：回答「+0x118=9 是撤回标记？标记与删除是否可分离」→ M-R4 hook 设计。

ISREVOKEMSG = 0x4e8d440
ASYNC_BODY = 0x3951040
STATUS_WRITE = 0x355aa90
NEEDLE = "撤回".encode("utf-8")
TIME_CAP_S = 900
DUMP_BUDGET = 8
LOG = open('/tmp/wxarm/d26.log', 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def read_sso(proc, addr):
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    tag = hdr[0]
    if tag & 1:
        size = int.from_bytes(hdr[8:16], 'little')
        ptr = int.from_bytes(hdr[16:24], 'little')
        if size == 0 or size > (1 << 20) or ptr < 0x10000:
            return None
        d = proc.ReadMemory(ptr, min(size, 120), err)
        return (size, d if err.Success() else b'')
    n = tag >> 1
    return (n, hdr[1:1 + n]) if n else None


def bt(t, base, n=8):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def dump_msg(proc, addr, idx):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, 0x278, err)
    if not err.Success():
        return
    mtype = int.from_bytes(blob[0xc:0x10], 'little', signed=True)
    s118 = int.from_bytes(blob[0x118:0x120], 'little')
    log(f'    msg[{idx}] @{addr:#x} type@+0xC={mtype} +0x118={s118:#x}')
    for off in (0x18, 0x30, 0x48, 0x168, 0x198):
        s = read_sso(proc, addr + off)
        if s and s[1]:
            mark = ' ★' if NEEDLE in s[1] else ''
            log(f'      +{off:#x} len={s[0]}: {s[1][:48]!r}{mark}')


def drive26(debugger, command, result, internal_dict):
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
        if proc.ReadMemory(cand + ISREVOKEMSG, 9, err).hex() == '554889e553504889fb':
            base = cand
            break
    if base is None:
        log('DRIVE26: 地面真值未匹配 — 放弃')
        return
    log(f'DRIVE26: base={base:#x}')

    sites = {}
    for off, nm in ((ASYNC_BODY, 'async-body'), (STATUS_WRITE, 'status-write')):
        bp = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE26: 已恢复运行——撤回一条（私聊优先）')

    dumps = 0
    status_dumps = 0
    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE26: 进程退出/脱离')
            return
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            key = pc - 1 if (pc - 1) in sites else (pc if pc in sites else None)
            if not key:
                continue
            nm = sites[key]
            if nm == 'async-body' and dumps < DUMP_BUDGET:
                dumps += 1
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
                log(f'\n@@@ async-body #{dumps} rsi={rsi:#x} rdx={rdx:#x}')
                log('   bt: ' + bt(t, base))
                err2 = lldb.SBError()
                vec = proc.ReadMemory(rsi, 16, err2)
                if err2.Success():
                    start = int.from_bytes(vec[0:8], 'little')
                    end = int.from_bytes(vec[8:16], 'little')
                    count = (end - start) // 0x278 if end > start else 0
                    log(f'   向量 [{start:#x},{end:#x}) count={count}')
                    for i in range(min(count, 4)):
                        dump_msg(proc, start + i * 0x278, i)
            elif nm == 'status-write' and status_dumps < 4:
                status_dumps += 1
                rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
                log(f'\n@@@ status-write #{status_dumps} rdx={rdx:#x}')
                log('   bt: ' + bt(t, base))
                blob = proc.ReadMemory(rdx, 0x200, err)
                if err.Success():
                    open(f'/tmp/wxarm/d26_status_obj_{status_dumps}.bin', 'wb').write(blob)
                    s118 = int.from_bytes(blob[0x118:0x120], 'little')
                    log(f'   +0x118(入口前)={s118:#x}  dump→d26_status_obj_{status_dumps}.bin')
        proc.Continue()
    log(f'DRIVE26: 时间到（async {dumps}/status {status_dumps}）——脱离')
    debugger.HandleCommand('process detach')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive26.drive26 drive26')
