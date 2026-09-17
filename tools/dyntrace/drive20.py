import lldb
import time

# drive20：M-R2 tip 物化验证 + 修正版 SSO 回溯（270099 x64）。
# drive19 教训：(a) 长串 SSO ptr 指向串首（昵称前缀），needle 在中部 → 指针值反查失配；
# (b) 空闲堆无已物化 tip（无打开的会话窗）→ 需先打开会话。
# 本轮：仅扫堆区（≥0x600000000000），needle="撤回了一条消息"，
# 回溯 = needle 前后 0x100 内找合法 SSO 头（tag 奇、size 覆盖、ptr≤h<ptr+size），
# 挂读 WP（≤4），阻塞等命中（外部触发 UI）。

ISREVOKEMSG = 0x4e8d440
NEEDLE = "撤回了一条消息".encode("utf-8")
REGION_MIN = 0x600000000000
REGION_MAX_SZ = 96 << 20
WP_CAP = 4
WP_HITS_CAP = 8


def bt(t, base, n=16):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def read_sso_at(proc, q, err):
    """q 为 SSO 头地址：返回 (data_ptr, size, tag) 或 None"""
    hdr = proc.ReadMemory(q, 24, err)
    if not err.Success() or len(hdr) < 24:
        return None
    tag = hdr[0]
    if not (tag & 1):
        return None
    size = int.from_bytes(hdr[8:16], 'little')
    ptr = int.from_bytes(hdr[16:24], 'little')
    if not (6 <= size <= 65536) or ptr < REGION_MIN:
        return None
    return ptr, size, tag


def find_sso_owner(proc, h, err):
    """在 h 之前 0x100 内找拥有该 needle 的 SSO 头"""
    back = proc.ReadMemory(h - 0x108, 0x110, err)
    if not err.Success():
        return None
    for k in range(0, 0x100, 8):
        q = h - 0x108 + k
        r = read_sso_at(proc, q, err)
        if not r:
            continue
        ptr, size, tag = r
        if ptr <= h < ptr + size:
            return q, ptr, size
    return None


def drive20(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    ci = debugger.GetCommandInterpreter()
    ro = lldb.SBCommandReturnObject()
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
        print('DRIVE20: base 不明', flush=True)
        return
    print(f'DRIVE20: base={base:#x}', flush=True)

    # 堆区域枚举
    regions = []
    addr = 0
    for _ in range(20000):
        ci.HandleCommand(f'memory region 0x{addr:x}', ro)
        out = ro.GetOutput() or ''
        line = out.split('\n')[0] if out else ''
        if not line.startswith('['):
            break
        try:
            rng = line[1:line.index(')')]
            b, e = rng.split('-')
            b, e = int(b, 16), int(e, 16)
        except ValueError:
            break
        perm = line.split(')')[1].strip().split(' ')[0] if ')' in line else ''
        name = line.split(')')[1].strip() if ')' in line else ''
        if 'rw' in perm and b >= REGION_MIN and 0 < e - b <= REGION_MAX_SZ:
            regions.append((b, e - b))
        addr = e
    tot = sum(s for _, s in regions)
    print(f'DRIVE20: heap regions={len(regions)} total={tot/(1<<20):.0f}MB', flush=True)

    hits = []
    for begin, sz in regions:
        off = 0
        while off < sz:
            n = min(1 << 20, sz - off)
            blob = proc.ReadMemory(begin + off, n, err)
            if not err.Success():
                break
            pos = 0
            while True:
                i = blob.find(NEEDLE, pos)
                if i < 0:
                    break
                hits.append(begin + off + i)
                pos = i + 1
            off += n
    print(f'DRIVE20: needle hits={len(hits)}', flush=True)

    owners = []
    seen = set()
    for h in hits[:400]:
        o = find_sso_owner(proc, h, err)
        if not o:
            continue
        q, ptr, size = o
        d = proc.ReadMemory(ptr, min(size, 120), err)
        if not err.Success():
            continue
        if q in seen:
            continue
        seen.add(q)
        owners.append((q, ptr, size, d))
        print(f'  SSO head@{q:#x} ptr={ptr:#x} size={size}: {d[:90]!r}', flush=True)
    print(f'DRIVE20: SSO owners={len(owners)}', flush=True)

    if not owners:
        print('DRIVE20: 无物化 tip —— 会话窗可能未打开（URL scheme 未生效？）', flush=True)
        ci.HandleCommand('process detach', ro)
        return

    armed = 0
    for q, ptr, size, d in owners[:WP_CAP]:
        ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{ptr:x}', ro)
        if ro.Succeeded():
            armed += 1
            print(f'DRIVE20: read-WP#{armed} @0x{ptr:x} (size={size})', flush=True)
    print(f'DRIVE20: ARMED ({armed}) — 等待读取', flush=True)

    n = 0
    while n < WP_HITS_CAP:
        proc.Continue()
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE20: gone ({n})', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonWatchpoint:
                continue
            n += 1
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            regs = ' '.join(f'{k}={f0.FindRegister(k).GetValueAsUnsigned():#x}'
                            for k in ('rdi', 'rsi', 'rdx'))
            print(f'\n>> WP READ #{n} pc=wechat+0x{pc-base:x} {regs}', flush=True)
            print('   bt: ' + bt(t, base), flush=True)
            break
    print('DRIVE20: 捕获完成 — detach', flush=True)
    ci.HandleCommand('watchpoint delete', ro)
    ci.HandleCommand('process detach', ro)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive20.drive20 drive20')
