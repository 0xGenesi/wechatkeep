import lldb
import time

# drive19：M-R2 消费点定位——全堆扫描模式（270099 x64，启动后执行）。
# 前两轮教训：管道断点=冷路径；Continue() 无停止时阻塞。
# 本轮：spawn → 模块就绪 → 等 UI 稳定 → 全堆扫"撤回了一条消息" SSO 串 →
# 反查 SSO 头（long-form ptr 指回）→ 挂读监视点（x86_64 4 个硬件 WP）→
# Continue 阻塞等命中（外部负责触发/超时杀会话）。命中即打印消费链回溯。

ISREVOKEMSG = 0x4e8d440
KEEP_SITE = 0x537e39d
NEEDLE = "撤回".encode("utf-8")
SETTLE_S = 25          # 模块就绪后等 UI/首屏稳定
SCAN_CAP_BYTES = 2 << 30   # 最多扫 2GB
REGION_MAX = 96 << 20       # 跳过 >96MB 的单区域
MAX_WP = 4
WP_HITS_CAP = 6


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


def bt(t, base, n=16):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def heap_scan(proc, base, verbose=True):
    """返回 [(sso_hdr_addr, data_addr, sample)]：含 NEEDLE 的 SSO 串"""
    err = lldb.SBError()
    regions = []
    # SBMemoryRegionList 未暴露 → 用 memory region 命令逐段解析
    ci = proc.GetTarget().GetDebugger().GetCommandInterpreter()
    ro = lldb.SBCommandReturnObject()
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
        if 'rw' in perm and e - b <= REGION_MAX and e > b:
            regions.append((b, e - b))
        addr = e
    if not regions:
        # 后备：常见堆区粗扫（MALLOC 栈区由命令枚举失败时）
        print('DRIVE19: memory-region 枚举失败', flush=True)
    if verbose:
        print(f'DRIVE19: RW regions={len(regions)} total={sum(s for _, s in regions)/(1<<20):.0f}MB', flush=True)

    # 第 1 遍：找数据区 needle
    data_hits = []
    scanned = 0
    for begin, sz in regions:
        off = 0
        CH = 1 << 20
        while off < sz:
            n = min(CH, sz - off)
            blob = proc.ReadMemory(begin + off, n, err)
            if not err.Success():
                break
            scanned += len(blob)
            pos = 0
            while True:
                i = blob.find(NEEDLE, pos)
                if i < 0:
                    break
                data_hits.append(begin + off + i)
                pos = i + 1
            off += n
        if scanned > SCAN_CAP_BYTES:
            break
    if verbose:
        print(f'DRIVE19: scanned={scanned/(1<<20):.0f}MB needle_hits={len(data_hits)}', flush=True)
        for h in data_hits[:40]:
            err2 = lldb.SBError()
            ctx = proc.ReadMemory(max(0, h - 48), 96, err2)
            print(f'  needle@{h:#x} ctx={ctx[:96]!r}' if err2.Success() else f'  needle@{h:#x}', flush=True)

    # 第 2 遍：反查 SSO 头——对每个 needle 位置，在 RW 区搜指向它的 8 字节指针值
    heads = []
    tgt = set()
    for h in data_hits[:80]:
        tgt.add(h)
        tgt.add(h - 8)
    tgt = list(tgt)[:96]
    for begin, sz in regions:
        off = 0
        CH = 1 << 20
        while off < sz:
            n = min(CH, sz - off)
            blob = proc.ReadMemory(begin + off, n, err)
            if not err.Success():
                break
            for tv in tgt:
                pos = 0
                pb = tv.to_bytes(8, 'little')
                while True:
                    i = blob.find(pb, pos)
                    if i < 0:
                        break
                    pos = i + 1
                    if i < 16 or (i % 8):
                        continue
                    k = i - 16   # SSO 头起点：tag@k, size@k+8, ptr@k+16
                    tag = blob[k]
                    size = int.from_bytes(blob[k+8:k+16], 'little')
                    if (tag & 1) and 6 <= size <= 65536:
                        heads.append((begin + off + k, tv))
            off += n
    if verbose:
        print(f'DRIVE19: SSO heads={len(heads)}', flush=True)
        for a, p in heads[:MAX_WP * 3]:
            d = read_sso(proc, a)
            print(f'  head@{a:#x} → {p:#x}: {d[:50]!r}', flush=True)
    return heads


def drive19(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    ci = debugger.GetCommandInterpreter()
    ro = lldb.SBCommandReturnObject()
    err = lldb.SBError()

    # 模块就绪（哨兵已在 launch 脚本里等待过；此处直接找）
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
        print('DRIVE19: base 不明 — 放弃', flush=True)
        return
    print(f'DRIVE19: base={base:#x} keep-site='
          f'{proc.ReadMemory(base+KEEP_SITE, 5, err).hex()}', flush=True)

    print(f'DRIVE19: 等待 {SETTLE_S}s 让首屏/会话列表稳定…', flush=True)
    time.sleep(SETTLE_S)

    heads = heap_scan(proc, base)
    if not heads:
        print('DRIVE19: 堆中无 tip SSO —— 记录后退出', flush=True)
        ci.HandleCommand('process detach', ro)
        return

    # 过滤：SSO 头附近 0x300 内存在 type==10000 字段 → 消息结构优先
    ranked = []
    for a, p in heads:
        ctx = proc.ReadMemory(max(0, a - 0x300), 0x330, err)
        score = 0
        if err.Success():
            for toff in (0x8, 0xC):
                for back in range(0, 0x300, 4):
                    v = int.from_bytes(ctx[back:back+4], 'little')
                    if v == 10000:
                        score = 1
                        break
                    # struct 起点未知，只做粗扫
                if score:
                    break
        ranked.append((score, a, p))
    ranked.sort(key=lambda x: -x[0])
    armed = 0
    for score, a, p in ranked:
        if armed >= MAX_WP:
            break
        wa = p if p > 0x10000 else a + 1
        ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{wa:x}', ro)
        if ro.Succeeded():
            armed += 1
            print(f'DRIVE19: read-WP#{armed} @0x{wa:x} (head@{a:#x} score={score})', flush=True)
    if armed == 0:
        print('DRIVE19: WP 布防失败', flush=True)
        ci.HandleCommand('process detach', ro)
        return

    print('DRIVE19: ARMED — WP 就绪，进入等待（外部触发渲染后命中）', flush=True)
    hits = 0
    while hits < WP_HITS_CAP:
        proc.Continue()   # 阻塞至下次停止
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE19: gone (wp_hits={hits})', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonWatchpoint:
                continue
            hits += 1
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            regs = ' '.join(f'{n}={f0.FindRegister(n).GetValueAsUnsigned():#x}'
                            for n in ('rdi', 'rsi', 'rdx'))
            print(f'\n>> WP READ #{hits} pc=wechat+0x{pc-base:x} {regs}', flush=True)
            print('   bt: ' + bt(t, base), flush=True)
            break
    print('DRIVE19: 捕获完成 — detaching', flush=True)
    ci.HandleCommand('watchpoint delete', ro)
    ci.HandleCommand('process detach', ro)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive19.drive19 drive19')
