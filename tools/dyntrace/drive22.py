import lldb
import time

# drive22：M-R2 hook 点终验 + M-R4 状态写捕获（270099 x64，附加模式）。
#
# 使用：微信保持运行（keeptip 态），另开终端:
#   lldb -b -p $(pgrep -f 'WeChat.app/Contents/MacOS/WeChat$') \
#        -o 'command script import tools/dyntrace/drive22.py' -o drive22
# 然后用另一账号撤回一条消息（私聊优先）。
#
# 本轮回答三个问题（一轮真实撤回全部拿下）：
# 1. isRevokemsg(0x4e8d440) 是否以「到达 tip 消息内容串」为参被调？
#    （M-R2 hook=isRevokemsg 入口 + SSO 原地改写 的前提）
#    → 每次命中打印 rdi 的 SSO 内容 + 调用方回溯；含"撤回"的串另挂读 WP
#      捕获其后续消费者（入库/渲染链）。
# 2. 异步撤回任务体 0x3951040 与状态写 0x355aa90（mov [rdx+0x118],9）是否命中；
#    命中即抓 rdx 对象转储（M-R4 消息标记位点：状态写与删除分离）。
# 3. 解析函数 0x537db40 的 newmsgid 存储后值（keeptip 下应为 0）。
#
# 教训沉淀（drive17-21）：
# - 解密循环 site / producer site 是冷路径，启动+空闲期零命中——别再当断点用
# - SBProcess.Continue() 无停止事件时阻塞：空闲等待必须用 listener WaitForEvent
# - 长串 SSO 的 ptr 指向串首（含昵称前缀），needle 在串中部——反查必须按
#   「ptr ≤ needle < ptr+size」验证，不能按指针值精确匹配
# - 本版 lldb Python 无 GetMemoryRegionAtIndex/SBMemoryRegionList，
#   枚举区域用 `memory region` 命令逐段解析

ISREVOKEMSG = 0x4e8d440   # 地面真值（keeptip 态原始序言）
KEEP_SITE = 0x537e39d
POST_STORE = 0x537e3a9    # newmsgid 存 [rbx+0x1C8] 之后
ASYNC_BODY = 0x3951040    # 异步撤回任务体（storage resolver 的调用方）
STATUS_WRITE = 0x355aa90  # mov [rdx+0x118],9 撤回状态写（M-R4）
PARSE = 0x537db40

NEEDLE = "撤回".encode("utf-8")
TIME_CAP_S = 900          # 15 分钟窗口，足够等一次人工撤回
REVOKEMSG_CAP = 24        # isRevokemsg 命中打印上限
WP_HITS_CAP = 6
TIP_WP_CAP = 2


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
        return ptr if ptr > 0x10000 else None
    return addr + 1


def bt(t, base, n=14):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def drive22(debugger, command, result, internal_dict):
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    ci = debugger.GetCommandInterpreter()
    r = lldb.SBCommandReturnObject()
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
        print('DRIVE22: 地面真值未匹配（变体是否为 keeptip？）— 放弃', flush=True)
        return
    ks = proc.ReadMemory(base + KEEP_SITE, 5, err)
    print(f'DRIVE22: base={base:#x} keep-site={ks.hex()}（4831c0=keeptip ✓）', flush=True)

    sites = {}
    for off, nm, in ((ISREVOKEMSG, 'isRevokemsg'), (POST_STORE, 'post-store'),
                     (ASYNC_BODY, 'async-body'), (STATUS_WRITE, 'status-write'),
                     (PARSE, 'parse')):
        b = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        print(f'DRIVE22: bp {nm} @0x{off:x} #{b.GetID()} locs={b.GetNumLocations()}', flush=True)
    print('DRIVE22: 就绪——现在用另一账号撤回一条消息（私聊优先）', flush=True)

    listener = lldb.SBListener('d22log')
    proc.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()

    rm_count = 0
    wp_hits = 0
    tip_wps = 0
    other = {}
    last_hb = time.monotonic()
    while time.monotonic() - t0 < TIME_CAP_S:
        proc.Continue()
        listener.WaitForEvent(2, event)
        if time.monotonic() - last_hb > 60:
            last_hb = time.monotonic()
            print(f'DRIVE22: [hb] {int(time.monotonic()-t0)}s isRevokemsg={rm_count} '
                  f'other={other} wp={wp_hits}', flush=True)
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            print(f'DRIVE22: gone', flush=True)
            return
        if state != lldb.eStateStopped:
            continue
        for t in proc:
            reason = t.GetStopReason()
            if reason == lldb.eStopReasonWatchpoint and tip_wps:
                wp_hits += 1
                f0 = t.GetFrameAtIndex(0)
                pc = f0.GetPC()
                regs = ' '.join(f'{k}={f0.FindRegister(k).GetValueAsUnsigned():#x}'
                                for k in ('rdi', 'rsi', 'rdx'))
                print(f'\n>> TIP-WP READ #{wp_hits} pc=wechat+0x{pc-base:x} {regs}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
                if wp_hits >= WP_HITS_CAP:
                    print('DRIVE22: tip 消费链捕获完成 — detaching', flush=True)
                    ci.HandleCommand('process detach', r)
                    return
                break
            if reason != lldb.eStopReasonBreakpoint:
                continue
            pc = t.GetFrameAtIndex(0).GetPC()
            nm = sites.get(pc)
            if nm is None:
                continue
            f0 = t.GetFrameAtIndex(0)
            if nm == 'isRevokemsg':
                rm_count += 1
                if rm_count > REVOKEMSG_CAP:
                    break
                rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
                s = read_sso(proc, rdi) if rdi > 0x10000 else b''
                try:
                    txt = s.decode('utf-8', 'replace')[:80]
                except Exception:
                    txt = repr(s[:60])
                mark = ' ★★含撤回' if NEEDLE in s else ''
                print(f'\n>> [isRevokemsg] #{rm_count} rdi={rdi:#x} str="{txt}"{mark}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
                if NEEDLE in s and tip_wps < TIP_WP_CAP:
                    da = sso_data_addr(proc, rdi)
                    if da:
                        ci.HandleCommand(f'watchpoint set expression -w read -s 8 -- 0x{da:x}', r)
                        if r.Succeeded():
                            tip_wps += 1
                            print(f'   ★ tip 内容读-WP #{tip_wps} @0x{da:x}', flush=True)
            elif nm == 'post-store':
                other['post-store'] = other.get('post-store', 0) + 1
                rbx = f0.FindRegister('rbx').GetValueAsUnsigned()
                nmv = int.from_bytes(proc.ReadMemory(rbx + 0x1C8, 8, err), 'little') \
                    if err.Success() and rbx else -1
                print(f'\n>> [post-store] obj={rbx:#x} newmsgid={nmv:#x}（keeptip=0 ✓）', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
            elif nm == 'async-body':
                other['async-body'] = other.get('async-body', 0) + 1
                print(f'\n>> [async-body] #{other["async-body"]} tid={t.id}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
                regs = {k: f0.FindRegister(k).GetValueAsUnsigned()
                        for k in ('rdi', 'rsi', 'rdx', 'rcx', 'rbx')}
                print('   regs: ' + ' '.join(f'{k}={v:#x}' for k, v in regs.items()), flush=True)
                blob = proc.ReadMemory(regs['rdi'], 0x120, err) if err.Success() else b''
                if err.Success():
                    open('/tmp/wxarm/d22_asyncobj.bin', 'wb').write(blob)
                    print('   → /tmp/wxarm/d22_asyncobj.bin', flush=True)
            elif nm == 'status-write':
                other['status-write'] = other.get('status-write', 0) + 1
                rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
                print(f'\n>> [status-write] ★M-R4 rdx 对象={rdx:#x} tid={t.id}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
                blob = proc.ReadMemory(rdx, 0x300, err)
                if err.Success():
                    open('/tmp/wxarm/d22_statusobj.bin', 'wb').write(blob)
                    print('   → /tmp/wxarm/d22_statusobj.bin（+0x118 将被写 9）', flush=True)
            elif nm == 'parse':
                other['parse'] = other.get('parse', 0) + 1
                print(f'\n>> [parse] #{other["parse"]} tid={t.id}', flush=True)
                print('   bt: ' + bt(t, base), flush=True)
            break
    print('DRIVE22: 时限到达 — detaching', flush=True)
    ci.HandleCommand('process detach', r)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive22.drive22 drive22')
