import lldb
import time

# drive23：M-R2 hook 点实弹验证（270099 x64，附加模式）。
#
# 结论目标（一轮真实撤回收口）：
#   0x538d700 = 撤回信息排水函数（rdi=信息对象[+0x1C8 newmsgid]，
#   rsi=刚提取的 replacemsg 裸 SSO）。静态证据：parse@0x537e3b9 构建
#   "replacemsg" 标签（movabs 立即数）→ 0x5212c70 提取 → 对象+0x1d0 setter
#   （free 旧串/movups 写入/lea rsi 传递消费）就在本函数。
#
#   本脚本在命中时用调试器执行与 runtime dylib 完全相同的改写
#   （缩短式 SSO 原地重写）——若微信界面显示自定义文案，
#   则 M-R2 hook（0x538d700 入口 inline hook）语义端到端成立。
#
# 使用：
#   lldb -b -p $(pgrep -x WeChat) \
#        -o 'command script import tools/dyntrace/drive23.py' -o drive23
#   然后用另一账号撤回一条消息（私聊优先）。
#   文案可改：/tmp/wxarm/drive23.txt（UTF-8，≤原文长度；缺省用内置短语）

ISREVOKEMSG = 0x4e8d440       # 地面真值：原始序言 554889e553504889fb
DRAIN = 0x538d700              # M-R2 hook 目标
ASYNC_BODY = 0x3951040
PARSE = 0x537db40
TIME_CAP_S = 900
REWRITE_CAP = 3                # 最多改写次数（验证即可，别刷屏）
DEFAULT_TIP = "🔒wxkeep M-R2 hook OK"

LOG = open('/tmp/wxarm/d23.log', 'a', buffering=1)


def log(msg):
    print(msg, flush=True)
    LOG.write(msg + '\n')


def phrase():
    try:
        return open('/tmp/wxarm/drive23.txt', 'rb').read().strip()
    except Exception:
        return DEFAULT_TIP.encode('utf-8')


def read_sso(proc, addr):
    err = lldb.SBError()
    hdr = proc.ReadMemory(addr, 24, err)
    if not err.Success():
        return None
    tag = hdr[0]
    if tag & 1:
        size = int.from_bytes(hdr[8:16], 'little')
        ptr = int.from_bytes(hdr[16:24], 'little')
        if size == 0 or size > 65536 or ptr == 0:
            return None
        return ('L', size, ptr, proc.ReadMemory(ptr, min(size, 200), err))
    return ('S', tag >> 1, addr + 1, hdr[1:1 + (tag >> 1)])


def bt(t, base, n=12):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def rewrite_sso_inplace(proc, sso_addr, sso, tip):
    """与 runtime.m rewrite_tip_sso 同语义：缩短式原地改写"""
    err = lldb.SBError()
    kind, size, data_addr, data = sso
    if len(tip) > size:
        log(f'  ! 文案({len(tip)}B)超过原文({size}B) —— 放弃（换短文案）')
        return False
    proc.WriteMemory(data_addr, tip + b'\0' * min(size - len(tip), 8), err)
    if not err.Success():
        log(f'  ! 写数据失败: {err}')
        return False
    if kind == 'L':
        proc.WriteMemory(sso_addr + 8, len(tip).to_bytes(8, 'little'), err)  # size@+8
    else:
        proc.WriteMemory(sso_addr, bytes([len(tip) << 1]), err)              # tag@+0
    log(f'  ✔ 已原地改写：{size}B → {len(tip)}B {tip!r}')
    return True


def drive23(debugger, command, result, internal_dict):
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
        log('DRIVE23: 地面真值未匹配 — 放弃')
        return
    pro = proc.ReadMemory(base + DRAIN, 12, err)
    log(f'DRIVE23: base={base:#x}')
    log(f'DRIVE23: drain@{DRAIN:#x} 序言={pro.hex()}'
        f'（期望 554889e54157415641554154）')

    sites = {}
    for off, nm in ((DRAIN, 'drain'), (ASYNC_BODY, 'async-body'), (PARSE, 'parse')):
        target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
    log('DRIVE23: 就绪——现在用另一账号撤回一条消息（私聊优先）')

    listener = lldb.SBListener('d23')
    proc.GetBroadcaster().AddListener(listener,
                                   lldb.SBProcess.eBroadcastBitStateChanged)
    event = lldb.SBEvent()
    rewrites = 0
    other_hits = 0
    heartbeats = 0

    # 事件循环教训链（drive22/23 三轮实弹）：
    #  a) 附加 SIGSTOP 发生在挂 listener 前 → 必须显式恢复，否则永久冻结；
    #  b) 本 lldb 同步模式下 WaitForEvent 收不到 Continue 消费的停止事件
    #     → 冻在断点上。改用 GetState 轮询（drive22 实测可靠）：
    #     stopped → 处理 → Continue（同步，阻塞到下一次停止）。
    proc.Continue()
    log('DRIVE23: 已恢复微信运行（断点生效中）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE23: 进程退出/脱离')
            return
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            if heartbeats != int((time.monotonic() - t0) / 30):
                heartbeats = int((time.monotonic() - t0) / 30)
                log(f'DRIVE23: 运行中 {heartbeats*30}s（parse/async 计数 {other_hits}）')
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
            if nm == 'drain':
                rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                nm118 = int.from_bytes(proc.ReadMemory(rdi + 0x1c8, 8, err), 'little')
                log(f'\n@@@ drain rdi={rdi:#x}(obj) rsi={rsi:#x}(sso) '
                    f'obj+0x1C8 newmsgid={nm118:#x}')
                log('   bt: ' + bt(t, base))
                sso = read_sso(proc, rsi)
                if sso:
                    log(f'   rsi SSO[{sso[0]}] len={sso[1]}: {sso[3][:60]!r}')
                    if b'\xe6\x92\xa4\xe5\x9b\x9e' in sso[3] and rewrites < REWRITE_CAP:
                        rewrites += 1
                        rewrite_sso_inplace(proc, rsi, sso, phrase())
                        after = read_sso(proc, rsi)
                        log(f'   改写后: {after[3][:40]!r}')
                        log('   >>> 看微信界面：提示是否已变？ <<<')
                else:
                    log('   rsi 非 SSO 形态 —— 检查参数假设（打印 rdi 前缀）')
                    log('   rdi[0:24]=' + proc.ReadMemory(rdi, 24, err).hex())
            else:
                other_hits += 1   # parse 是全体 sysmsg 分发器：静默计数防刷屏
        proc.Continue()
    log('DRIVE23: 时间到——脱离')
    debugger.HandleCommand('process detach')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive23.drive23 drive23')
