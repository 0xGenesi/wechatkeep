import lldb
import os
import time

# drive34：撤回执行管线站位定位轮（270100 x64，NATIVE 模式——编排
# `NATIVE=1 bash tools/dyntrace/d28_live.sh drive34`）。
#
# 53 轮静态图的实弹归位：apply(0x35103d0) 末端把消息批次交给
# 0x351f4e0→0x34f4440 批次处理器（元素=0x278 stride Message）。
# 本轮在各站位抓 bt，回答「删除原消息」与「tip 灰条插入」各在哪个站：
#   DISPATCH 0x34f4440  批次处理器入口（apply→0x351f4e0→此）
#   ACTION   0x34f4480  Phase1 per-msg 动作（pred 命中→0x530e280 再入库）
#   VCALL    0x34f4520  Phase4 逆序 vtable 调用位点
#   POST1-4  0x34f45a0/0x34f5560/0x34f5660/0x34f5840/0x34f5940
#   FLAGW    0x3510baf  apply 尾段 [found+0x278]=1 状态位写
#   PARSE    0x537dcd0  基址探针 + revokemsg 计数（对齐时间线）
# 判读：各站位命中清单 + bt → tip 插入/删除归位（VERDICT 行仅计数汇总；
# 语义判读人工/编排层）。只读观察。工件 → var/wxarm/d34.log

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

PARSE = 0x537DCD0
SITES = ((0x34F4440, 'dispatch'), (0x34F4480, 'action'), (0x34F4520, 'vcall'),
         (0x34F45A0, 'post1'), (0x34F5560, 'post2'), (0x34F5660, 'post3'),
         (0x34F5840, 'post4'), (0x34F5940, 'post5'), (0x3510BAF, 'flagw'))
TIME_CAP_S = int(os.environ.get('DRIVE_TIME_CAP_S', '900'))
MAX_CB_LOG = 8
LOG = open(os.path.join(OUT, 'd34.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=14):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def rd(proc, addr, n):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, n, err)
    return blob if err.Success() else None


def read_sso(proc, addr, cap=300):
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
        dd = proc.ReadMemory(ptr, min(size, cap), err)
        return (size, dd if err.Success() else b'')
    n = tag >> 1
    return (n, hdr[1:1 + min(n, cap)]) if n else None


counts = {}
NAMES = {}


def bump(nm):
    counts[nm] = counts.get(nm, 0) + 1
    return counts[nm]


def drive34(debugger, command, result, internal_dict):
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
        head = proc.ReadMemory(cand, 4, err)
        if not err.Success() or head.hex() != 'cffaedfe':
            continue
        d = proc.ReadMemory(cand + PARSE, 12, err)
        if not err.Success():
            continue
        h = d.hex()
        if h == '554889e54157415641554154':
            base = cand   # NATIVE 模式：只认原始序言
            log(f'DRIVE34: base={base:#x} parse12={h[:16]}… (native)')
            break
    if base is None:
        log('DRIVE34: parse 位点原始序言未匹配（NATIVE 模式要求 pristine）— 放弃')
        proc.Detach()
        return

    for off, nm in [(PARSE, 'parse')] + list(SITES):
        NAMES[base + off] = nm
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE34: 已恢复——请触发【群聊】撤回（原生观察：被撤消息会正常删除）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE34: 进程退出/脱离')
            break
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            key = pc - 1 if (pc - 1) in NAMES else (pc if pc in NAMES else None)
            if not key:
                continue
            nm = NAMES[key]
            rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
            rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
            if nm == 'parse':
                bump('parse')
                sso = read_sso(proc, rsi, 1024) if rsi > 0x10000 else None
                head = sso[1][:200] if sso else b''
                if b'revokemsg' not in head:
                    continue
                rv = bump('parse_revokemsg')
                log(f'\n@@@ parse/revokemsg #{rv} t=+{time.monotonic()-t0:.0f}s len={sso[0] if sso else 0}')
                if rv <= 4 and sso:
                    open(os.path.join(OUT, f'd34_parse_{rv}.xml'), 'wb').write(sso[1])
            elif nm == 'action':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    typ = rd(proc, rdi + 0x10, 4)
                    log(f'@@@ action #{n} msg={rdi:#x} type={int.from_bytes(typ, "little") if typ else "?"} '
                        f'sil={rsi:#x} bt: {bt(t, base, 8)}')
            elif nm == 'flagw':
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    log(f'@@@ flagw #{n} obj={rdi:#x} bt: {bt(t, base, 8)}')
            else:
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    arg = rsi if nm != 'dispatch' else rdi
                    log(f'@@@ {nm} #{n} t=+{time.monotonic()-t0:.0f}s rdi={rdi:#x} rsi={rsi:#x} bt: {bt(t, base, 10)}')
        if time.monotonic() - t0 >= TIME_CAP_S:
            break
        proc.Continue()

    log(f'DRIVE34 VERDICT-COUNTS: parse_revokemsg={counts.get("parse_revokemsg", 0)} '
        + ' '.join(f'{nm}={counts.get(nm, 0)}' for _, nm in SITES))
    log('DRIVE34: 收工——detach 恢复微信运行')
    proc.Detach()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive34.drive34 drive34')
