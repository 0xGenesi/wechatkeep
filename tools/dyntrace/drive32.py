import lldb
import os
import time

# drive32：M-R4 验证轮（270100 x64，防护态 = runtime hook 清零 newmsgid 的
# 真机流，日常配置直接跑——hook 清零正是被观察对象，无需惰性化）。
#
# ㊿ 静态图谱的实弹验证 + miss 分支行为抓捕：
#   PARSE       0x537dcd0  基址探针 + revokemsg 到达计数（hook 桩双形态门）
#   LOOKUP      0x3541fe0  查库入口（revoke 专属，㊿ 实锤）：rsi = newmsgid 实参
#                          ——防护态预期收到 0（hook 清零到达此处 = 端到端证明）
#   LOOKUP_RET  0x394bfbb  call 后第一站：rax = 查库结果（防护态预期 0）
#   DECISION    0x394c058  test r13,r13 分叉点：读 r13 + [rbp-0x6e8] 旗标
#   APPLY       0x35103d0  删除执行原语（17 handler 共用）——防护态预期零命中
#                          （查库 miss → 不该到达；命中即推翻 ㊿ 模型）
#   MISS        0x394c904  无删除分支入口——防护态预期命中；bt 揭示上游
#   MISS 内业务调用候选（tip 插入嫌疑，静态提取）：0x53105a0 / 0x355a180 /
#   0x355a200 / 0x351e000 / 0x394e620 —— 命中即 M-R4 群提示插入候选点
#
# 判读（VERDICT）：
#   miss 命中 + APPLY 零命中 = MODEL-CONFIRMED（㊿ 模型端到端成立，hook 置
#   r13=0 的 M-R4 候选一安全）+ miss 业务调用清单（tip 插入选址素材）
#   APPLY 命中 = MODEL-VIOLATED（删除在 miss 下仍发生——推翻候选一）
#   LOOKUP 未命中 = NEGATIVE（撤回未到达）
#
# 观察轮（只读不改）。工件 → var/wxarm/d32.log

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

PARSE = 0x537DCD0
LOOKUP = 0x3541FE0
LOOKUP_RET = 0x394BFBB
DECISION = 0x394C058
APPLY = 0x35103D0
MISS = 0x394C904
MISS_CANDS = ((0x394D9C9, 'miss_53105a0'), (0x394D263, 'miss_355a180'),
              (0x394DB22, 'miss_355a200'), (0x394D620, 'miss_351e000'),
              (0x394D93A, 'miss_394e620'))
NEEDLE = b'revokemsg'
TIME_CAP_S = int(os.environ.get('DRIVE_TIME_CAP_S', '900'))
MAX_CB_LOG = 6
LOG = open(os.path.join(OUT, 'd32.log'), 'a', buffering=1)


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


def drive32(debugger, command, result, internal_dict):
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
        if h == '554889e54157415641554154' or (h.startswith('48b8') and h.endswith('ffe0')):
            base = cand
            log(f'DRIVE32: base={base:#x} parse12={h[:16]}…')
            break
    if base is None:
        log('DRIVE32: parse 位点地面真值未匹配 — 放弃')
        proc.Detach()
        return

    sites = [(PARSE, 'parse'), (LOOKUP, 'lookup'), (LOOKUP_RET, 'lookup_ret'),
             (DECISION, 'decision'), (APPLY, 'apply'), (MISS, 'miss')] + list(MISS_CANDS)
    for off, nm in sites:
        NAMES[base + off] = nm
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE32: 已恢复——请触发【群聊】撤回（防护态观察；卡顿=断点计数）')
    # 时限收口：不能在脚本内做——Continue() 是不释放 GIL 的 C++ 调用，任何
    # Python 线程（threading.Timer 实测）都会被饿死（drive32 22:33 实证：
    # Timer 到点后从未执行）。SIGINT 亦被 batch 模式忽略。唯一可靠收口 =
    # 编排层 shell watchdog 对 lldb 发 SIGTERM（debuggee 运行态下实测存活
    # 三轮）；本脚本死亡时 VERDICT 行不落盘，由编排层从日志计数判读
    # （capture_p：miss 命中 && apply 零命中 = MODEL-CONFIRMED）。

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE32: 进程退出/脱离')
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
                if NEEDLE not in head:
                    continue
                rv = bump('parse_revokemsg')
                log(f'\n@@@ parse/revokemsg #{rv} t=+{time.monotonic()-t0:.0f}s len={sso[0] if sso else 0}')
                if rv <= 4 and sso:
                    open(os.path.join(OUT, f'd32_parse_{rv}.xml'), 'wb').write(sso[1])
            elif nm == 'lookup':
                n = bump(nm)
                log(f'@@@ lookup #{n} rdi(obj)={rdi:#x} rsi(newmsgid)={rsi:#x}')
            elif nm == 'lookup_ret':
                n = bump(nm)
                rax = f0.FindRegister('rax').GetValueAsUnsigned()
                log(f'@@@ lookup_ret #{n} rax(result)={rax:#x}')
            elif nm == 'decision':
                n = bump(nm)
                r13 = f0.FindRegister('r13').GetValueAsUnsigned()
                err2 = lldb.SBError()
                flag = proc.ReadMemory(f0.FindRegister('rbp').GetValueAsUnsigned() - 0x6e8, 1, err2)
                log(f'@@@ decision #{n} r13={r13:#x} flag={flag.hex() if err2.Success() else "?"}')
            elif nm == 'apply':
                n = bump(nm)
                rcx = f0.FindRegister('rcx').GetValueAsUnsigned()
                log(f'\n@@@ apply #{n} rdi={rdi:#x} rsi={rsi:#x} rcx(found)={rcx:#x} — '
                    f'防护态不应到达！bt: {bt(t, base)}')
            elif nm == 'miss':
                n = bump(nm)
                log(f'\n@@@ miss #{n} t=+{time.monotonic()-t0:.0f}s bt: {bt(t, base)}')
            else:   # miss_* 候选
                n = bump(nm)
                if n <= MAX_CB_LOG:
                    log(f'@@@ {nm} #{n} rdi={rdi:#x} rsi={rsi:#x} bt: {bt(t, base, 10)}')
        if time.monotonic() - t0 >= TIME_CAP_S:
            break
        proc.Continue()

    lk = counts.get('lookup', 0)
    ap = counts.get('apply', 0)
    ms = counts.get('miss', 0)
    cands = {nm: counts.get(nm, 0) for _, nm in MISS_CANDS}
    if ap:
        v = 'MODEL-VIOLATED'
    elif ms and lk:
        v = 'MODEL-CONFIRMED'
    elif lk:
        v = 'HIT-NO-MISS'
    else:
        v = 'NEGATIVE'
    log(f'DRIVE32 VERDICT: {v} lookup={lk} lookup_ret={counts.get("lookup_ret", 0)} '
        f'apply={ap} miss={ms} miss_cands={cands} parse_revokemsg={counts.get("parse_revokemsg", 0)}')
    if v == 'MODEL-CONFIRMED':
        log('DRIVE32: ㊿ 模型端到端成立（清零→查库0→miss→不删除）；miss 候选命中清单即 tip 插入选址素材')
    elif v == 'MODEL-VIOLATED':
        log('DRIVE32: 删除在 miss 下仍发生——候选一（置 r13=0）被推翻，重新选址')
    log('DRIVE32: 收工——detach 恢复微信运行')
    proc.Detach()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive32.drive32 drive32')
