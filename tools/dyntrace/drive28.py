import lldb
import time

# drive28：群聊灰条第二轮（270100 x64）——3421BB0 完成回调三候选静态分类（
# ROADMAP ㉜）的实弹判定轮。
#
# 静态图谱（本轮产出，全部 270100 偏移，expected 已对 pristine 核验）：
#   HANDLER-CMP 0x3445E20  cmp dword [rax+0x118],2; je（㉘ 状态机分叉，==2 → 回调）
#   CB_ENTRY    0x3421BB0  完成回调（序言 = parse 同款纯栈 12B）
#                          rdi=r14 上下文 / rsi=r13 →[rsi]=svrid /
#                          edx=ebx（DBOP 模式，==2 分支传 1）/ ecx=r15d（插入条件）
#   LOOKUP      0x3421BE0  call 0x5311B30（唯一调用者=本回调；rdi=[rsi]=svrid）
#   DBOP        0x3421C4D  call 0x3680980（rdi=&opstruct(16B), rsi=[r14+0x360],
#                          rdx=svrid, ecx=edx。0x3680980 亦被
#                          UpdateCancelUpload(status9,ecx=2) 复用 →
#                          通用消息 DB 操作派发器，非物理删除专属）
#   INS-COND    0x3422375  cmp byte [rbp-0x184],0（= ecx 参数低字节；≠0 → 插入）
#   INSERT      0x342238E  call 0x3415A30（rsi=0x800000000 旗标；全消息 handler
#                          家族共用的入库漏斗 = AddMessageToDBbyWxID 同构）
#   ⚠ 毒值约束：DBOP 的 opstruct 由 movaps 写 0xAA×16 预初始化，返回槽
#     [rbp-0x198] 被下游 retain（lock inc [rax+8]）——未来「跳过 DBOP」补丁
#     若只 NOP call 必崩；须让被调方正常写回结构（或改 svrid/模式参数）。
#
# 实验矩阵（两次真实群聊撤回）：
#   A 惰性态（runtime keep_message=false 透传，newmsgid 原样）——
#     预期 CB/LOOKUP/DBOP/INSERT 全链命中，INSERT 的 rdi 里应见服务端
#     replacemsg 文案（撤回 needle）→ 三分类定案 + 插入数据源定案
#   B 防护态（keep_message=true，newmsgid=0）——预期链路不达（对照组，
#     解释现状群聊静默）
#
# 观察轮（只读不改）。工件 → var/wxarm/d28*.log/.bin

import os
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

PARSE = 0x537dcd0          # 基址探针位点（hook 桩签名地面真值）
HANDLER_CMP = 0x3445E20
CB_ENTRY = 0x3421BB0
LOOKUP = 0x3421BE0
DBOP = 0x3421C4D
INS_COND = 0x3422375
INSERT = 0x342238E
NEEDLE = "撤回".encode("utf-8")
TIME_CAP_S = 900
LOG = open(os.path.join(OUT, 'd28.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=12):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def rd(proc, addr, n):
    err = lldb.SBError()
    blob = proc.ReadMemory(addr, n, err)
    return blob if err.Success() else None


def u64(blob, off):
    return int.from_bytes(blob[off:off+8], 'little') if blob and len(blob) >= off+8 else None


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
        d = proc.ReadMemory(ptr, min(size, cap), err)
        return (size, d if err.Success() else b'')
    n = tag >> 1
    return (n, hdr[1:1 + min(n, cap)]) if n else None


counts = {}
NAMES = {}


def bump(nm):
    counts[nm] = counts.get(nm, 0) + 1
    return counts[nm]


def dump_insert_struct(proc, rdi, seq):
    """INSERT 的 rdi = tip 数据结构——找 replacemsg 文案所在字段。"""
    blob = rd(proc, rdi, 0x140)
    if not blob:
        log(f'   rdi 不可读')
        return
    open(os.path.join(OUT, f'd28_insert_{seq}.bin'), 'wb').write(blob)
    log(f'   rdi dump → d28_insert_{seq}.bin (0x140B)')
    for off in range(0, 0x138, 8):
        s = read_sso(proc, rdi + off, 96)
        if s and s[1] and (NEEDLE in s[1] or (4 <= s[0] <= 80)):
            mark = ' ★NEEDLE' if NEEDLE in s[1] else ''
            log(f'   rdi+{off:#x} len={s[0]}: {s[1][:80]!r}{mark}')


def drive28(debugger, command, result, internal_dict):
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()

    # 地面真值（drive27 同款字节探针）：parse 位点 = 原始序言或 hook 桩
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
            log(f'DRIVE28: base={base:#x} parse12={h[:16]}…')
            break
    if base is None:
        log('DRIVE28: parse 位点地面真值未匹配 — 放弃')
        return

    for off, nm in ((HANDLER_CMP, 'handlercmp'), (CB_ENTRY, 'cb'),
                    (LOOKUP, 'lookup'), (DBOP, 'dbop'),
                    (INS_COND, 'inscond'), (INSERT, 'insert')):
        NAMES[base + off] = nm
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE28: 已恢复——请触发【群聊】撤回一次（观察轮：只读）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE28: 进程退出/脱离')
            return
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
            rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
            rcx = f0.FindRegister('rcx').GetValueAsUnsigned()
            if nm == 'handlercmp':
                n = bump(nm)
                if n <= 8:
                    msg = rd(proc, rax := f0.FindRegister('rax').GetValueAsUnsigned(), 0x120)
                    s118 = u64(msg, 0x118) if msg else None
                    typ = int.from_bytes(msg[0xc:0x10], 'little', signed=True) if msg else None
                    log(f'\n@@@ handlercmp #{n} msg={rax:#x} type={typ} +0x118={s118:#x} bt: {bt(t, base)}')
            elif nm == 'cb':
                n = bump(nm)
                if n <= 4:
                    sv = u64(rd(proc, rsi, 8), 0) if rsi > 0x10000 else None
                    log(f'\n@@@ cb #{n} rdi={rdi:#x} rsi=[{rsi:#x}]→svrid={sv} '
                        f'edx(mode)={rdx:#x} ecx(inscond)={rcx:#x}')
                    log('   bt: ' + bt(t, base))
            elif nm == 'lookup':
                n = bump(nm)
                if n <= 4:
                    log(f'@@@ lookup #{n} rdi(svrid)={rdi:#x}')
            elif nm == 'dbop':
                n = bump(nm)
                if n <= 4:
                    blob = rd(proc, rdi, 16)
                    log(f'@@@ dbop #{n} rdi=&opstruct({blob.hex() if blob else "?"}) '
                        f'rsi={rsi:#x} rdx(svrid)={rdx:#x} ecx(mode)={rcx:#x}')
            elif nm == 'inscond':
                n = bump(nm)
                if n <= 4:
                    rbp = f0.FindRegister('rbp').GetValueAsUnsigned()
                    cond = rd(proc, rbp - 0x184, 1)
                    log(f'@@@ inscond #{n} [rbp-0x184]={cond.hex() if cond else "?"}')
            elif nm == 'insert':
                n = bump(nm)
                if n <= 4:
                    log(f'\n@@@ insert #{n} rdi={rdi:#x} rsi(flags)={rsi:#x}')
                    log('   bt: ' + bt(t, base))
                    if rdi > 0x10000:
                        dump_insert_struct(proc, rdi, n)
        proc.Continue()
    log('DRIVE28: 时限到，收工')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive28.drive28 drive28')
