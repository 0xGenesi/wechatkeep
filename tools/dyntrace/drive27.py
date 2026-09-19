import lldb
import time

# drive27：群聊灰条深 RE（270100 x64）——静态图谱（ROADMAP ㉘）的实弹验证。
#
# 已知静态图谱（全部 270100 偏移）：
#   parse 汇点 0x537dcd0（rsi = sysmsg XML SSO，drive25 地面真值）
#   revoke_manager 二次分派 0x394be13 所在函数（调用者 B [0x355b0c0..)）
#   状态写函数 0x355abf0（mov [rdx+0x118],9 @+0x70；调用者 A/B）
#   消息状态谓词 0x5034aa0/0x5034ae0/0x5034ac0（+0xC/+0x10 状态机）
#   async-body 0x3951040（rsi = 消息向量 0x278 步长）
#
# 目标问题（每轮捕获都直接回答一部分）：
#   Q1 群聊撤回 sysmsg XML 原始形态（含未被 hook 清零的 newmsgid）
#   Q2 二次分派点 rsi-对象长什么样（撤回指令载体）
#   Q3 状态写触发时：rdi+0xb78 服务、rdx 消息对象、+0x118 前后值、
#      完整 bt（确认走调用者 A 还是 B）
#   Q4 async-body 向量里被撤消息的 +0x118 状态迁移
#
# 观察轮（本脚本）：只读不改。hook 配置已设为情性（keep_message=false
# 无 tip_text——parse 入口透传），XML 在 parse 断点处是原始字节。
# 工件写 var/wxarm/（持久），日志 d27.log。

import os
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

PARSE = 0x537dcd0
DISPATCH2 = 0x394be13
STATUS_WRITE = 0x355abf0
ASYNC_BODY = 0x3951040
NEEDLE = "撤回".encode("utf-8")
TIME_CAP_S = 900
LOG = open(os.path.join(OUT, 'd27.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def read_sso(proc, addr, cap=400):
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


def bt(t, base, n=12):
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
    s10 = int.from_bytes(blob[0x10:0x14], 'little')
    s118 = int.from_bytes(blob[0x118:0x120], 'little')
    s11c = int.from_bytes(blob[0x11c:0x120], 'little')
    log(f'    msg[{idx}] @{addr:#x} type={mtype} sub={s10} +0x118={s118:#x} +0x11c={s11c:#x}')
    for off in (0x18, 0x30, 0x48, 0x168, 0x198):
        s = read_sso(proc, addr + off, 64)
        if s and s[1]:
            mark = ' ★' if NEEDLE in s[1] else ''
            log(f'      +{off:#x} len={s[0]}: {s[1][:60]!r}{mark}')


parse_n = disp_n = st_n = async_n = 0


def drive27(debugger, command, result, internal_dict):
    global parse_n, disp_n, st_n, async_n
    t0 = time.monotonic()
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    err = lldb.SBError()

    # 地面真值：wechat.dylib 模块的 parse 位点。注意该 dylib 由壳程序手动
    # 映射——SBModule.GetLoadAddress 可能返回异常基址（d27 实测 0x12b435000
    # 处 UUID 解析失败但 hook 桩 48b8…ffe0 在 parse 位点在——runtime dylib
    # 同款「按字节特征探针」最可靠）：候选 = 模块表地址 + hook 桩签名验证。
    # 惰性实验态（keep_message=false）下桩也在场（hook 恒装）——两种 12B
    # 都接受：原像 554889E54157…（未装）或桩 48b8????????????FFE0（已装）。
    base = None
    cands = []
    for m in target.modules:
        if m.GetFileSpec().GetFilename() != 'wechat.dylib':
            continue
        cand = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
        if cand not in (0, lldb.LLDB_INVALID_ADDRESS):
            cands.append(cand)
    for cand in cands:
        head = proc.ReadMemory(cand, 4, err)
        if not err.Success() or head.hex() != 'cffaedfe':
            continue
        d = proc.ReadMemory(cand + PARSE, 12, err)
        if not err.Success():
            continue
        h = d.hex()
        # 桩 = 48b8 + imm64(16 hex) + ffe0 → 总 24 hex；imm64 是 hook 函数地址
        # （含 0 填充高位），只判首尾：48b8 前缀 + ffe0 后缀。
        if h == '554889e54157415641554154' or (h.startswith('48b8') and h.endswith('ffe0')):
            base = cand
            log(f'DRIVE27: base={base:#x} parse12={h[:16]}…（{"hook 桩在场-惰性" if h.startswith("48b8") else "原始序言"}）')
            break
    if base is None:
        log('DRIVE27: parse 位点地面真值未匹配 — 放弃')
        return

    sites = {}
    for off, nm in ((PARSE, 'parse'), (DISPATCH2, 'disp2'), (STATUS_WRITE, 'status'), (ASYNC_BODY, 'async')):
        bp = target.BreakpointCreateByAddress(base + off)
        sites[base + off] = nm
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE27: 已恢复——请触发【群聊】撤回一次（观察轮：只读）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE27: 进程退出/脱离')
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
            if nm == 'parse' and parse_n < 12:
                parse_n += 1
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                s = read_sso(proc, rsi) if rsi > 0x10000 else None
                if s and s[1]:
                    body = s[1]
                    log(f'\n@@@ parse #{parse_n} xml len={s[0]}')
                    log(f'   {body[:360]!r}')
                    if b'<newmsgid>' in body:
                        open(os.path.join(OUT, f'd27_parse_{parse_n}.xml'), 'wb').write(body)
                        log(f'   ★ 撤回 XML 存档 → d27_parse_{parse_n}.xml')
            elif nm == 'disp2' and disp_n < 6:
                disp_n += 1
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                log(f'\n@@@ disp2 #{disp_n} rsi={rsi:#x}')
                log('   bt: ' + bt(t, base))
                if rsi > 0x10000:
                    err2 = lldb.SBError()
                    blob = proc.ReadMemory(rsi, 0x180, err2)
                    if err2.Success():
                        open(os.path.join(OUT, f'd27_disp2_{disp_n}.bin'), 'wb').write(blob)
                        # 常见 SSO 槽位尝试（0x1d0=tip, 0x1e8=wxid, 0x1a8=类型，271C8=newmsgid@对象）
                        for off in (0x1a8, 0x1c8, 0x1d0, 0x1e8):
                            s = read_sso(proc, rsi + off, 80)
                            if s and s[1]:
                                log(f'   rsi+{off:#x} len={s[0]}: {s[1][:70]!r}')
                        v = int.from_bytes(blob[0x1c8:0x1d0], 'little')
                        log(f'   rsi+0x1C8(u64)={v:#x}')
                        log(f'   dump → d27_disp2_{disp_n}.bin (0x180B)')
            elif nm == 'status' and st_n < 6:
                st_n += 1
                rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
                log(f'\n@@@ status-write #{st_n} rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x}')
                log('   bt: ' + bt(t, base))
                if rdx > 0x10000:
                    blob = proc.ReadMemory(rdx, 0x278, err)
                    if err.Success():
                        open(os.path.join(OUT, f'd27_status_{st_n}.bin'), 'wb').write(blob)
                        s118 = int.from_bytes(blob[0x118:0x120], 'little')
                        s11c = int.from_bytes(blob[0x11c:0x120], 'little')
                        mtype = int.from_bytes(blob[0xc:0x10], 'little')
                        log(f'   msg type={mtype} +0x118={s118:#x} +0x11c={s11c:#x} dump→d27_status_{st_n}.bin')
            elif nm == 'async' and async_n < 6:
                async_n += 1
                rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
                log(f'\n@@@ async-body #{async_n} rsi={rsi:#x}')
                log('   bt: ' + bt(t, base))
                err2 = lldb.SBError()
                vec = proc.ReadMemory(rsi, 16, err2)
                if err2.Success():
                    start = int.from_bytes(vec[0:8], 'little')
                    end = int.from_bytes(vec[8:16], 'little')
                    count = (end - start) // 0x278 if end > start else 0
                    log(f'   向量 [{start:#x},{end:#x}) count={count}')
                    for i in range(min(count, 5)):
                        dump_msg(proc, start + i * 0x278, i)
        proc.Continue()
    log(f'DRIVE27: 时间到（parse {parse_n}/disp {disp_n}/status {st_n}/async {async_n}）——脱离')
    debugger.HandleCommand('process detach')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive27.drive27 drive27')
