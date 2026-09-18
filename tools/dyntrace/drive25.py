import lldb
import time

# drive25：M-R2 终验——parse 入口 XML CDATA 改写（270099 x64）。
# drive24 判别实验结论：真实撤回走 parse(0x537db40)×3 + async-body(0x3951040)
# 但 0x538d700 零命中（drain 假设推翻）。parse 是 XML 源头（0x537e3b9 构建
# "replacemsg" 标签 → 0x5212c70 提取 → obj+0x1d0）——在 parse 入口把
# <replacemsg><![CDATA[原文]]></replacemsg> 内文等长改写为自定义文案，
# 下游全部拿新文本。本脚本 = runtime.m parse-hook 的同语义调试器版。
#
# 命中时先转储 rdi/rsi/rdx 三参（SSO/对象形态自动识别），确认 XML 载体；
# 含"撤回"needle 才改写；等长（尾部空格填充），SSO size/XML 结构不动。

ISREVOKEMSG = 0x4e8d440
PARSE = 0x537db40
NEEDLE = "撤回".encode("utf-8")
TAG_OPEN = b"<replacemsg>"
CDATA_OPEN = b"<![CDATA["
TAG_CLOSE = b"</replacemsg>"
TIME_CAP_S = 900
DUMP_CAP = 6          # 最多转储几轮参数
REWRITE_CAP = 3
DEFAULT_TIP = "🔒wxkeep M-R2 hook OK"
LOG = open('/tmp/wxarm/d25.log', 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def phrase():
    try:
        return open('/tmp/wxarm/drive25.txt', 'rb').read().strip()
    except Exception:
        return DEFAULT_TIP.encode('utf-8')


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
        d = proc.ReadMemory(ptr, min(size, 500), err)
        return ('L', size, ptr, d if err.Success() else b'')
    n = tag >> 1
    if n:
        return ('S', n, addr + 1, hdr[1:1 + n])
    return None


def describe_arg(proc, name, val):
    """三形态探测：SSO / 指针指向 SSO / 其他（hex 前缀）"""
    sso = read_sso(proc, val)
    if sso and sso[3][:1] in (b'<', b' ') or (sso and NEEDLE in sso[3]):
        log(f'   [{name}] SSO[{sso[0]}] len={sso[1]}: {sso[3][:80]!r}')
        return ('sso', val, sso)
    # 指针间接：[val] 是 SSO 头？
    err = lldb.SBError()
    p = proc.ReadMemory(val, 8, err)
    if err.Success():
        pv = int.from_bytes(p, 'little')
        if pv > 0x10000:
            sso2 = read_sso(proc, pv)
            if sso2 and (sso2[3][:1] == b'<' or NEEDLE in sso2[3]):
                log(f'   [{name}] *SSO[{sso2[0]}] len={sso2[1]}: {sso2[3][:80]!r}')
                return ('psso', pv, sso2)
    raw = proc.ReadMemory(val, 24, err)
    log(f'   [{name}] ? raw={raw.hex() if err.Success() else "unreadable"}')
    return (None, None, None)


def rewrite_cdata(proc, data_addr, size, tip):
    """等长改写承载提示文本的元素内文（兼容 <content> / <replacemsg>，
    可选 CDATA 包裹——尾部空格填充，XML 良构 + SSO size 不动）。
    实测 270099 推送撤回 XML 用 <content>（joy👀 案例）。"""
    err = lldb.SBError()
    buf = proc.ReadMemory(data_addr, size, err)
    if not err.Success() or NEEDLE not in buf:
        return False
    for tag in (b"<content>", b"<replacemsg>"):
        o = buf.find(tag)
        if o < 0:
            continue
        body = o + len(tag)
        if buf[body:body + len(CDATA_OPEN)] == CDATA_OPEN:
            body += len(CDATA_OPEN)
        close = buf.find(b"</" + tag[1:], body)
        if close < 0:
            continue
        room = close - body
        if len(tip) > room:
            log(f'   ! 文案 {len(tip)}B > <{tag[1:-1]}> 内文 {room}B —— 换短文案')
            return False
        new = tip + b' ' * (room - len(tip))
        proc.WriteMemory(data_addr + body, new, err)
        if not err.Success():
            log(f'   ! 写失败: {err}')
            return False
        log(f'   ✔ <{tag[1:-1]}> 内文已改写：{room}B → {tip!r}（尾部空格填充）')
        return True
    log('   （含针但 <content>/<replacemsg> 均未找到——转储完整 XML）')
    log('   full=' + repr(buf))
    return False


def bt(t, base, n=8):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


def drive25(debugger, command, result, internal_dict):
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
        log('DRIVE25: 地面真值未匹配 — 放弃')
        return
    log(f'DRIVE25: base={base:#x}')
    bp = target.BreakpointCreateByAddress(base + PARSE)
    log(f'DRIVE25: parse bp #{bp.GetID()} locs={bp.GetNumLocations()} '
        f'resolved={bp.GetNumResolvedLocations()}')

    proc.Continue()
    log('DRIVE25: 已恢复运行——撤回一条（私聊优先）')

    dumps = 0
    rewrites = 0
    hits = 0
    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE25: 进程退出/脱离')
            return
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        for t in proc:
            if t.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            if (pc - 1) != base + PARSE and pc != base + PARSE:
                continue
            hits += 1
            rdi = f0.FindRegister('rdi').GetValueAsUnsigned()
            rsi = f0.FindRegister('rsi').GetValueAsUnsigned()
            rdx = f0.FindRegister('rdx').GetValueAsUnsigned()
            log(f'\n@@@ parse #{hits} rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x}')
            log('   bt: ' + bt(t, base))
            if dumps >= DUMP_CAP and rewrites >= REWRITE_CAP:
                continue
            found_xml = None
            for nm, v in (('rdi', rdi), ('rsi', rsi), ('rdx', rdx)):
                if v < 0x10000:
                    continue
                kind, addr, sso = describe_arg(proc, nm, v)
                if kind and sso and (sso[3][:1] == b'<' or NEEDLE in sso[3]):
                    found_xml = (addr if kind == 'sso' else addr, sso)
            if found_xml and NEEDLE in found_xml[1][3]:
                if rewrites < REWRITE_CAP:
                    sso = found_xml[1]
                    if rewrite_cdata(proc, sso[2], sso[1], phrase()):
                        rewrites += 1
                        after = read_sso(proc, found_xml[0])
                        log(f'   改写后 XML: {after[3][:100]!r}')
                        log('   >>> 看微信界面：提示是否已变？ <<<')
            elif dumps < DUMP_CAP:
                dumps += 1
        proc.Continue()
    log(f'DRIVE25: 时间到（parse {hits} 次 / 改写 {rewrites} 次）——脱离')
    debugger.HandleCommand('process detach')


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive25.drive25 drive25')
