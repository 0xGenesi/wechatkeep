import lldb
import os
import time

# drive36：原生删除机制定位轮（270100 x64，NATIVE 模式）——两段式观察点。
#
# 背景（54/55 轮）：原生撤回的删除+tip 绕过 revoke_manager 全链与 DB 漏斗，
# 六轮 bp 排除无一生效。本轮改用硬件观察点：在 revoke_manager 查库返回位
# （0x394bfbb）截获**原生命中**的消息对象（rax≠0），对它挂 8B 写观察点后
# 放行——下一个写该对象（或其 DB 行删除路径）的代码即删除执行者。
#
# 站位：
#   LOOKUP_RET 0x394bfbb  原生命中截获点：rax=found msg（≠0 才挂观察点）
#   APPLY      0x35103d0  对照（若 apply 在原生流可达则先命中）
# 判读：观察点命中站的 bt = 触碰消息对象的代码（删除/tip 候选全暴露）。
# 只读观察（观察点只读语义不阻断）。工件 → var/wxarm/d36.log

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), 'var', 'wxarm')
os.makedirs(OUT, exist_ok=True)

LOOKUP_RET = 0x394BFBB
APPLY = 0x35103D0
TIME_CAP_S = int(os.environ.get('DRIVE_TIME_CAP_S', '900'))
MAX_WP_LOG = 12
LOG = open(os.path.join(OUT, 'd36.log'), 'a', buffering=1)


def log(m):
    print(m, flush=True)
    LOG.write(m + '\n')


def bt(t, base, n=16):
    out = []
    for i in range(min(t.GetNumFrames(), n)):
        pc = t.GetFrameAtIndex(i).GetPC()
        out.append(f'wechat+0x{pc-base:x}' if base <= pc < base + 0x9f40000 else hex(pc))
    return ' <- '.join(out)


counts = {'lookup_ret': 0, 'apply': 0, 'watchpoint': 0}


def drive36(debugger, command, result, internal_dict):
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
        d = proc.ReadMemory(cand + 0x537DCD0, 12, err)
        if not err.Success():
            continue
        if d.hex() == '554889e54157415641554154':
            base = cand
            log(f'DRIVE36: base={base:#x} (native pristine confirmed)')
            break
    if base is None:
        log('DRIVE36: parse 原始序言未匹配 — 放弃')
        proc.Detach()
        return

    for off, nm in ((LOOKUP_RET, 'lookup_ret'), (APPLY, 'apply')):
        bp = target.BreakpointCreateByAddress(base + off)
        log(f'  bp {nm}@{off:#x} #{bp.GetID()} resolved={bp.GetNumResolvedLocations()}')

    def arm_watch(addr):
        """8B 写观察点：现代/经典两代 API 依序尝试。"""
        error = lldb.SBError()
        try:   # 现代重载：WatchpointType
            wp = target.WatchAddress(addr, 8, lldb.eWatchpointTypeWrite, error)
            if wp.IsValid():
                return wp
        except Exception:
            pass
        try:   # 经典重载：bool read/write
            wp = target.WatchAddress(addr, 8, False, True, error)
            return wp
        except Exception:
            return None

    watch_addr = None
    wp = None
    armed = False
    proc.Continue()
    log('DRIVE36: 已恢复——请触发【群聊】撤回（原生观察；命中消息对象后自动挂观察点）')

    while time.monotonic() - t0 < TIME_CAP_S:
        state = proc.GetState()
        if state in (lldb.eStateExited, lldb.eStateInvalid, lldb.eStateDetached):
            log('DRIVE36: 进程退出/脱离')
            break
        if state != lldb.eStateStopped:
            time.sleep(0.05)
            continue
        stopped_by_wp = False
        for t in proc:
            reason = t.GetStopReason()
            f0 = t.GetFrameAtIndex(0)
            pc = f0.GetPC()
            if reason == lldb.eStopReasonWatchpoint and watch_addr is not None:
                counts['watchpoint'] += 1
                if counts['watchpoint'] <= MAX_WP_LOG:
                    log(f'\n@@@ WATCHPOINT #{counts["watchpoint"]} t=+{time.monotonic()-t0:.0f}s '
                        f'addr={watch_addr:#x} bt: {bt(t, base)}')
                stopped_by_wp = True
                continue
            if reason != lldb.eStopReasonBreakpoint:
                continue
            key = None
            if pc - 1 == base + LOOKUP_RET or pc == base + LOOKUP_RET:
                key = 'lookup_ret'
            elif pc - 1 == base + APPLY or pc == base + APPLY:
                key = 'apply'
            if key is None:
                continue
            counts[key] += 1
            rax = f0.FindRegister('rax').GetValueAsUnsigned()
            rcx = f0.FindRegister('rcx').GetValueAsUnsigned()
            if key == 'lookup_ret':
                log(f'@@@ lookup_ret #{counts["lookup_ret"]} t=+{time.monotonic()-t0:.0f}s '
                    f'rax(found)={rax:#x}')
                if rax > 0x10000 and not armed:
                    # 两段式：对命中消息对象头部 8B 挂写观察点（DB 删除/状态
                    # 迁移必写对象或先行释放——头部是最早被触碰的位置）
                    watch_addr = rax
                    wp = arm_watch(watch_addr)
                    armed = bool(wp and wp.IsValid())
                    log(f'   watchpoint armed addr={watch_addr:#x} valid={armed} '
                        f'wp={wp.GetID() if armed else 0}')
                    if not armed:
                        # 回退：观察对象的 +0x118 状态字段（㉘ 状态机字段）
                        watch_addr = rax + 0x118
                        wp = arm_watch(watch_addr)
                        armed = bool(wp and wp.IsValid())
                        log(f'   fallback watch +0x118 addr={watch_addr:#x} valid={armed}')
            else:
                log(f'@@@ apply #{counts["apply"]} t=+{time.monotonic()-t0:.0f}s rcx={rcx:#x} '
                    f'bt: {bt(t, base)}')
        if time.monotonic() - t0 >= TIME_CAP_S:
            break
        proc.Continue()

    log(f'DRIVE36 VERDICT-COUNTS: lookup_ret={counts["lookup_ret"]} apply={counts["apply"]} '
        f'watchpoint={counts["watchpoint"]} watch_addr={watch_addr:#x}' if watch_addr else
        f'DRIVE36 VERDICT-COUNTS: lookup_ret={counts["lookup_ret"]} apply={counts["apply"]} '
        f'watchpoint=0 watch_addr=none')
    log('DRIVE36: 收工——detach 恢复微信运行')
    proc.Detach()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f drive36.drive36 drive36')
