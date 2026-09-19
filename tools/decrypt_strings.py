#!/usr/bin/env python3
"""
decrypt_strings.py — 微信 4.x macOS 混淆字符串静态解密器（mars xlog 符号恢复，无 IDA）。

原理（看雪 thread-286611 方法论的纯静态移植）：
微信 4.x 的日志字符串（文件名/函数名）运行时解密，编译器生成固定形态的循环：
    out[i] = (BASE[data_off + i] + addend) & 0xFF ^ BASE[key_off + (i % 20)]
BASE = __TEXT,__const 里某块常量区（lea rcx,[rip+X]）；key 为 20 字节滚动密钥
（mul 0xCCCC..CD + shr 2 + and ~3 的取模运算推导：i mod 20）。
本工具在 __text 扫描四种编码形态的解密循环，现场模拟解密，产出
「函数 → 字符串」映射 = 免 IDA 的符号恢复。

用法:
  python3 tools/decrypt_strings.py /Applications/WeChat.app                # 摘要+全量 JSON
  python3 tools/decrypt_strings.py /path/wechat.dylib --grep revoke       # 过滤关键词
输出: stdout 摘要 + decrypted_strings.json（[{func, site, str}]）

已验证（269602 x64）：139 串，含 message_revoke_manager.cc 全家族 24 函数——
定位撤回子系统的首选武器。

依赖: tools/machutil.py（同目录，VA 换算/函数边界统一口径）。
2026-09 审计修复: 函数基址由「第一个 section 的 addr」改为 __TEXT 段 vmaddr
（dyld 语义）——旧版 func 字段的 VA 系统性偏大（多加了 mach header + load
commands 区域的大小）；str 字段不受影响。历史 decrypted_strings.json 的
func 值如需精确引用，请用本工具重跑刷新。
"""
import argparse, bisect, json, re, struct, sys

import machutil

PATS = [
    rb'\x0f\xb6\x44\x0e(.)\x04(.)\x32\x42(.)',                 # movzx eax,[rsi+rcx+d8]; add al,i; xor al,[rdx+d8]
    rb'\x44\x0f\xb6\x44\x0e(.)\x44\x04(.)\x44\x32\x42(.)',     # r8d 同构
    rb'\x0f\xb6\x84\x0e(....)\x04(.)\x32\x42(.)',              # disp32 变体
    rb'\x44\x0f\xb6\x84\x0e(....)\x44\x04(.)\x44\x32\x42(.)',
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('source', help='WeChat.app 或 wechat.dylib 路径')
    ap.add_argument('--grep', default=None, help='过滤关键词（不区分大小写）')
    ap.add_argument('--json', default='decrypted_strings.json')
    args = ap.parse_args()

    src = args.source.rstrip('/')
    dylib = src + '/Contents/Resources/wechat.dylib' if src.endswith('.app') else src
    D = machutil.load_slice(dylib, machutil.CPU_X86_64)
    # machutil.sections: (segname, sectname, addr, size, fileoff) → 本工具只需 4 元组
    secs = [(s[1], s[2], s[3], s[4]) for s in machutil.sections(D)]
    ta, tsz, to = [(s[1], s[2], s[3]) for s in secs if s[0] == '__text'][0]
    def o2v(o):
        for name, a, z, so in secs:
            if so <= o < so + z: return a + (o - so)
    def sec_off(va):
        for name, a, z, so in secs:
            if a <= va < a + z: return so + (va - a)
    # 基址 = __TEXT 段 vmaddr（machutil，dyld 语义）——旧实现取第一个
    # section 的 addr，函数归属 VA 系统性偏移了头部区域大小（2026-09 审计修复，
    # libsystem_kernel nm 1566/1566 全命中交叉验证）。
    funcs = machutil.function_starts(D)
    def func_of(va):
        k = bisect.bisect_right(funcs, va) - 1
        return funcs[k] if k >= 0 else 0

    out, seen = [], set()
    for pi, pat in enumerate(PATS):
        rx = re.compile(pat, re.S)
        pos = to
        while True:
            m = rx.search(D, pos, to + tsz)
            if not m: break
            off = m.start()
            gs = m.groups()
            data_off = gs[0][-1] if pi < 2 else struct.unpack('<I', gs[0])[0]
            addend, key_off = gs[1][-1], gs[2][-1]
            if data_off > 0x4000 or key_off > 0x4000:
                pos = off + 1; continue
            va = o2v(off)
            if va in seen:
                pos = off + 1; continue
            back = D[max(to, off - 0x60):off]
            base = None
            for k in range(len(back) - 6, -1, -1):
                if back[k:k+3] == b'\x48\x8d\x0d':
                    base = o2v(max(to, off - 0x60) + k) + 7 + struct.unpack_from('<i', back, k + 3)[0]
                    break
            span = m.end() - m.start()
            fwd = D[off + span:off + span + 0x60]
            length = None
            for k in range(len(fwd) - 3):
                if fwd[k:k+2] == b'\x81\xfe': length = struct.unpack_from('<I', fwd, k + 2)[0]; break
                if fwd[k:k+2] == b'\x83\xfe': length = struct.unpack_from('<b', fwd, k + 2)[0]; break
            if base is None or not (3 < (length or 0) <= 0x600):
                pos = off + 1; continue
            bo = sec_off(base)
            if bo is None or bo + data_off + length > len(D) or bo + key_off + 32 > len(D):
                pos = off + 1; continue
            best = None
            for mod in (20, 5, 10):
                buf = bytearray()
                for i2 in range(length):
                    b = (D[bo + data_off + i2] + addend) & 0xFF
                    b ^= D[bo + key_off + (i2 % mod)]
                    buf.append(b)
                try:
                    s = buf.decode('utf-8').rstrip('\0')
                    pr = sum(1 for c in s if 32 <= ord(c) < 127) / max(len(s), 1)
                except UnicodeDecodeError:
                    continue
                if pr > 0.9:
                    best = s; break
            if best:
                seen.add(va)
                out.append({'func': hex(func_of(va)), 'site': hex(va), 'str': best})
            pos = off + max(1, span)

    if args.grep:
        out = [r for r in out if args.grep.lower() in r['str'].lower()]
    json.dump(out, open(args.json, 'w'), ensure_ascii=False, indent=0)
    byf = {}
    for r in out:
        byf.setdefault(r['func'], []).append(r['str'])
    print(f'解密 {len(out)} 串（{len(byf)} 个函数）→ {args.json}')
    for f, ss in sorted(byf.items(), key=lambda kv: int(kv[0], 16)):
        for s in ss:
            print(f'  {f}: "{s[:70]}"')

if __name__ == '__main__':
    main()
