#!/usr/bin/env python3
"""
locate_x64_parse_guard.py — 定位 x64 解析守卫分支（fzlzjerry x64 silent 法的目录化实现）。

原理（2026-09-17 在 269602 验证，位点族来自 docs/related-tools-analysis.md 调研）：
  1. imm64 "revokems" 锚定 isRevokemsg 比较函数（同 locate_x64_revoke.py）
  2. 全 __text 反查它的 E8 调用者，保留"调用后紧跟 test al,al; je rel32"
     (84 C0 0F 84) 守卫形态的站点
  3. 自动甄别解析函数的守卫：所在函数体内含 newmsgid 存储
     (48 89 83 C8 01 00 00 = mov [rbx+0x1C8],rax) 者即是 parseRevokeXML
  4. 输出 silent 备用条目：je(E8? 不,0F84 disp32) → jmp(E9 disp'+1 90)

语义：翻转后"非撤回才跳过删除块"变成"永远跳过"= 解析级 silent，
不依赖 isRevokemsg 函数存活（该函数被内联/改签名的构建仍可用）。
与现有 revoke 条目（函数级）互为冗余，可同时在场。

用法:
  python3 tools/locate_x64_parse_guard.py /Applications/WeChat.app          # 只读定位
  python3 tools/locate_x64_parse_guard.py /Applications/WeChat.app --append config.json
"""
import struct, re, json, sys, os, shutil, time

def read_x64_slice(path):
    data = open(path, 'rb').read()
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        nfat = struct.unpack_from('>I', data, 4)[0]
        for i in range(nfat):
            cputype, _, off, size, _ = struct.unpack_from('>IIIII', data, 8 + i * 20)
            if cputype == 0x01000007:
                return data[off:off + size]
        raise SystemExit('fat 里没有 x86_64 slice')
    if struct.unpack_from('<i', data, 4)[0] != 0x01000007:
        raise SystemExit('不是 x86_64 Mach-O')
    return data

def text_range(d):
    p, ncmds = 32, struct.unpack_from('<I', d, 16)[0]
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, p)
        if cmd == 0x19:
            n = struct.unpack_from('<I', d, p + 64)[0]
            sp = p + 72
            for _ in range(n):
                if d[sp:sp + 16].rstrip(b'\0') == b'__text':
                    a, sz = struct.unpack_from('<QQ', d, sp + 32)
                    o = struct.unpack_from('<I', d, sp + 48)[0]
                    return a, sz, o
                sp += 80
        p += cmdsize
    raise SystemExit('找不到 __text')

def find_entry(d, t_off, site_off):
    o = site_off
    while o > t_off:
        o -= 1
        if d[o] in (0xC3, 0xE9, 0xEB):
            e = o + 1
            while e < len(d):
                if d[e] in (0xCC, 0x90):
                    e += 1
                elif d[e] == 0x66 and d[e + 1] == 0x90:
                    e += 2
                else:
                    break
            return e
    return None

def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    app = sys.argv[1].rstrip('/')
    dylib = os.path.join(app, 'Contents/Resources/wechat.dylib')
    if not os.path.exists(dylib):
        dylib = app
    d = read_x64_slice(dylib)
    t_addr, t_size, t_off = text_range(d)

    # 1) isRevokemsg：movabs "revokems" → 前找函数入口
    sites = [m.start() for m in re.finditer(b'revokems', d) if t_off <= m.start() < t_off + t_size]
    cands = []
    for s in sites:
        e = find_entry(d, t_off, s)
        if e is None: continue
        entry_va = t_addr + (e - t_off)
        callers = 0
        pos = t_off
        while True:
            idx = d.find(b'\xe8', pos, t_off + t_size)
            if idx < 0: break
            disp = struct.unpack_from('<i', d, idx + 1)[0]
            if t_addr + (idx - t_off) + 5 + disp == entry_va: callers += 1
            pos = idx + 1
        if callers: cands.append((callers, entry_va))
    if not cands: raise SystemExit('未找到 isRevokemsg（调用者判据）')
    cands.sort(reverse=True)
    callers_n, isrev = cands[0]
    print(f'isRevokemsg = {isrev:#x}（{callers_n} 个直接调用者）')

    # 2) 调用者中的守卫形态：call 后紧跟 test al,al(2B); je rel32(6B)
    #    je 指令本体在 call_end+2（0F 84 disp32），short 形态(74)暂不支持
    guards = []
    pos = t_off
    while True:
        idx = d.find(b'\xe8', pos, t_off + t_size)
        if idx < 0: break
        disp = struct.unpack_from('<i', d, idx + 1)[0]
        if t_addr + (idx - t_off) + 5 + disp == isrev:
            tail = d[idx + 5:idx + 12]
            if tail[0:3] == b'\x84\xc0\x0f' and tail[3] == 0x84:
                je_va = t_addr + (idx + 7 - t_off)          # 0F 84 本体（call_end+2）
                guards.append((je_va, struct.unpack_from('<i', d, idx + 9)[0]))
            elif tail[0:3] == b'\x84\xc0\x74':
                print(f'  跳过短跳形态守卫（call_end={t_addr + (idx + 5 - t_off):#x}）— 暂不支持')
        pos = idx + 1
    print(f'守卫形态站点(je): {[hex(g[0]) for g in guards]}')

    # 3) 解析函数甄别：守卫所在函数体含 newmsgid 存储 488983C8010000
    picked = None
    for je_va, disp in guards:
        fe = find_entry(d, t_off, je_va - t_addr + t_off)
        if fe is None: continue
        body = d[fe:fe + 0x4000]
        if b'\x48\x89\x83\xc8\x01\x00\x00' in body:
            picked = (je_va, disp)
            print(f'解析守卫: je@{je_va:#x}（所在函数 {fe:#x} 含 newmsgid 存储）✓')
            break
    if picked is None:
        raise SystemExit('未甄别出解析守卫（需人工分析，见 docs/related-tools-analysis.md）')

    je_va, disp = picked
    foff = je_va - t_addr + t_off
    expected = d[foff:foff + 6].hex().upper()          # 0F 84 disp32
    # 0F 84 disp32(6B) → E9 disp'+1(5B) + 90（同目标：pc+6+disp == pc+5+disp'）
    asm = 'E9' + struct.pack('<I', (disp + 1) & 0xFFFFFFFF).hex().upper() + '90'
    print(f'\n条目: addr={je_va:x}  expected={expected}  asm={asm}')

    if '--append' in sys.argv:
        cfg_path = sys.argv[sys.argv.index('--append') + 1]
        build = subprocess.run(['defaults', 'read', os.path.join(app, 'Contents/Info.plist'),
                                'CFBundleVersion'], capture_output=True, text=True).stdout.strip() \
            if app.endswith('.app') else '?'
        bak = cfg_path + '.bak.' + time.strftime('%Y%m%d%H%M%S')
        shutil.copy(cfg_path, bak)
        cfg = json.load(open(cfg_path), object_pairs_hook=json.OrderedDict if hasattr(json, 'OrderedDict') else None)
        import collections
        cfg = json.load(open(cfg_path), object_pairs_hook=collections.OrderedDict)
        entry = next((x for x in cfg if x['version'] == build), None)
        if entry is None:
            entry = collections.OrderedDict([('version', build), ('targets', [])])
            cfg.insert(0, entry)
        rev = next((t for t in entry['targets'] if t['identifier'] == 'revoke'), None)
        if rev is None:
            rev = collections.OrderedDict([('identifier', 'revoke'),
                                           ('binary', 'Contents/Resources/wechat.dylib'), ('entries', [])])
            entry['targets'].insert(0, rev)
        rev['entries'] = [x for x in rev['entries'] if not (x.get('arch') == 'x86_64' and x.get('addr') == format(site_va, 'x'))]
        rev['entries'].append(collections.OrderedDict([
            ('arch', 'x86_64'), ('addr', format(site_va, 'x')),
            ('expected', [expected]), ('asm', asm),
            ('source', 'wxkeep:parse-guard je→jmp 翻转（解析级 silent 冗余位，见 docs/related-tools-analysis.md）')]))
        json.dump(cfg, open(cfg_path, 'w'), indent=2, ensure_ascii=False)
        print(f'已写入 {cfg_path}（备份 {bak}）；重打 silent 即生效')

if __name__ == '__main__':
    import subprocess
    main()
