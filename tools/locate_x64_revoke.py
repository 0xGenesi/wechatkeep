#!/usr/bin/env python3
"""
locate_x64_revoke.py — 为 Intel (x86_64) 微信自动定位防撤回 silent 补丁点。

原理（2026-09 在 269602 上验证成功的方法）:
  1. 在 x86_64 slice 的 __text 里搜 movabs 立即数 "revokems"
     (msgType=="revokemsg" 比较函数懒初始化全局常量时内联的机器码)
  2. 每个命中点向前找函数入口 (ret/jmp + CC/90 padding 边界)
  3. 全 __text 反查 E8 rel32 直接调用者;
     唯一「有调用者」的入口即目标比较函数 (其余命中点是编译器内联副本, 无直接调用者)
  4. 输出 config.json 的 x86_64 条目: 入口改 xor eax,eax; ret (31C0C3) + NOP

用法:
  python3 locate_x64_revoke.py /Applications/WeChat.app                 # 只读定位
  python3 locate_x64_revoke.py /Applications/WeChat.app --append PATH   # 定位并写入 config.json

只读分析 WeChat 二进制; --append 只改本工具链的 config.json (先自动备份)。
"""
import struct, re, json, sys, os, shutil, subprocess, time

PATCH_ASM = '31C0C3909090909090'   # xor eax,eax; ret + 6x nop
EXPECTED_LEN = 9

def read_x64_slice(path):
    data = open(path, 'rb').read()
    magic = struct.unpack_from('>I', data, 0)[0]
    if magic == 0xCAFEBABE or magic == 0xBEBAFECA:
        nfat = struct.unpack_from('>I', data, 4)[0]
        for i in range(nfat):
            cputype, cpusub, off, size, align = struct.unpack_from('>IIIII', data, 8 + i * 20)
            if cputype == 0x01000007:  # x86_64
                return data[off:off + size]
        raise SystemExit('fat 文件里没有 x86_64 slice')
    # thin: 确认是 x86_64
    cputype = struct.unpack_from('<i', data, 4)[0]
    if cputype != 0x01000007:
        raise SystemExit('不是 x86_64 thin Mach-O (cputype=0x%x)' % cputype)
    return data

def parse_text_section(d):
    p, ncmds, secs = 32, struct.unpack_from('<I', d, 16)[0], []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', d, p)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', d, p + 64)[0]
            sp = p + 72
            for i in range(nsects):
                sname = d[sp:sp+16].rstrip(b'\0').decode()
                saddr, ssize = struct.unpack_from('<QQ', d, sp + 32)
                soff = struct.unpack_from('<I', d, sp + 48)[0]
                secs.append((sname, saddr, ssize, soff))
                sp += 80
        p += cmdsize
    t = [s for s in secs if s[0] == '__text']
    if not t:
        raise SystemExit('找不到 __TEXT,__text')
    _, t_addr, t_size, t_off = t[0]
    return t_addr, t_size, t_off

def find_entry(d, t_off, site_off):
    """向前找上一个函数结尾 (C3/E9/EB) + padding (CC/90/66 90) 之后的第一个字节"""
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

def find_callers(d, t_addr, t_off, t_size, entry_off):
    entry_va = t_addr + (entry_off - t_off)
    callers, pos, end = [], t_off, t_off + t_size
    while True:
        idx = d.find(b'\xe8', pos, end)
        if idx == -1:
            break
        disp = struct.unpack_from('<i', d, idx + 1)[0]
        if t_addr + (idx - t_off) + 5 + disp == entry_va:
            callers.append(t_addr + (idx - t_off))
        pos = idx + 1
    return callers

def locate(dylib_path):
    d = read_x64_slice(dylib_path)
    t_addr, t_size, t_off = parse_text_section(d)
    sites = [m.start() for m in re.finditer(b'revokems', d)
             if t_off <= m.start() < t_off + t_size]
    if not sites:
        raise SystemExit('没找到 "revokems" movabs 立即数——新构建可能改了代码生成, 需要人工分析')
    print(f'__text VA 0x{t_addr:x} size 0x{t_size:x}; "revokems" 立即数命中 {len(sites)} 处')
    results = []
    for s in sites:
        e = find_entry(d, t_off, s)
        if e is None:
            continue
        callers = find_callers(d, t_addr, t_off, t_size, e)
        entry_va = t_addr + (e - t_off)
        print(f'  site 0x{t_addr + s - t_off:x} -> entry 0x{entry_va:x}, 直接调用者 {len(callers)} 个')
        results.append((len(callers), entry_va, e))
    if not results:
        raise SystemExit('所有命中点都找不到函数入口, 需要人工分析')
    results.sort(reverse=True)
    ncall, entry_va, entry_off = results[0]
    if ncall == 0:
        raise SystemExit('没有任何入口有直接调用者 (可能全部被内联), 需要人工分析')
    expected = d[entry_off:entry_off + EXPECTED_LEN].hex().upper()
    print(f'\n选定: entry 0x{entry_va:x} ({ncall} 个调用者)')
    print(f'  expected: {expected}')
    print(f'  asm:      {PATCH_ASM}   (xor eax,eax; ret + nop)')
    return entry_va, expected

def wechat_build(app_path):
    plist = os.path.join(app_path, 'Contents', 'Info.plist')
    out = subprocess.run(['defaults', 'read', plist, 'CFBundleVersion'],
                         capture_output=True, text=True).stdout.strip()
    return out

def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    app = sys.argv[1].rstrip('/')
    dylib = os.path.join(app, 'Contents', 'Resources', 'wechat.dylib')
    if not os.path.exists(dylib):
        dylib = app  # 允许直接传 dylib 路径
    build = wechat_build(app) if app.endswith('.app') else '?'
    print(f'微信构建号: {build}')
    entry_va, expected = locate(dylib)

    if '--append' in sys.argv:
        cfg_path = sys.argv[sys.argv.index('--append') + 1]
        bak = cfg_path + '.bak.' + time.strftime('%Y%m%d%H%M%S')
        shutil.copy(cfg_path, bak)
        cfg = json.load(open(cfg_path))
        entry = None
        for e in cfg:
            if e['version'] == build:
                entry = e
                break
        if entry is None:
            entry = {'version': build, 'targets': [], 'source': ''}
            cfg.insert(0, entry)
        rev = next((t for t in entry['targets'] if t['identifier'] == 'revoke'), None)
        if rev is None:
            rev = {'identifier': 'revoke', 'binary': 'Contents/Resources/wechat.dylib', 'entries': []}
            entry['targets'].insert(0, rev)
        rev['entries'] = [x for x in rev['entries'] if x.get('arch') != 'x86_64']
        rev['entries'].append({'arch': 'x86_64', 'addr': format(entry_va, 'x'),
                               'expected': expected, 'asm': PATCH_ASM})
        json.dump(cfg, open(cfg_path, 'w'), indent=2, ensure_ascii=False)
        print(f'\n已写入 {cfg_path} (原文件备份为 {bak})')
        print('下一步: 完全退出微信, 然后')
        print(f'  sudo ~/wechattweak-intel/wechattweak patch --app "{app}" --config {cfg_path} --variant silent --no-block-update')

if __name__ == '__main__':
    main()
