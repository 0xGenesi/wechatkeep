#!/usr/bin/env python3
"""
verify_derivations.py — 对指定构建做全位点回归验证（新脚本 vs 已登记数据）。

对单个构建重新派生全部位点家族，与 config.json（catalog）及
Sources/wxkeep/RuntimeConfig.swift（knownHooks）逐项对比：

  1. revoke x64/arm64   wxkeep locate（配方引擎，fake bundle）
  2. parse guard x64    tools/locate_x64_parse_guard.py
  3. keeptip x64        parse 函数内 E8+newmsgid store 扫描
  4. update x64         tools/locate_update_x64.py（XAppUpdateManager）
  5. hooks rows         tools/derive_runtime_hooks.py（x64 wrapper 世代口径）
                        + FUNCTION_STARTS parse 入口（parse 直挂现行口径）

用法: python3 tools/verify_derivations.py --build 270099
依赖: var/wxarm/<build>_x64.dylib、<build>_arm64.dylib（或 var/cdn 的 dmg
      自动挂载抽取）；仓库根的 config.json 与 Release 构建的 wxkeep。
"""
import argparse
import json
import struct
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil  # noqa: E402

X64 = machutil.CPU_X86_64


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def load_catalog(path):
    return json.load(open(path), object_pairs_hook=None)


def load_merged_catalog(path, local_path=None):
    """与 Config.load 同语义：catalog + config.local.json 合并（local 优先追加）。"""
    cfg = json.load(open(path), object_pairs_hook=None)
    if local_path and os.path.exists(local_path):
        local = json.load(open(local_path), object_pairs_hook=None)
        for lv in local:
            sv = next((x for x in cfg if x['version'] == lv['version']), None)
            if sv is None:
                cfg.append(lv)
                continue
            for lt in lv['targets']:
                st = next((t for t in sv['targets']
                           if t['identifier'] == lt['identifier']
                           and (t.get('binary') or '') == (lt.get('binary') or '')), None)
                if st is None:
                    sv['targets'].append(lt)
                    continue
                have = {(e['arch'], e.get('addr')) for e in st['entries']}
                for e in lt['entries']:
                    if (e['arch'], e.get('addr')) not in have:
                        st['entries'].append(e)
    return cfg


def catalog_sites(cfg, build):
    """→ {family: {addr_str, ...}}（arm64/x64 混合，按 family 分）"""
    v = next((x for x in cfg if x['version'] == build), None)
    out = {}
    if v is None:
        return out
    for t in v['targets']:
        for e in t['entries']:
            out.setdefault(t['identifier'], set()).add(
                (e['arch'], e.get('addr', '').lower(), e.get('source', '')))
    return out


def known_hooks(path):
    src = open(path).read()
    rows = re.findall(
        r'HookRow\(build: "(\d+)", uuid: "([0-9a-f\-]+)",\s*'
        r'arch: "(arm64|x86_64)", hook_off: "(0x[0-9a-f]+)", msg_arg: \d+, '
        r'xml_sso_off: (\d+),\s*expected: "([0-9A-F]+)"', src)
    return [dict(build=b, uuid=u, arch=a, hook_off=h, sso=int(o), expected=e)
            for b, u, a, h, o, e in rows]


def fake_bundle(build, fat_dylib, work):
    app = os.path.join(work, f'WeChat_{build}.app')
    res = os.path.join(app, 'Contents', 'Resources')
    os.makedirs(res, exist_ok=True)
    shutil.copy(fat_dylib, os.path.join(res, 'wechat.dylib'))
    plist = os.path.join(app, 'Contents', 'Info.plist')
    open(plist, 'w').write(
        f'<?xml version="1.0"?><plist version="1.0"><dict>'
        f'<key>CFBundleVersion</key><string>{build}</string></dict></plist>')
    return app


def locate_sites(wxkeep, app):
    """wxkeep locate → {arch: revoke_site_va}"""
    out = {}
    r = sh([wxkeep, 'locate', '-a', app])
    for line in r.stdout.splitlines():
        m = re.match(r'\s+\[(\w+)\] ✓ site 0x([0-9A-Fa-f]+)', line)
        if m:
            out[m.group(1)] = int(m.group(2), 16)
    return out


def guard_site(dylib_fat):
    r = sh(['python3', os.path.join(HERE, 'locate_x64_parse_guard.py'), dylib_fat])
    m = re.search(r'条目: addr=([0-9a-f]+)', r.stdout)
    return int(m.group(1), 16) if m else None


def guard_parse_entry(dylib_fat, guard_hex):
    """guard 位点（parse 函数体内）→ FUNCTION_STARTS → parse 入口"""
    import struct
    d = machutil.load_slice(dylib_fat, X64)
    funcs = machutil.function_starts(d)
    g = int(guard_hex, 16)
    return max((f for f in funcs if f <= g), default=None)


def keeptip_site(dylib_fat, parse_entry):
    """parse 函数范围内 E8(5B call) + 48 89 83 C8 01 00 00（newmsgid 存储）唯一命中"""
    d = machutil.load_slice(dylib_fat, X64)
    funcs = machutil.function_starts(d)
    nxt = min((f for f in funcs if f > parse_entry), default=None)
    off = machutil.va2off(d, parse_entry)
    end = machutil.va2off(d, nxt) if nxt else off + 0x2000
    text_addr, text_size, text_off = machutil.text_range(d)
    hits = []
    o = off
    while o + 12 <= end:
        if d[o] == 0xE8 and d[o+5:o+12] == b'\x48\x89\x83\xc8\x01\x00\x00':
            hits.append(parse_entry + (o - off))   # E8+store 即 keeptip 位点
        o += 1
    return hits


def update_imps(dylib_thin):
    r = sh(['python3', os.path.join(HERE, 'locate_update_x64.py'), dylib_thin])
    imps = re.findall(r'ret  (\S+)\s+imp 0x([0-9A-Fa-f]+)', r.stdout)
    return {name: int(imp, 16) for name, imp in imps}


def derive_wrapper(dylib_thin, guard_hex, build):
    r = sh(['python3', os.path.join(HERE, 'derive_runtime_hooks.py'),
            dylib_thin, guard_hex, build])
    m = re.search(r'"hook_off": "(0x[0-9a-f]+)"', r.stdout)
    return int(m.group(1), 16) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', required=True)
    ap.add_argument('--wxkeep', default=os.path.join(ROOT, '.build/release/wxkeep'))
    ap.add_argument('--skip-locate', action='store_true', help='跳过配方引擎（最慢步）')
    args = ap.parse_args()
    build = args.build

    local_cfg = os.path.expanduser(
        '~/Library/Application Support/wxkeep/config.local.json')
    cfg = load_merged_catalog(os.path.join(ROOT, 'config.json'), local_cfg)
    sites = catalog_sites(cfg, build)
    cfg_for_build = next((x for x in cfg if x['version'] == build), {})
    if not sites:
        raise SystemExit(f'catalog 无 {build}')
    hooks = [h for h in known_hooks(os.path.join(
        ROOT, 'Sources/wxkeep/RuntimeConfig.swift')) if h['build'] == build]

    x64thin = os.path.join(ROOT, 'var/wxarm', f'{build}_x64.dylib')
    fat = os.path.join(ROOT, 'var/wxarm', f'{build}_fat.dylib')
    if not os.path.exists(fat):
        dmgs = [p for p in os.listdir(os.path.join(ROOT, 'var/cdn'))
                if p.endswith(f'_{build}.dmg')] if os.path.isdir(os.path.join(ROOT, 'var/cdn')) else []
        if not dmgs:
            raise SystemExit(f'需要 {fat} 或 var/cdn 的 dmg')
        sh(['hdiutil', 'attach', '-nobrowse', '-readonly',
            os.path.join(ROOT, 'var/cdn', dmgs[0]), '-quiet'])
        src = '/Volumes/微信 WeChat/WeChat.app/Contents/Resources/wechat.dylib'
        shutil.copy(src, fat)
        sh(['hdiutil', 'detach', '/Volumes/微信 WeChat'])

    results = []

    def check(name, catalog_val, derived, ok=None):
        ok = (catalog_val == derived) if ok is None else ok
        results.append((name, catalog_val, derived, ok))

    def cat_addr(family, arch, source_has=None):
        for ar, a, src in sites.get(family, set()):
            if ar == arch and (source_has is None or source_has in src):
                return int(a, 16)
        return None

    def cat_addrs(family, arch):
        return {int(a, 16) for ar, a, _ in sites.get(family, set()) if ar == arch}

    # 1. revoke 配方（双架构，fake bundle）
    if not args.skip_locate:
        work = tempfile.mkdtemp(prefix='wxkeep-verify-')
        app = fake_bundle(build, fat, work)
        loc = locate_sites(args.wxkeep, app)
        rev_x64_set = cat_addrs('revoke', 'x86_64')
        check('revoke x86_64 (recipe)',
              '/'.join(format(v, 'x') for v in sorted(rev_x64_set)),
              format(loc['revoke_x64'], 'x') if 'revoke_x64' in loc else None,
              'revoke_x64' in loc and loc['revoke_x64'] in rev_x64_set)
        check('revoke arm64 (recipe)',
              format(cat_addr('revoke', 'arm64'), 'x') if cat_addr('revoke', 'arm64') else None,
              format(loc['revoke_arm64_gen3'], 'x') if 'revoke_arm64_gen3' in loc else None)

    # 2. parse guard（守卫条目按 source 识别）
    gs = guard_site(fat)
    check('parse guard x86_64',
          format(cat_addr('revoke', 'x86_64', 'parse-guard'), 'x') if cat_addr('revoke', 'x86_64', 'parse-guard') else None,
          format(gs, 'x') if gs else None)

    # 3. keeptip store（parse 从 guard 独立推导）
    if gs:
        pe = guard_parse_entry(fat, format(gs, 'x'))
        rev_x64 = cat_addrs('revoke', 'x86_64')
        kt = next((a for a in cat_addrs('revoke-keeptip', 'x86_64') if a not in rev_x64), None)
        kt_sites = keeptip_site(fat, pe) if pe else []
        check('keeptip store x86_64', format(kt, 'x') if kt else None,
              format(kt_sites[0], 'x') if len(kt_sites) == 1 else f'{len(kt_sites)} hits')

    # 4. update 方法表
    imps = update_imps(x64thin)
    upd = cat_addrs('update', 'x86_64')
    # 子集语义：工具只产出 ret 方法（访问器对等非纯 stub 形态的条目为
    # 手工补充），derived ⊆ catalog 即通过
    check('update imps x86_64 (derived subset)',
          '/'.join(format(v, 'x') for v in sorted(upd)),
          '/'.join(format(v, 'x') for v in sorted(imps.values())),
          all(v in upd for v in imps.values()) and len(upd) > 0)

    # 5. hooks rows（parse 直挂）：x64 行 = guard 独立推导的 parse 入口；
    #    arm64 行 = catalog arm64 revoke 位点 → FUNCTION_STARTS parse 入口
    for h in hooks:
        if h['arch'] == 'x86_64' and gs:
            pe = guard_parse_entry(fat, format(gs, 'x'))
            check(f"hook parse x86_64", format(pe, 'x') if pe else None,
                  format(int(h['hook_off'], 16), 'x'))
        elif h['arch'] == 'arm64':
            g = next((int(e['addr'], 16) for t in cfg_for_build['targets']
                      if t['identifier'] == 'revoke'
                      for e in t['entries'] if e['arch'] == 'arm64'), None)
            d = machutil.load_slice(x64thin.replace('_x64', '_arm64'), machutil.CPU_ARM64)
            funcs = machutil.function_starts(d)
            pe = max((f for f in funcs if f <= g), default=None) if g else None
            check(f"hook parse arm64", format(pe, 'x') if pe else None,
                  format(int(h['hook_off'], 16), 'x'))

    print(f'\n===== {build} 回归验证 =====')
    fails = 0
    for name, cat, der, ok in results:
        mark = 'PASS' if ok else 'FAIL'
        if not ok:
            fails += 1
        print(f'  [{mark}] {name}: catalog={cat} derived={der}')
    print(f'  {len(results) - fails}/{len(results)} PASS')
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
