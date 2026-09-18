#!/usr/bin/env python3
"""
contribute_expected.py — 用一份原版 wechat.dylib 回填 config.json 里缺失的 expected 字节。

背景：catalog 中部分条目（如 tanranv5 线的 x64 构建）缺 expected（原始字节），
引擎默认隔离（拒绝写入、不可 restore）。本工具让任何手里有【未打补丁】dylib 的用户
一键贡献原始字节：读地址处的现成字节写进 expected，隔离即解除（走正常安全门）。

用法:
  python3 tools/contribute_expected.py /Applications/WeChat.app                 # 按构建号匹配
  python3 tools/contribute_expected.py /path/to/wechat.dylib --build 269333     # 直接给 dylib
  python3 tools/contribute_expected.py ... --dry-run                            # 只看会填什么
  python3 tools/contribute_expected.py ... --force                              # 覆盖已有 expected（慎用）

安全约定:
  - 只处理 expected 缺失的条目（--force 才覆盖已有值——那是溯源数据）
  - 条目地址超出 dylib 范围/落在非加载段 → 报告 skipped（构建不符的信号），绝不猜
  - 打印 dylib 各架构切片 SHA-256 供贡献者留档
"""
import argparse, json, shutil, sys, time, hashlib

import machutil

def load_slices(path):
    """返回 {cputype: slice_bytes}；thin/fat 均可（machutil 统一实现）。"""
    return machutil.load_slices(path)

def va2off(slice_bytes, va):
    return machutil.va2off(slice_bytes, va)

def dylib_build_from_app(app):
    import subprocess, os
    plist = os.path.join(app, 'Contents', 'Info.plist')
    out = subprocess.run(['defaults', 'read', plist, 'CFBundleVersion'],
                         capture_output=True, text=True).stdout.strip()
    return out or None

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', help='原版 wechat.dylib 或 WeChat.app 路径')
    ap.add_argument('--build', help='构建号（.app 自动读 Info.plist；dylib 必须显式给）')
    ap.add_argument('--config', default='config.json')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--hashes', action='store_true',
                    help='只打印/登记 dylib 切片哈希到 known_dylib_hashes.json（不做 expected 回填）')
    ap.add_argument('--force', action='store_true', help='覆盖已有 expected（默认绝不）')
    args = ap.parse_args()

    src = args.source.rstrip('/')
    if src.endswith('.app'):
        dylib = src + '/Contents/Resources/wechat.dylib'
        build = args.build or dylib_build_from_app(src)
    else:
        dylib = src
        build = args.build
    if not build:
        sys.exit('dylib 直给时必须 --build <构建号>')

    slices = load_slices(dylib)
    if args.hashes:
        import hashlib as _h
        entry = {}
        for ct, sb in sorted(slices.items()):
            name = machutil.CPU_NAMES.get(ct, f'cputype{ct:x}')
            entry[name] = _h.sha256(sb).hexdigest()
            print(f'  {name}: {entry[name]}')
        known_path = 'known_dylib_hashes.json'
        known = {}
        try:
            known = json.load(open(known_path))
        except Exception:
            pass
        known[build] = entry
        json.dump(known, open(known_path, 'w'), indent=2, sort_keys=True)
        print(f'已登记构建 {build} 的切片哈希 → {known_path}')
        return
    for ct, sb in sorted(slices.items()):
        h = hashlib.sha256(sb).hexdigest()
        print(f'slice cputype 0x{ct:x}: sha256 {h[:16]}… ({len(sb)/1e6:.0f} MB)')

    cfg = json.load(open(args.config))
    ver = next((v for v in cfg if str(v['version']) == str(build)), None)
    if ver is None:
        sys.exit(f'config.json 里没有构建 {build} 的条目')
    CPU = {'arm64': machutil.CPU_ARM64, 'x86_64': machutil.CPU_X86_64}

    filled = skipped = still = 0
    for t in ver['targets']:
        for e in t['entries']:
            if e.get('expected') and not args.force:
                continue
            arch = e.get('arch')
            sb = slices.get(CPU.get(arch, 0))
            if sb is None:
                still += 1
                continue
            off = va2off(sb, int(e['addr'], 16))
            if off is None:
                print(f'  skipped {t["identifier"]}/{arch}@{e["addr"]}: 地址不在该 slice 的加载段（构建不符？）')
                skipped += 1
                continue
            # patch 侧是前缀比较（短 expected 也匹配），但 restore 会把
            # expected[0] 原样写回——短于 asm 的条目还原后会残留补丁尾巴
            # （269602 的 9/12 字节 asm 实证）。取 max(asm, 8)：覆盖整个
            # 写入跨度，短补丁保留 8 字节溯源裕量。
            want = max(len(bytes.fromhex(e['asm'])), 8)
            raw = sb[off:off + want]
            if args.dry_run:
                print(f'  would fill {t["identifier"]}/{arch}@{e["addr"]}: {raw.hex().upper()}')
            else:
                e['expected'] = [raw.hex().upper()]   # 数组形态（与引擎编码/backfill 一致）
                e.setdefault('source', '')
                e['source'] = (e['source'] + ' ' if e['source'] else '') + f'contributed:{build}'
            filled += 1

    print(f'\n构建 {build}: 可填 {filled}，跳过(地址不符) {skipped}，仍缺(无该架构切片) {still}')
    if args.dry_run or filled == 0:
        return
    bak = args.config + '.bak.' + time.strftime('%Y%m%d%H%M%S')
    shutil.copy(args.config, bak)
    json.dump(cfg, open(args.config, 'w'), indent=2, ensure_ascii=False)
    print(f'已写 {args.config}（备份 {bak}）。请核对 diff 后提交，注明 dylib 来源。')

if __name__ == '__main__':
    main()
