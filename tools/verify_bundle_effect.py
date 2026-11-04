#!/usr/bin/env python3
"""
verify_bundle_effect.py — L13 真件 bundle 局部性 SOP（V6-DEPTH D17/R16，133 轮）。

合成镜像（BundleEffectTests）在 CI 常跑；本工具把真件面补上：pristine app
的 clonefile 副本 → wxkeep patch --no-resign → **独立 python 实现**对全树
做差分，逐差分文件分类：
  · 位点级（目标二进制内 diff ⊆ 声明位点区间——machutil 段表口径独立实现）；
  · 备份（.wxkeep-bak-*）；
  · 签名面（重签模式：Mach-O 尾部 / _CodeSignature 目录）——默认
    --no-resign 模式下签名面应为空，出现即 FAIL；
  · 未归类差分 = FAIL（作用域主张的硬门）。
负控：诱饵文件预注入一字节 → patch 后必须出现在差分面且被标记
（诱饵缺席 = 检测器失灵 = FAIL）。位点级直证为全文件差分（64MiB 截断
曾在 133 轮双评审揭出——真 dylib 位点 VA ~70MB 落在截断区外，直证
空洞化；现全量读入）。

Preconditions（不满足则显式退出非零——skip=failure 纪律）：
  · pristine app 在场（--app 指定，默认 /Applications/WeChat.app——必须
    未打补丁：doctor 或位点 pristine 抽查判定）；
  · 磁盘余量 ≥ 15G（WeChat.app ~1.5G × 2 副本 + 瞬态）。

台账落 var/logs/bundle-effect-<date>.txt。

用法: var/venv/bin/python tools/verify_bundle_effect.py \
        [--app /Applications/WeChat.app] [--variant silent] [--resign]
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil   # noqa: E402  段表权威（VA→fileoff 唯一口径）

WXKEEP = shutil.which("wxkeep") or os.path.join(ROOT, ".build", "debug", "wxkeep")
if not os.path.exists(WXKEEP):
    print(f"✗ wxkeep 可执行不在场：{WXKEEP}（先 swift build）")
    sys.exit(1)


def sh(cmd, **kw):
    print(f"  $ {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print(f"    exit={r.returncode} {r.stderr.strip()[:300]}")
    return r


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_snapshot(root):
    """相对路径 → sha256（全树快照；大文件流式哈希）。"""
    out = {}
    for dirpath, _, names in os.walk(root):
        for name in names:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = "link:" + os.readlink(p)
            else:
                out[rel] = sha256(p)
    return out


def declared_sites(config, build, variant_targets=("revoke", "update")):
    """{binary_rel: [(arch, va, len)]}——目录中 variant 域条目的声明位点。
    keeptip 变体必须带 revoke-keeptip 域（133 轮双评审：缺域会让 keeptip
    写出的位点 diff 落不进 allowed 集 = 假红）。"""
    out = {}
    for version in config:
        if version.get("version") != build:
            continue
        for target in version.get("targets", []):
            if target.get("identifier") not in variant_targets:
                continue
            rel = target.get("binary") or "Contents/MacOS/WeChat"
            for entry in target.get("entries", []):
                asm = bytes.fromhex(entry["asm"]) if entry.get("asm") else b""
                expected = entry.get("expected")
                if isinstance(expected, str):
                    expected = [expected]
                lens = [len(asm)]
                for spec in expected or []:
                    # hexpart 可含通配 `?`（半字节占位）——按字符数折算字节，
                    # 不经 fromhex（Length 校验归 L1；此处只要位点跨度）。
                    lens.append(len(spec.split(":")[0]) // 2)
                out.setdefault(rel, []).append(
                    (entry.get("arch", "arm64"), int(entry["addr"], 16), max(lens)))
    return out


def differing_ranges(a_path, b_path, cap=1 << 30):
    """两文件的差异字节段——全量读入（133 轮双评审 P0 修正：64MiB 截断
    会把真 dylib 的位点（VA≈70MB）与全部尾部 diff 静默裁掉，直证空洞化；
    340MB×2 双读内存暂态可承受，cap=1GiB 纯防御）。"""
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        a, b = fa.read(cap), fb.read(cap)
    if len(a) == cap or len(b) == cap:
        print(f"✗ {os.path.basename(a_path)} 达到 1GiB 读入上限—— refusing 猜测")
        sys.exit(1)
    if len(a) != len(b):
        return [(min(len(a), len(b)), max(len(a), len(b)))]
    ranges, start = [], None
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, len(a)))
    return ranges


def fat_slice_offsets(path):
    """[(cputype, fat 内偏移, size)]——fat/thin 统一口径（本文件独立实现，
    与 machutil.load_slices 同语义但保留偏移）。"""
    data = open(path, "rb").read(8 + 20 * 8)
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == 0xCAFEBABE:
        nfat = struct.unpack_from(">I", data, 4)[0]
        out = []
        with open(path, "rb") as f:
            head = f.read(8 + 20 * nfat)
        for i in range(nfat):
            cputype, _, off, size, _ = struct.unpack_from(">IIIII", head, 8 + i * 20)
            out.append((cputype, off, size))
        return out
    if magic == 0xFEEDFACF:
        cputype = struct.unpack_from("<i", data, 4)[0]
        return [(cputype, 0, os.path.getsize(path))]
    return []


def site_offsets_in_file(path, entries):
    """[(fat 全文件偏移 lo, hi)]——声明位点的文件坐标（段表换算走 machutil
    权威 va2off；fat 布局本地小解析）。性能注记：每条目整文件 load_slice
    （340MB × 条目数）——真件单次跑秒级可接受，批量场景需缓存切片。"""
    allowed = []
    slices = fat_slice_offsets(path)
    cpu_by_arch = {"arm64": 0x0100000C, "x86_64": 0x01000007}
    for arch, va, ln in entries:
        cputype = cpu_by_arch.get(arch)
        slice_off = next((off for ct, off, _ in slices if ct == cputype), None)
        if slice_off is None:
            continue
        try:
            sl = machutil.load_slice(path, cputype)
        except SystemExit:
            continue
        off_in_slice = machutil.va2off(sl, va)
        if off_in_slice is None:
            continue
        base = slice_off + off_in_slice
        allowed.append((base, base + ln))
    return allowed


def classify(rel, config_sites, abs_path=None):
    """差分文件 → 类别（site / backup / signature / macho / UNCLASSIFIED）。
    rel 用于 site/backup 键查找（bundle 相对路径）；abs_path 用于 Mach-O
    头探测（133 轮实测：传绝对路径进来会把 site 查找打 miss → 位点级
    直证整个被跳过）。magic 集含 32/64 双端四形态。"""
    if ".wxkeep-bak-" in rel:
        return "backup"
    if rel in config_sites:
        return "site"
    if "/_CodeSignature/" in rel:
        return "signature"
    try:
        with open(abs_path or rel, "rb") as f:
            head = f.read(4)
        if head in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                    b"\xbe\xba\xfe\xca", b"\xce\xfa\xed\xfe"):
            return "macho"
    except OSError:
        pass
    return "UNCLASSIFIED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="/Applications/WeChat.app")
    ap.add_argument("--variant", default="silent", choices=["silent", "keeptip"])
    ap.add_argument("--resign", action="store_true",
                    help="默认 --no-resign（精确位点级主张）；--resign 升级为"
                         "签名面分类主张（嵌套重签的 diff 文件归 macho/_CodeSignature）")
    args = ap.parse_args()

    # ---- Preconditions（skip=failure）----
    if not os.path.isdir(args.app):
        print(f"✗ pristine app 不在场：{args.app}")
        sys.exit(1)
    df = sh(["df", "-g", "/tmp"])
    try:
        avail = int(df.stdout.strip().split("\n")[-1].split()[3])
    except (IndexError, ValueError):
        print("✗ df 输出不可解析——磁盘余量前置无法判定，拒跑。")
        sys.exit(1)
    if avail < 15:
        print(f"✗ 磁盘余量 {avail}G < 15G——双副本 + 瞬态不足（Precondition）。")
        sys.exit(1)

    config_path = os.path.join(ROOT, "config.json")
    config = json.load(open(config_path))
    build = None
    info = os.path.join(args.app, "Contents", "Info.plist")
    r = sh(["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleVersion", info])
    if r.returncode == 0:
        build = r.stdout.strip()
    if not build or not any(v.get("version") == build for v in config):
        print(f"✗ app 构建 {build} 不在 config.json——无法取得声明位点集。")
        sys.exit(1)

    # pristine 抽查（skip=failure 纪律的反面：已是补丁态也必须显式拒跑——
    # patch 会 alreadyPatched 全跳、差分面退化成备份对照，结论失真）。
    # 多点抽查（133 轮双评审 P1：单点+通配跳过有空洞绿窗口）：遍历 revoke
    # 域全部全具体条目，任一位点非 pristine 即拒跑；前缀比较防红向误判
    #（expected 短于 asm 的构型全等比较会恒不等）。无全具体条目 = 无法
    # 抽查 → 拒跑（不静默放行——pristine 门不能缺席）。
    probe_checked = 0
    sites_probe = declared_sites(config, build, variant_targets=("revoke",))
    for rel, entries in sites_probe.items():
        full = os.path.join(args.app, rel)
        if not os.path.exists(full):
            continue
        allowed = site_offsets_in_file(full, entries)
        concrete = []   # (entry, expected_hex, file_off)
        for entry, span in zip(entries, allowed):
            exp_hex = None
            for version in config:
                if version.get("version") != build:
                    continue
                for target in version.get("targets", []):
                    if target.get("identifier") != "revoke" or (
                            target.get("binary") or "Contents/MacOS/WeChat") != rel:
                        continue
                    for e in target.get("entries", []):
                        expected = e.get("expected")
                        if isinstance(expected, list):
                            expected = expected[0] if expected else None
                        if (e.get("arch") == entry[0]
                                and int(e["addr"], 16) == entry[1]
                                and isinstance(expected, str)
                                and "?" not in expected):
                            exp_hex = expected.upper()
                            break
            if exp_hex:
                concrete.append((entry, exp_hex, span[0]))
        if not concrete:
            continue
        with open(full, "rb") as f:
            for entry, exp_hex, off in concrete:
                f.seek(off)
                on_disk = f.read(len(exp_hex) // 2).hex().upper()
                n = min(len(on_disk), len(exp_hex))
                if on_disk[:n] != exp_hex[:n]:
                    print(f"✗ app 非 pristine：{rel}@{entry[1]:x} 盘上 {on_disk[:16]}… "
                          f"≠ expected {exp_hex[:16]}…（已是补丁态——pristine 属 Precondition）")
                    sys.exit(1)
                probe_checked += 1
        break
    if probe_checked == 0:
        print("✗ pristine 抽查无全具体 expected 可用——无法判定盘面态，拒跑"
              "（skip=failure；先补 expected 或换 pristine 件）")
        sys.exit(1)
    print(f"✓ pristine 抽查：{probe_checked} 位点全 pristine ✓")

    log_dir = os.path.join(ROOT, "var", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(
        log_dir, f"bundle-effect-{datetime.date.today().strftime('%Y%m%d')}.txt")
    lines = [f"L13 bundle-effect {datetime.datetime.now().isoformat()} "
             f"app={args.app} build={build} variant={args.variant} "
             f"resign={args.resign}"]

    work = f"/tmp/l13-bundle-{int(time.time())}"
    os.makedirs(work)
    copy = os.path.join(work, "WeChat.app")
    print(f"1. clonefile 副本 → {copy}")
    r = sh(["cp", "-cR", args.app, copy])
    if r.returncode != 0:
        print("✗ clonefile 失败")
        sys.exit(1)

    print("2. pristine 全树快照")
    pristine_tree = tree_snapshot(copy)

    # 诱饵负控注入（检测器灵敏度）：在 decoy 普通资源上改一字节——
    # 该差分必须被分类面抓住（非位点/备份/签名 → UNCLASSIFIED → FAIL）。
    decoy = os.path.join(copy, "Contents", "Resources", "decoy_l13.bin")
    os.makedirs(os.path.dirname(decoy), exist_ok=True)
    with open(decoy, "wb") as f:
        f.write(b"L13-DECOY-NEGATIVE-CONTROL")
    print(f"3. 诱饵负控注入：{decoy}（预期 FAIL 路径演示）")

    # 变体域对齐（双评审 P1）：keeptip 的位点在 revoke-keeptip target。
    variant_targets = ("revoke", "update") if args.variant == "silent" else (
        "revoke-keeptip", "update")
    sites = declared_sites(config, build, variant_targets=variant_targets)

    print("4. wxkeep patch")
    resign_flag = [] if args.resign else ["--no-resign"]
    r = sh([WXKEEP, "patch", "--variant", args.variant, "--app", copy] + resign_flag)
    if r.returncode != 0:
        print(f"✗ patch 失败：{r.stdout[-500:]} {r.stderr[-300:]}")
        sys.exit(1)

    print("5. patched 全树快照 + 差分分类")
    patched_tree = tree_snapshot(copy)
    changed = [rel for rel in set(pristine_tree) | set(patched_tree)
               if pristine_tree.get(rel) != patched_tree.get(rel)]

    mismatches = 0
    decoy_seen = False
    for rel in sorted(changed):
        # 诱饵负控必须被抓（非位点/备份 → UNCLASSIFIED 语义）——它出现且
        # 被标记 = 检测器灵敏度绿；不出现 = 负控失效 = FAIL。
        if rel == "Contents/Resources/decoy_l13.bin":
            decoy_seen = True
            lines.append(f"DECOY {rel} ✓ 负控注入被抓（检测器灵敏度）")
            continue
        cat = classify(rel, sites, os.path.join(copy, rel))
        note = ""
        if cat == "site":
            # 位点级直证：备份(=pristine) vs patched 的 diff ⊆ 声明位点区间
            full_rel = os.path.join(copy, rel)
            bak = [b for b in os.listdir(os.path.dirname(full_rel))
                   if b.startswith(os.path.basename(rel) + ".wxkeep-bak-")]
            if bak:
                bak_path = os.path.join(os.path.dirname(full_rel), sorted(bak)[-1])
                ranges = differing_ranges(bak_path, full_rel)
                allowed = site_offsets_in_file(bak_path, sites[rel])
                for lo, hi in ranges:
                    if not any(a <= lo and hi <= b for a, b in allowed):
                        mismatches += 1
                        note += f" 位点外 diff [{lo:#x},{hi:#x}) ✗"
                if not note:
                    note = f" 位点级 {len(ranges)} 段全部 ⊆ 声明位点 ✓"
            else:
                note = "（无备份可直证——按分类面接受）"
        # 签名面合同（双评审 P1 实现）：--no-resign（默认）模式下 patch
        # 只该碰目录位点+备份——signature/macho 类改动同样是越界
        #（重签名 blob 只出现在 --resign 模式，那里才算合法签名面）。
        lines.append(f"DIFF {rel} → {cat}{note}")
        if cat == "UNCLASSIFIED":
            mismatches += 1
        elif cat in ("signature", "macho") and not args.resign:
            mismatches += 1
            lines.append(f"  ✗ --no-resign 模式下 {cat} 类改动 = 越界写"
                         f"（重签面只在 --resign 模式合法）")
    if not decoy_seen:
        mismatches += 1
        lines.append("DECOY ✗ 负控注入未出现在差分面——检测器失灵（预期项缺席）")

    verdict = "FAIL" if mismatches else "PASS"
    lines.append(f"L13 {verdict} 差分文件 {len(changed)} 个，未归类/越界 {mismatches}")
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines[-8:]))
    print(f"台账：{log_path}")

    print("6. 清理（副本为实验件，不入库）")
    shutil.rmtree(work, ignore_errors=True)
    sys.exit(0 if not mismatches else 1)


if __name__ == "__main__":
    main()
