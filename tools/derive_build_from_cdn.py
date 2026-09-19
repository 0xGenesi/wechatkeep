#!/usr/bin/env python3
"""
derive_build_from_cdn.py — CDN 归档构建 → 全位点派生 → staging config。

4.1.13 全线回捞轮（2026-09-19）的驱动脚本：对 var/cdn 的官方归档 dmg
（xWeChatMac_universal_<点分>_<构建>.dmg）执行完整派生链并产出
var/staging/<build>.json（后续合入 config.json 前的暂存产物）：

  1. 切片抽取    dmg → var/wxarm/<build>_{x64,arm64}.dylib（thin，不留 fat）
  2. revoke      wxkeep locate --append（配方引擎，双架构；fake bundle）
  3. guard       locate_x64_parse_guard.py（test→xor 条目）
  4. keeptip x64 parse 入口内 E8+newmsgid store 唯一命中（expected 按实读字节）
                 + isRevokemsg 归一化恢复型条目
  5. update      locate_update_x64.py（XAppUpdateManager 四方法 + 访问器对；
                 类不存在的构建诚实跳过）
  6. arm64 keeptip（仅目录外新构建）：按命中配方的代际几何派生
                 （cbz 归一化 + newmsgid 存储清零对）
  7. 隔离回填    目录内已有条目缺 expected 者，按 (arch, addr) 实读字节回填

用法:
  python3 tools/derive_build_from_cdn.py --build 269627 --dotted 4.1.13.59 \
      [--download] [--prune-dmg] [--staging-dir var/staging]

安全: 只读官方 dmg 与本地切片；staging 不直接进 config.json（合并与
manifest 重签由收尾轮统一做）。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import machutil  # noqa: E402

X64, ARM64 = machutil.CPU_X86_64, machutil.CPU_ARM64
CDN_URL_FMT = ("https://dldir1v6.qq.com/weixin/Universal/Mac/"
               "xWeChatMac_universal_{dotted}_{build}.dmg")

# arm64 各代 keeptip 几何（与 signatures.json 配方 confirm 同源）：
#   代 → (anchor 后存储偏移, 原始存储字节, 清零 asm, cbz 原始字节)
ARM64_GEN_KEEPTIP = {
    "revoke_arm64_gen1": (0x794, "60B600F9", "7FB600F9", "E00F0034"),
    "revoke_arm64_gen2": (0x7A0, "60CE00F9", "7FCE00F9", "40100034"),
    "revoke_arm64_gen3": (0x7A0, "60E600F9", "7FE600F9", "40100034"),
}

REV_X64_EXPECTED = "554889E553504889FB"      # isRevokemsg 序言（家族恒定）
REV_X64_ASM = "31C0C3909090909090"
KEEPTIP_STORE_ASM = "4831C06690488983C8010000"
STORE_TAIL = b"\x48\x89\x83\xc8\x01\x00\x00"  # mov [rbx+0x1C8],rax


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def die(msg):
    print(f"  ✗ {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- 切片抽取
def ensure_thins(build, dotted, download, prune_dmg):
    x64 = os.path.join(ROOT, "var/wxarm", f"{build}_x64.dylib")
    arm = os.path.join(ROOT, "var/wxarm", f"{build}_arm64.dylib")
    if os.path.exists(x64) and os.path.exists(arm):
        return x64, arm
    dmg = os.path.join(ROOT, "var/cdn", f"xWeChatMac_universal_{dotted}_{build}.dmg")
    if not os.path.exists(dmg):
        if not download:
            die(f"无 {dmg}（--download 可自动拉取）")
        url = CDN_URL_FMT.format(dotted=dotted, build=build)
        print(f"  下载 {url}")
        with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "wxkeep"}),
                timeout=1800) as r, open(dmg, "wb") as f:
            shutil.copyfileobj(r, f)
    mount = tempfile.mkdtemp(prefix="wxkeep-mount-")
    r = sh(["hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mount, dmg])
    if r.returncode != 0:
        die(f"挂载失败: {r.stderr.strip()[:120]}")
    try:
        src = None
        for root, _dirs, files in os.walk(mount):
            if "wechat.dylib" in files:
                src = os.path.join(root, "wechat.dylib")
                break
        if not src:
            die("dmg 内无 wechat.dylib")
        fat = os.path.join(ROOT, "var/wxarm", f"{build}_fat.tmp.dylib")
        shutil.copy(src, fat)
        for thin, cpu, name in ((x64, "x86_64", "x64"), (arm, "arm64", "arm64")):
            r = sh(["lipo", "-thin", cpu, fat, "-output", thin])
            if r.returncode != 0:
                die(f"lipo {name} 失败: {r.stderr.strip()[:120]}")
        os.unlink(fat)
    finally:
        sh(["hdiutil", "detach", mount, "-force"])
    if prune_dmg:
        os.unlink(dmg)
        print(f"  已抽取并删除 dmg（省磁盘策略）")
    return x64, arm


# ---------------------------------------------------------------- revoke（配方引擎）
def run_locate(build, x64thin, armthin, staging):
    """fake bundle（双 thin 合成的临时 fat）→ locate --append → staging。
    返回 {recipe_name: site_va}。"""
    work = tempfile.mkdtemp(prefix="wxkeep-locate-")
    app = os.path.join(work, f"WeChat_{build}.app")
    res = os.path.join(app, "Contents", "Resources")
    os.makedirs(res, exist_ok=True)
    fat = os.path.join(work, "fat.dylib")
    r = sh(["lipo", "-create", x64thin, armthin, "-output", fat])
    if r.returncode != 0:
        die(f"lipo -create 失败: {r.stderr.strip()[:120]}")
    shutil.copy(fat, os.path.join(res, "wechat.dylib"))
    with open(os.path.join(app, "Contents", "Info.plist"), "w") as f:
        f.write(f'<?xml version="1.0"?><plist version="1.0"><dict>'
                f'<key>CFBundleVersion</key><string>{build}</string></dict></plist>')
    wxkeep = os.path.join(ROOT, ".build/release/wxkeep")
    r = sh([wxkeep, "locate", "-a", app, "--append", "--config", staging])
    sites = {}
    for m in re.finditer(r"\[(\w+)\] ✓ site 0x([0-9A-Fa-f]+)", r.stdout):
        sites[m.group(1)] = int(m.group(2), 16)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        die("locate 失败")
    shutil.rmtree(work, ignore_errors=True)
    return sites


# ---------------------------------------------------------------- guard + keeptip x64
def derive_guard_and_keeptip(x64thin, rev_x64_site):
    r = sh(["python3", os.path.join(HERE, "locate_x64_parse_guard.py"), x64thin])
    m = re.search(r"条目: addr=([0-9a-f]+)\s+expected=(\S+)\s+asm=(\S+)", r.stdout)
    if not m:
        return None, None, r.stdout[-400:]
    guard = {"addr": m.group(1), "expected": [m.group(2)], "asm": m.group(3)}

    d = machutil.load_slice(x64thin, X64)
    funcs = machutil.function_starts(d)
    g = int(guard["addr"], 16)
    parse_entry = max((f for f in funcs if f <= g), default=None)
    if parse_entry is None:
        return guard, None, "parse 入口未找到"
    nxt = min((f for f in funcs if f > parse_entry), default=None)
    off = machutil.va2off(d, parse_entry)
    end = machutil.va2off(d, nxt) if nxt else off + 0x2000
    hits, o = [], off
    while o + 12 <= end:
        if d[o] == 0xE8 and d[o + 5:o + 12] == STORE_TAIL:
            hits.append(parse_entry + (o - off))
        o += 1
    if len(hits) != 1:
        return guard, None, f"keeptip store 命中 {len(hits)} 处（需唯一）"
    site = hits[0]
    so = machutil.va2off(d, site)
    expected = d[so:so + 12].hex().upper()
    if not expected.endswith(STORE_TAIL.hex().upper()):
        return guard, None, f"store 尾字节异常: {expected}"
    keeptip = {
        "store": {"addr": format(site, "x"), "expected": [expected],
                  "asm": KEEPTIP_STORE_ASM},
        "normalize": {"addr": format(rev_x64_site, "x"), "asm": REV_X64_EXPECTED,
                      "expected": [REV_X64_ASM, REV_X64_EXPECTED]},
    }
    return guard, keeptip, None


def check_rev_x64_bytes(x64thin, site):
    d = machutil.load_slice(x64thin, X64)
    off = machutil.va2off(d, site)
    actual = d[off:off + 9].hex().upper()
    if actual != REV_X64_EXPECTED:
        die(f"isRevokemsg 序言家族漂移: {actual}（配方静态 expected 将失配）")


# ---------------------------------------------------------------- update
def derive_update(x64thin, build):
    r = sh(["python3", os.path.join(HERE, "locate_update_x64.py"), x64thin])
    if "not found" in (r.stdout + r.stderr):
        return None, "XAppUpdateManager 不存在（该构建更新器走 C++/其他类）"
    entries = []
    m = re.search(r"=== config\.json update target.*?===\s*(\{.*\})\s*$",
                  r.stdout, re.S)
    if m:
        for e in json.loads(m.group(1))["entries"]:
            entries.append({
                "arch": "x86_64", "addr": e["addr"],
                "expected": [e["expected"]], "asm": e["asm"],
                "source": f"wxkeep:objc:{e['source'].split(':', 1)[1]}@{build}"})
        return entries, None
    # 工具因 problems 退出（无 JSON 段）→ 只收形态良好的 ret 方法行
    for sel, imp, exp in re.findall(
            r"ret  (\S+)\s+imp 0x([0-9A-Fa-f]+) expected ([0-9A-F]+)(?!\s*<<<)", r.stdout):
        entries.append({
            "arch": "x86_64", "addr": format(int(imp, 16), "x"),
            "expected": [exp], "asm": "C3",
            "source": f"wxkeep:objc:{sel}@{build}"})
    note = "访问器对形态不符已跳过（只入 ret 方法）" if entries else "无可用 update 条目"
    return entries or None, note + (f"; 工具输出尾: {r.stdout[-200:]}" if not entries else "")


# ---------------------------------------------------------------- arm64 keeptip（新构建）
def derive_arm64_keeptip(armthin, recipe_name, site):
    geo = ARM64_GEN_KEEPTIP.get(recipe_name)
    if geo is None:
        return None, f"配方 {recipe_name} 无 keeptip 几何"
    off, store_bytes, zero_asm, cbz = geo
    d = machutil.load_slice(armthin, ARM64)
    so = machutil.va2off(d, site + off)
    actual = d[so:so + 4].hex().upper()
    if actual != store_bytes:
        return None, f"arm64 store 字节 {actual} ≠ 家族 {store_bytes}"
    return [
        {"arch": "arm64", "addr": format(site, "x"), "asm": cbz,
         "expected": [cbz]},
        {"arch": "arm64", "addr": format(site + off, "x"), "asm": zero_asm,
         "expected": [store_bytes]},
    ], None


# ---------------------------------------------------------------- 隔离回填
def quarantine_backfill(build, x64thin, armthin):
    cfg_path = os.path.join(ROOT, "config.json")
    cfg = json.load(open(cfg_path))
    v = next((x for x in cfg if x["version"] == build), None)
    if not v:
        return []
    slices = {X64: machutil.load_slice(x64thin, X64),
              ARM64: machutil.load_slice(armthin, ARM64)}
    out = []
    for t in v["targets"]:
        for e in t["entries"]:
            if e.get("expected"):
                continue
            cpu = ARM64 if e["arch"] == "arm64" else X64
            d = slices[cpu]
            off = machutil.va2off(d, int(e["addr"], 16))
            n = len(bytes.fromhex(e["asm"]))
            raw = d[off:off + n] if off is not None else None
            if raw is None or len(raw) != n:
                out.append({"identifier": t["identifier"], "arch": e["arch"],
                            "addr": e["addr"], "error": "读取失败"})
                continue
            out.append({"identifier": t["identifier"], "arch": e["arch"],
                        "addr": e["addr"], "expected": [raw.hex().upper()]})
    return out


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True)
    ap.add_argument("--dotted", required=True, help="点分营销版本（CDN 文件名用）")
    ap.add_argument("--new-build", action="store_true",
                    help="目录外新构建（额外派生 arm64 revoke+keeptip）")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--prune-dmg", action="store_true", help="抽取后删除 dmg（省磁盘）")
    ap.add_argument("--staging-dir", default=os.path.join(ROOT, "var/staging"))
    args = ap.parse_args()

    os.makedirs(args.staging_dir, exist_ok=True)
    x64thin, armthin = ensure_thins(args.build, args.dotted,
                                    args.download, args.prune_dmg)
    print(f"[{args.build}] 切片就绪")

    staging = os.path.join(args.staging_dir, f"{args.build}.locate.json")
    if os.path.exists(staging):
        os.unlink(staging)
    sites = run_locate(args.build, x64thin, armthin, staging)
    print(f"[{args.build}] locate 命中: " +
          ", ".join(f"{k}=0x{v:x}" for k, v in sorted(sites.items())))

    report = {"build": args.build, "dotted": args.dotted, "notes": []}
    targets = []   # 最终 target 组装（从 locate 产物起步）

    # revoke target（locate 已写 staging；读回并整形）
    located = json.load(open(staging))
    rev_t = next((t for t in located[0]["targets"] if t["identifier"] == "revoke"), None)
    if rev_t:
        for e in rev_t["entries"]:
            e["expected"] = [e["expected"]] if isinstance(e["expected"], str) else e["expected"]
        targets.append(rev_t)
    else:
        rev_t = None

    # guard（并入 revoke target）
    rev_site = sites.get("revoke_x64")
    if rev_site:
        check_rev_x64_bytes(x64thin, rev_site)
        guard, keeptip, err = derive_guard_and_keeptip(x64thin, rev_site)
        if guard:
            if rev_t is None:
                rev_t = {"identifier": "revoke",
                         "binary": "Contents/Resources/wechat.dylib", "entries": []}
                targets.append(rev_t)
            guard.update({
                "arch": "x86_64",
                "source": (f"wxkeep:parse-guard test→xor 翻转（{args.build} 冗余 silent，"
                           "2026-09-19 4.1.13 全线回捞轮）")})
            rev_t["entries"].append(guard)
        else:
            report["notes"].append(f"guard/keeptip 未派生: {err}")

        if keeptip:
            kt = {"identifier": "revoke-keeptip",
                  "binary": "Contents/Resources/wechat.dylib", "entries": [
                {"arch": "x86_64", "addr": keeptip["normalize"]["addr"],
                 "asm": keeptip["normalize"]["asm"],
                 "expected": keeptip["normalize"]["expected"],
                 "source": f"wxkeep:{args.build} keeptip——还原 isRevokemsg（解除 silent）"},
                {"arch": "x86_64", "addr": keeptip["store"]["addr"],
                 "asm": keeptip["store"]["asm"],
                 "expected": keeptip["store"]["expected"],
                 "source": (f"wxkeep:{args.build} keeptip——v1语义：parse 内 newmsgid "
                            "转换call置零（expected 按实读字节；家族恒定 E8+store 形态）")},
            ]}
            targets.append(kt)
    else:
        report["notes"].append("revoke_x64 配方未命中（无 guard/keeptip 派生）")

    # update
    upd_entries, upd_note = derive_update(x64thin, args.build)
    if upd_entries:
        targets.append({"identifier": "update",
                        "binary": "Contents/Resources/wechat.dylib",
                        "entries": upd_entries})
    if upd_note:
        report["notes"].append(f"update: {upd_note}")

    # arm64 keeptip（仅新构建；arm64 revoke 已由 locate 产出）
    if args.new_build:
        arm_recipe = next((k for k in sites if k.startswith("revoke_arm64_gen")
                           and not k.endswith("gen0")), None)
        if arm_recipe:
            kt_arm, err = derive_arm64_keeptip(armthin, arm_recipe, sites[arm_recipe])
            if kt_arm:
                kt = next((t for t in targets if t["identifier"] == "revoke-keeptip"),
                          {"identifier": "revoke-keeptip", "entries": []})
                for e in kt_arm:
                    e["source"] = (f"wxkeep:{args.build} keeptip arm64——"
                                   f"{arm_recipe} 几何派生（cbz 归一 + 存储清零）")
                    kt["entries"].append(e)
                if not any(t is kt for t in targets):
                    targets.append(kt)
            else:
                report["notes"].append(f"arm64 keeptip: {err}")
        else:
            report["notes"].append("arm64 配方未命中（keeptip 未派生）")

    # 隔离回填
    backfill = quarantine_backfill(args.build, x64thin, armthin)
    ok = [b for b in backfill if "expected" in b]
    report["backfill"] = ok
    report["backfill_failed"] = len(backfill) - len(ok)

    report["targets"] = targets
    out = os.path.join(args.staging_dir, f"{args.build}.json")
    json.dump(report, open(out, "w"), indent=1, ensure_ascii=False)
    os.unlink(staging)

    n = {t["identifier"]: len(t["entries"]) for t in targets}
    print(f"[{args.build}] 派生完成 → {out}")
    print(f"  条目: {n}  隔离回填: {len(report['backfill'])} 条"
          + (f"（失败 {report['backfill_failed']}）" if report["backfill_failed"] else ""))
    for note in report["notes"]:
        print(f"  note: {note}")


if __name__ == "__main__":
    main()
