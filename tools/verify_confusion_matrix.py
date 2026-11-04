#!/usr/bin/env python3
"""
verify_confusion_matrix.py — L12 真切片混淆矩阵驱动（V6-DEPTH D16/R15，133 轮）。

合成全矩阵已在 ConfusionMatrixTests 常跑（CI 真跑、零语料依赖）；本工具把
**真语料**的判别力普查补上：config.json 的 revoke 条目 × var/wxarm 真切片，
inspect 只读零写入，逐格产出「接受/拒绝」；随后用**独立 python 实现**
（machutil 段表换算 + 字节直读）双向复核：
  · swift 报「接受」的格子 ⇔ python 独立确认盘上字节 == expected 变体或
    asm 前缀（判别力=字节精确匹配的设计定义）；
  · 不一致 = 假接受/假拒绝 = FAIL（这正是共享序言构型下 L9 目标恒等门
    存在的理由——普查把共享构型的规模量化入台账）。

判定台账落 var/logs/confusion-matrix-<date>.txt（追加模式——同日重跑
不截断首跑记录）。skip = failure 纪律同 verify_staging 家系（语料缺失/
磁盘不足必须显式退出非零，不静默绿）。读取半边独立（slice_va_bytes
直读盘上字节 vs swift 上报值，不符 = FAIL）。

用法: var/venv/bin/python tools/verify_confusion_matrix.py [--sample N]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WXARM = os.path.join(ROOT, "var", "wxarm")
CONFIG = os.path.join(ROOT, "config.json")

ARM64_CPU = 0x0100000C
X64_CPU = 0x01000007


def fat_slices(path):
    """[(cputype, slice_offset, slice_size)] — machutil 同源口径（本文件
    独立实现 fat header 解析；thin 文件返回单切片）。"""
    with open(path, "rb") as f:
        head = f.read(8)
        if len(head) < 8:
            return []
        magic = struct.unpack(">I", head[:4])[0]
        if magic == 0xCAFEBABE:
            nfat = struct.unpack(">I", head[4:8])[0]
            out = []
            for i in range(nfat):
                f.seek(8 + i * 20)
                entry = f.read(20)
                cputype, _, offset, size, _ = struct.unpack(">iiIII", entry)
                out.append((cputype, offset, size))
            return out
        if magic == 0xFEEDFACF:
            cputype = struct.unpack("<I", head[4:8])[0]
            size = os.path.getsize(path)
            return [(cputype, 0, size)]
        return []


def slice_va_bytes(path, cputype, va, length):
    """某切片 VA 处 length 字节（走段表换算——machutil 同口径的独立实现）。
    落在文件背书区间外返回 None。"""
    with open(path, "rb") as f:
        slices = fat_slices(path)
        slice_off = next((off for ct, off, _ in slices if ct == cputype), None)
        if slice_off is None:
            return None
        f.seek(slice_off)
        header = f.read(32)
        if len(header) < 32 or struct.unpack("<I", header[:4])[0] != 0xFEEDFACF:
            return None
        ncmds = struct.unpack("<I", header[16:20])[0]
        cursor = slice_off + 32
        for _ in range(ncmds):
            f.seek(cursor)
            cmd_head = f.read(8)
            if len(cmd_head) < 8:
                return None
            cmd, cmdsize = struct.unpack("<II", cmd_head)
            if cmd == 0x19 and cmdsize >= 72:
                f.seek(cursor + 24)
                seg = f.read(40)
                vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", seg)
                if vmaddr <= va < vmaddr + filesize:
                    pos = slice_off + fileoff + (va - vmaddr)
                    if pos + length > os.path.getsize(path):
                        return None
                    f.seek(pos)
                    return f.read(length)
            cursor += cmdsize
    return None


def load_revoke_entries():
    """config.json → {build: [(arch_hex, addr_hex, [expected], asm)]}——
    revoke/revoke-keeptip 目标的条目（revoke-keeptip 与 revoke 位点重叠，
    取 revoke 域即可刻画判别力；3.x 主程序条目同样纳入）。"""
    config = json.load(open(CONFIG))
    out = {}
    for version in config:
        build = version.get("version")
        if not build:
            continue
        entries = []
        for target in version.get("targets", []):
            if target.get("identifier") != "revoke":
                continue
            for entry in target.get("entries", []):
                expected = entry.get("expected")
                if isinstance(expected, str):
                    expected = [expected]
                if not expected or not entry.get("asm"):
                    continue   # quarantined 条目无门可言，跳过
                entries.append({
                    "arch": entry.get("arch", "arm64"),
                    "addr": entry.get("addr"),
                    "expected": expected,
                    "asm": entry.get("asm"),
                })
        if entries:
            out[build] = entries
    return out


def available_builds():
    """var/wxarm 在场切片 → {build: {arch: path}}。"""
    out = {}
    for name in os.listdir(WXARM):
        m = re.match(r"^(\d+)_(arm64|x64)\.dylib$", name)
        if m:
            out.setdefault(m.group(1), {})[
                "arm64" if m.group(2) == "arm64" else "x86_64"] = os.path.join(WXARM, name)
    return out


def nibble_match(data_hex, pattern_hex):
    """ExpectedPattern 同语义的独立实现：`?` = 半字节通配；data ≥ pattern。
    全十六进制时退化为前缀比较。"""
    if len(data_hex) < len(pattern_hex):
        return False
    for d, p in zip(data_hex[:len(pattern_hex)].lower(), pattern_hex.lower()):
        if p != "?" and d != p:
            return False
    return True


def swift_state_of(current_hex, expected, asm):
    """Patcher.inspect 同语义的独立实现：prefix(asm) → patched；
    任一 expected 变体 match（含 ? 通配与 :mask 掩码尾——双评审 P2 修正：
    忽略 mask 会让真目录的掩码构型误报假接受）→ pristine；both →
    ambiguous；else unknown。"""
    cur = bytes.fromhex(current_hex)
    asm_b = bytes.fromhex(asm)
    asm_match = cur[:len(asm_b)] == asm_b
    cur_hex = current_hex.upper()
    exp_match = False
    wildcard = False
    for spec in expected:
        parts = spec.split(":")
        hexpart = parts[0]
        mask = parts[1][len("mask"):] if len(parts) > 1 and parts[1].startswith("mask") else None
        if mask is not None:
            # 掩码形：mask 的每 nibble F = 参与比较，0 = 忽略；pattern
            # 非通配 nibble 与 mask F 位一一对齐。
            if len(cur_hex) < len(mask):
                continue
            ok = True
            for i, (m, d, p) in enumerate(zip(mask.upper(), cur_hex,
                                              hexpart.upper())):
                if m == "F" and p != "?" and d != p:
                    ok = False
                    break
            if ok:
                exp_match = True
            continue
        if "?" in hexpart:
            wildcard = True
            if nibble_match(cur_hex, hexpart):
                exp_match = True
            continue
        eb = bytes.fromhex(hexpart)
        if cur[:len(eb)] == eb:
            exp_match = True
    if wildcard and not (asm_match or exp_match):
        return "wildcard-unreviewed"
    if asm_match and exp_match:
        return "ambiguous"
    if asm_match:
        return "patched"
    if exp_match:
        return "pristine"
    return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=3,
                    help="每 (from,to) 非对角对抽取的位点数（默认 3）")
    args = ap.parse_args()

    if not os.path.isdir(WXARM):
        print("✗ var/wxarm 无切片语料——L12 真件腿需要 pristine 切片库（skip=failure，"
              "见 V6-DEPTH §3）；CI 走合成矩阵，本地 SOP 跑本工具。")
        sys.exit(1)

    catalog = load_revoke_entries()
    slices = available_builds()
    paired = sorted(set(catalog) & set(slices))
    if not paired:
        print("✗ config.json 与 var/wxarm 无交集构建——无从普查。")
        sys.exit(1)

    log_dir = os.path.join(ROOT, "var", "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(
        log_dir, f"confusion-matrix-{datetime.date.today().strftime('%Y%m%d')}.txt")

    # 计划：全对角 + 非对角抽样（每对抽 min(sample, 条目数) 个位点）。
    # 抽样边界登记（133 轮双评审 P3）：对角只测该构建首选 arch；非对角对
    # 在 arch 集不交时整对丢弃（不回退另一 arch）——抽样策略由 --sample
    # 与切片在场性决定，台账头如实记录 pairs 数。
    plan = []
    for b in paired:
        arch_key = "arm64" if "arm64" in slices[b] else "x86_64"
        plan.append({"from": b, "to": b, "dylib": slices[b][arch_key],
                     "entries": [e for e in catalog[b] if e["arch"] == arch_key]})
    for i, b1 in enumerate(paired):
        for j, b2 in enumerate(paired):
            if i == j:
                continue
            arch_key = "arm64" if "arm64" in slices[b2] else "x86_64"
            entries = [e for e in catalog[b1] if e["arch"] == arch_key]
            if not entries:
                continue
            step = max(1, len(entries) // args.sample)
            plan.append({"from": b1, "to": b2, "dylib": slices[b2][arch_key],
                         "entries": entries[::step][:args.sample]})

    plan_path = os.path.join(ROOT, "var", "confusion-plan.json")
    json.dump(plan, open(plan_path, "w"))
    pairs = len({(p["from"], p["to"]) for p in plan})
    print(f"L12 混淆矩阵计划：{pairs} 对 × 抽样位点 → {plan_path}")

    # swift test 计划注入（TestingMacros 楔死兜底同款：-load-plugin-library
    # 显式装载 + 独立 scratch；4 次重试 2s 冷却）。
    env = dict(os.environ, WXKEEP_CONFUSION_PLAN=plan_path)
    tm = ("/Library/Developer/CommandLineTools/usr/lib/swift/host/"
          "plugins/testing/libTestingMacros.dylib")
    scratch = "/tmp/l12-confusion-scratch"
    shutil.rmtree(scratch, ignore_errors=True)
    out = ""
    for attempt in range(4):
        r = subprocess.run(
            ["swift", "test", "--disable-sandbox",
             "-Xswiftc", "-load-plugin-library", "-Xswiftc", tm,
             "--scratch-path", scratch, "--filter", "ConfusionMatrixReal"],
            capture_output=True, text=True, cwd=ROOT, timeout=3600, env=env)
        out = r.stdout + r.stderr
        build_flake = "✘" not in out and ("Build failed" in out
                                          or "could not be found for macro" in out)
        if build_flake and attempt < 3:
            print(f"  TestingMacros 楔死（attempt {attempt + 1}），2s 后重试")
            import time
            time.sleep(2)
            shutil.rmtree(scratch, ignore_errors=True)
            continue
        break
    cells = []
    for ln in out.splitlines():
        if ln.startswith("CONF "):
            try:
                cells.append(json.loads(ln[len("CONF "):]))
            except json.JSONDecodeError:
                pass
    if not cells:
        print("✗ swift 侧零 CONF 行输出——计划注入或测试执行失败：")
        print(out[-2000:])
        sys.exit(1)

    # 计划条目索引：(from,to) → {addr_hex: (entry, dylib_path)}
    entries_by_pair = {}
    for p in plan:
        for e in p["entries"]:
            entries_by_pair.setdefault((p["from"], p["to"]), {})[e["addr"].lower()] = (
                e, p["dylib"])

    # —— 独立复核（python 双向灵敏度）——
    # 读取半边（133 轮双评审 P1：此前只复核 swift 上报的 hex——swift 读错
    # 字节时 python 用错字节「确认一致」= 假绿）：每格用独立实现
    # slice_va_bytes 直读盘上字节，与 swift 上报值比对，不符 = FAIL。
    accepted = rejected = mismatch = 0
    diag_accepted = shared_shapes = readback_bad = malformed = 0
    lines = [f"L12 confusion-matrix {datetime.datetime.now().isoformat()}"
             f" sample={args.sample} pairs={pairs}"]
    for row in cells:
        frm, to = row["from"], row["to"]
        pair_entries = entries_by_pair.get((frm, to), {})
        for cell in row["cells"]:
            parts = cell.split(":")
            if len(parts) != 4:
                malformed += 1
                lines.append(f"CONF-PAIR {frm}->{to} 输出格式异常: {cell[:40]}… ✗")
                mismatch += 1
                continue
            verdict, state, addr, current = parts
            slot = pair_entries.get(addr.lower())
            expect_state = "n/a"
            if slot:
                entry, dylib_path = slot
                # 读取半边：独立实现直读盘上字节 vs swift 上报的 current
                cpu = ARM64_CPU if entry["arch"] == "arm64" else X64_CPU
                expect_len = len(current) // 2
                disk = slice_va_bytes(dylib_path, cpu, int(addr, 16), expect_len)
                if disk is not None and disk.hex().upper() != current.upper():
                    readback_bad += 1
                    mismatch += 1
                    lines.append(f"CONF-PAIR {frm}->{to} @{addr} 读取复核不符："
                                 f"swift={current[:16]}… py={disk.hex().upper()[:16]}… ✗")
                    continue
                expect_state = swift_state_of(current, entry["expected"], entry["asm"])
            if verdict == "accept":
                accepted += 1
                if expect_state in ("pristine", "ambiguous", "patched",
                                    "wildcard-unreviewed"):
                    if expect_state in ("pristine", "ambiguous"):
                        if frm == to:
                            diag_accepted += 1
                        else:
                            shared_shapes += 1
                    lines.append(f"CONF-PAIR {frm}->{to} @{addr} {state} vs py:{expect_state} ✓")
                else:
                    mismatch += 1
                    lines.append(f"CONF-PAIR {frm}->{to} @{addr} 假接受 swift:{state} "
                                 f"py:{expect_state} current={current[:16]}… ✗")
            else:
                rejected += 1
                if expect_state in ("unknown", "wildcard-unreviewed", "n/a"):
                    lines.append(f"CONF-PAIR {frm}->{to} @{addr} reject vs py:{expect_state} ✓")
                else:
                    mismatch += 1
                    lines.append(f"CONF-PAIR {frm}->{to} @{addr} 假拒绝 swift:reject "
                                 f"py:{expect_state} current={current[:16]}… ✗")

    verdict = "FAIL" if mismatch else "PASS"
    lines.append(f"L12 {verdict} accept={accepted} reject={rejected} "
                 f"mismatch={mismatch} 对角接受={diag_accepted} "
                 f"跨构建共享构型接受={shared_shapes} "
                 f"（设计边界规模，上层防线=L9 目标恒等门+行为 verify）；"
                 f"读取复核不符={readback_bad} 坏行={malformed}")
    # 追加模式（133 轮双评审 P2：同日重跑截断会抹掉首跑失败记录）。
    with open(log_path, "a") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines[-5:]))
    print(f"台账：{log_path}")
    sys.exit(0 if not mismatch else 1)


if __name__ == "__main__":
    main()
