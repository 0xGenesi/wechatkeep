#!/usr/bin/env python3
"""diff_engine_twin.py — L17 差分引擎孪生（V7-DEPTH D21/R21，134 轮）。

差分测试学派（Csmith / TLS-Attacker 脉络）：找引擎逻辑 bug 最强的武器是
**第二个独立实现**。既有 Python 工具各复算单一性质（混淆矩阵 / bundle 差分）；
本工具把独立性升格到引擎写入语义本体——

  * Python 侧：按 spec（槽位级字节模拟：变体互斥 undo / 归一化条目 /
    only 过滤 / always-apply 目标 / 共享 VA 后写者赢 / 混长 asm<expected /
    隔离条目 alreadyPatched 先于 missingExpected / restore preflight）独立
    预测每命令后的全位点字节与命令成败；
  * Swift 侧：真跑 CLI 子进程（完整编排链：journal→引擎→收口）；
  * 逐命令逐位点比对：任何分歧 = 红 + 双侧字节落盘对账。

语料：真实 config.json 全 123 构建 2001 条目（list 形 expected / 双 arch /
dylib+主可执行双 binary / update 16 条目集 / 掩码通配），VA 重排进合成
fat 夹具（dense 映射，字节语义不变）。随机种子化可复现。

用法:
  python3 tools/diff_engine_twin.py [--trials 60] [--seed 1] [--cli PATH] \
      [--config config.json] [--log-dir var/logs]

判定: 全部试验逐位点恒等 + 成败预测一致 → "L17 PASS trials=N diffs=0 ..."。
（evidence-ledger L17 族判定行；asm 含通配的槽位只断言合法集，计数登记。）
"""
import argparse
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

VARIANT_TARGET = {"silent": "revoke", "keeptip": "revoke-keeptip"}
OTHER_TARGET = {"silent": "revoke-keeptip", "keeptip": "revoke"}
ALWAYS_EXCLUDE = {"revoke", "revoke-keeptip", "revoke-keeptip2"}
COMMANDS = ["silent", "keeptip", "silent:only-update", "keeptip:only-revoke", "restore"]


# ---------- Mach-O 夹具（与 Swift 侧 MachOFixture 同布局合同：VA==fileoff） ----------

def thin_image(cputype, size, sites):
    data = bytearray(size)
    def put32(off, v): data[off:off + 4] = struct.pack("<I", v)
    def put64(off, v): data[off:off + 8] = struct.pack("<Q", v)
    put32(0, 0xFEEDFACF); put32(4, cputype & 0xFFFFFFFF)
    put32(8, 0); put32(12, 6)          # MH_DYLIB（切片解析合同，与 MachOFixture 同）
    put32(16, 1); put32(20, 152)
    put32(32, 0x19); put32(36, 152)
    data[40:45] = b"__TEXT"
    put64(56, 0); put64(64, size); put64(72, 0); put64(80, size)
    put32(88, 7); put32(92, 7); put32(96, 1); put32(100, 0)
    data[104:109] = b"__text"; data[120:126] = b"__TEXT"
    put64(128, 0); put64(136, size); put32(144, 0x68); put32(148, 3); put32(152, size)
    for off, b in sites.items():
        data[off:off + len(b)] = b
    return bytes(data)

def fat_image(arm_sites, x64_sites):
    arm = thin_image(0x0100000C, max(arm_sites) + 0x80 if arm_sites else 0x400, arm_sites)
    x64 = thin_image(0x01000007, max(x64_sites) + 0x80 if x64_sites else 0x400, x64_sites)
    arm_off, x64_off = 0x1000, (0x1000 + len(arm) + 0xFFF) & ~0xFFF
    out = bytearray(x64_off + len(x64))
    struct.pack_into(">II", out, 0, 0xCAFEBABE, 2)
    struct.pack_into(">IIIII", out, 8, 0x0100000C, 0, arm_off, len(arm), 12)
    struct.pack_into(">IIIII", out, 28, 0x01000007, 0, x64_off, len(x64), 12)
    out[arm_off:arm_off + len(arm)] = arm
    out[x64_off:x64_off + len(x64)] = x64
    return bytes(out), arm_off, x64_off


# ---------- hex 工具（含 '?' 半字节通配） ----------

def hx(s):
    return bytes.fromhex(s) if s else b""

def parse_masked_hex(s):
    """→ (bytes, mask)；mask[i]==0 表示该字节含通配（现行 DSL 只支持整字节
    '?'）。None = 不支持的形态。"""
    if not isinstance(s, str) or len(s) % 2:
        return None
    known, mask = bytearray(), bytearray()
    for i in range(0, len(s), 2):
        hi, lo = s[i], s[i + 1]
        if hi == "?" and lo == "?":
            known.append(0); mask.append(0)
        elif hi != "?" and lo != "?":
            known.append(int(hi + lo, 16)); mask.append(0xFF)
        else:
            return None
    return bytes(known), bytes(mask)

def matches_spec(spec, data):
    known, mask = spec
    if len(data) < len(known):
        return False
    seg = data[:len(known)]
    return all((seg[i] & mask[i]) == (known[i] & mask[i]) for i in range(len(known)))


# ---------- 目录条目形态 ----------

def entry_forms(entry):
    exp = entry.get("expected")
    exps = exp if isinstance(exp, list) else ([exp] if exp else [])
    return entry.get("asm", ""), exps

def entry_unrestorable(entry):
    """restore 前置（Engine.restoreAsm 的独立转译）：expected 缺失，或
    asm ∉ expected 且 expected[0] 的通配位落进 asm 跨度。归一化（asm ∈
    expected）恒可还原。"""
    exp = entry.get("expected")
    if not exp:
        return True
    exps = exp if isinstance(exp, list) else [exp]
    asm = entry.get("asm", "")
    if asm in exps:
        return False
    first = exps[0]
    asm_len = len(asm) // 2
    if not isinstance(first, str) or len(first) % 2:
        return True
    for i in range(0, min(len(first), asm_len * 2), 2):
        if first[i] == "?" or first[i + 1] == "?":
            return True
    return False

def target_unrestorable(target):
    return any(entry_unrestorable(e) for e in target.get("entries", []))


# ---------- 试验计划（VA 重排 + pristine 选定） ----------

def build_plan(version_entry, rng):
    targets = [t for t in version_entry.get("targets", [])
               if t.get("identifier") != "revoke-keeptip2"]
    if not targets:
        return None
    slot_key_index = {}   # (binary, arch, va) -> idx
    slot_meta = {}
    for t in targets:
        binary = t.get("binary", "Contents/MacOS/WeChat")
        for e in t.get("entries", []):
            va = int(e["addr"], 16)
            arch = e.get("arch", "arm64")
            key = (binary, arch, va)
            if key not in slot_key_index:
                slot_key_index[key] = len(slot_meta)
                slot_meta[slot_key_index[key]] = {"va_orig": va, "arch": arch,
                                                  "binary": binary, "entries": []}
            asm, exps = entry_forms(e)
            slot_meta[slot_key_index[key]]["entries"].append((t["identifier"], asm, exps))

    for m in slot_meta.values():
        m["pristine"] = None
        for (_, asm, exps) in m["entries"]:
            if exps and asm not in exps:
                m["pristine"] = exps[0]
                break
        if m["pristine"] is None:
            # 全归一化或全无 expected（无操作条目）：asm 即现形
            m["pristine"] = m["entries"][0][1]
        spec = parse_masked_hex(m["pristine"])
        if spec is None:
            return None
        known, mask = spec
        m["pristine_bytes"] = bytes(b & m_ for b, m_ in zip(known, mask))
        # 槽位读面长度 = asm/expected 变体最大跨度（与 Patcher siteLen 同源）
        lens = [len(hx(a)) for (_, a, _) in m["entries"] if a]
        for (_, a, exps) in m["entries"]:
            for form in exps:
                spec = parse_masked_hex(form)
                if spec:
                    lens.append(len(spec[0]))
        m["span"] = max(lens + [len(m["pristine_bytes"])])

    remap, counters = {}, {}
    for idx in sorted(slot_meta):
        m = slot_meta[idx]
        ck = (m["binary"], m["arch"])
        n = counters.get(ck, 0)
        remap[idx] = 0x100 + n * 0x40
        counters[ck] = n + 1

    config = []
    for t in version_entry.get("targets", []):
        if t.get("identifier") == "revoke-keeptip2":
            continue
        binary = t.get("binary", "Contents/MacOS/WeChat")
        ents = []
        for e in t.get("entries", []):
            va = int(e["addr"], 16)
            arch = e.get("arch", "arm64")
            e2 = dict(e)
            e2["addr"] = format(remap[slot_key_index[(binary, arch, va)]], "x")
            ents.append(e2)
        config.append({"identifier": t["identifier"], "binary": binary, "entries": ents})

    seq = [rng.choice(COMMANDS) for _ in range(rng.randint(1, 4))]
    return {"config": [dict(version=version_entry["version"], targets=config)],
            "slot_meta": slot_meta, "slot_key_index": slot_key_index,
            "remap": remap, "seq": seq}


# ---------- spec 侧：失败预测 + 槽位级字节模拟 ----------

def predict_failure(version_entry, plan, cmd, cur_bytes, entry_slot):
    """预测命令失败（CLI 非零退出、零写入）。隔离条目（无 expected）只在
    盘面前缀 ≠ asm 时拒——Patcher 写循环 alreadyPatched 判定先于
    missingExpected（268851 实证：multiInstance 无操作条目恒 skip）。"""
    tmap = {}
    for t in version_entry["targets"]:
        if t["identifier"] != "revoke-keeptip2":
            tmap.setdefault(t["identifier"], []).append(t)
    variant, _, only = cmd.partition(":only-")

    if cmd == "restore":
        return any(target_unrestorable(t) for ts in tmap.values() for t in ts)

    def quarantined_would_fire(tid_list):
        for tid in tid_list:
            for t in tmap.get(tid, []):
                for e in t.get("entries", []):
                    if e.get("expected"):
                        continue
                    a = hx(e.get("asm", ""))
                    if not a:
                        return True
                    idx = entry_slot[id(e)]
                    if bytes(cur_bytes[idx][:len(a)]) != a:
                        return True
        return False

    if only == "update":
        return "update" not in tmap or quarantined_would_fire(["update"])
    if only == "revoke":
        vid = VARIANT_TARGET[variant]
        return vid not in tmap or quarantined_would_fire([vid])
    vid = VARIANT_TARGET[variant]
    if vid not in tmap:
        return True
    always = [k for k in tmap if k not in ALWAYS_EXCLUDE]
    return quarantined_would_fire([vid] + always)


def simulate(version_entry, plan, seq):
    """槽位级字节模拟：①成功命令按引擎顺序写——undo 臂（另一变体可还原
    时）→ 选中 target 按 targets 数组序；②共享 VA 后写者赢；③asm 前缀
    替换（混长尾保持）；④alreadyPatched 跳过；⑤预测失败零写入；⑥restore
    按数组序全还原（归一化写 asm、否则 expected[0] 物化前缀）。"""
    tlist = [t for t in version_entry["targets"] if t.get("identifier") != "revoke-keeptip2"]
    ids = [t["identifier"] for t in tlist]
    always = [i for i in ids if i not in ALWAYS_EXCLUDE]
    entry_slot = {}
    for t in tlist:
        binary = t.get("binary", "Contents/MacOS/WeChat")
        for e in t.get("entries", []):
            va = int(e["addr"], 16)
            arch = e.get("arch", "arm64")
            entry_slot[id(e)] = plan["slot_key_index"][(binary, arch, va)]
    cur = {idx: bytearray(m["pristine_bytes"]) for idx, m in plan["slot_meta"].items()}

    def write_asm(e):
        a = hx(e.get("asm", ""))
        if not a:
            return
        buf = cur[entry_slot[id(e)]]
        if bytes(buf[:len(a)]) != a:
            buf[:len(a)] = a

    def write_restore(e):
        asm, exps = entry_forms(e)
        if exps and asm in exps:
            form = hx(asm)                       # 归一化：asm 即现形
        elif exps:
            spec = parse_masked_hex(exps[0])
            if spec is None:
                return
            known, mask = spec
            a = hx(asm)
            n = len(a) if any(b != 0xFF for b in mask) else len(known)
            form = bytes(known[:n])              # 通配尾只写 asm 跨度内具体前缀
        else:
            return
        buf = cur[entry_slot[id(e)]]
        if len(form) <= len(buf):
            buf[:len(form)] = form

    for cmd in seq:
        if predict_failure(version_entry, plan, cmd, cur, entry_slot):
            continue
        if cmd == "restore":
            for t in tlist:
                for e in t.get("entries", []):
                    write_restore(e)
            continue
        variant, _, only = cmd.partition(":only-")
        vid = VARIANT_TARGET[variant]
        if only:
            sel = ["update"] if only == "update" else [vid]
        else:
            sel = [vid] + always
        # undo 臂触发条件 = 变体 target 在本次选中集（Engine.patch 的
        # `selected.contains(variantID)`）：--only update 不含变体域 → 不触发；
        # --only revoke / 全量命令 → 触发（另一变体可还原才真正执行）。
        if vid in sel:
            other_t = next((t for t in tlist if t["identifier"] == OTHER_TARGET[variant]), None)
            if other_t is not None and not target_unrestorable(other_t):
                for e in other_t.get("entries", []):
                    write_restore(e)
        for tid in sel:
            for t in [x for x in tlist if x["identifier"] == tid]:
                for e in t.get("entries", []):
                    write_asm(e)
    return cur, entry_slot


def legal(slot, data):
    for (_, asm, exps) in slot["entries"]:
        for form in ([asm] if asm else []) + [x for x in exps if isinstance(x, str)]:
            spec = parse_masked_hex(form)
            if spec and matches_spec(spec, data):
                return True
    return False


# ---------- 驱动 ----------

def run_cli(cli, args, env_extra):
    env = dict(os.environ); env.update(env_extra)
    p = subprocess.run([cli] + args, capture_output=True, text=True, env=env, timeout=120)
    return p.returncode, p.stdout + p.stderr

def read_at(path, off, length):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(length)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--cli", default=None)
    ap.add_argument("--config", default=os.path.join(ROOT, "config.json"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "var", "logs"))
    args = ap.parse_args()

    cli = args.cli or next((os.path.join(ROOT, p) for p in
                            (".build/out/Products/Debug/wxkeep", ".build/debug/wxkeep")
                            if os.access(os.path.join(ROOT, p), os.X_OK)), None)
    if not cli:
        print("FAIL: wxkeep CLI 不可执行文件", file=sys.stderr); sys.exit(2)

    catalog = json.load(open(args.config))
    versions = catalog if isinstance(catalog, list) else catalog.get("versions", catalog)
    rng = random.Random(args.seed)

    os.makedirs(args.log_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(args.log_dir, f"engine-twin-{ts}.txt")
    log = open(log_path, "w", buffering=1)

    diffs = trials_run = masked_slots = 0
    t0 = time.time()
    for trial in range(args.trials):
        version_entry = rng.choice(versions)
        plan = build_plan(version_entry, rng)
        if plan is None:
            continue
        build = version_entry["version"]
        with tempfile.TemporaryDirectory(prefix="wxkeep-twin-") as work:
            data_dir = os.path.join(work, "data"); os.makedirs(data_dir)
            app = os.path.join(work, "TWIN.app")
            res = os.path.join(app, "Contents", "Resources")
            macos = os.path.join(app, "Contents", "MacOS")
            os.makedirs(res, exist_ok=True); os.makedirs(macos, exist_ok=True)
            with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
                f.write(('<?xml version="1.0" encoding="UTF-8"?>'
                         '<plist version="1.0"><dict>'
                         '<key>CFBundleVersion</key><string>%s</string>'
                         '<key>CFBundleExecutable</key><string>TWIN</string>'
                         '</dict></plist>' % build).encode())
            cfg_path = os.path.join(work, "config.json")
            json.dump(plan["config"], open(cfg_path, "w"))
            env = {"WXKEEP_DATA_DIR": data_dir}

            # 每个 binary 一份 fat 夹具（dylib / 主可执行 WeChat）
            binaries = {}
            for m in plan["slot_meta"].values():
                binaries.setdefault(m["binary"], {"arm64": {}, "x86_64": {}})
                binaries[m["binary"]][m["arch"]][plan["remap"][
                    [i for i, mm in plan["slot_meta"].items() if mm is m][0]]] = m["pristine_bytes"]
            bin_offsets = {}
            for rel, arch_sites in binaries.items():
                img, arm_off, x64_off = fat_image(arch_sites["arm64"], arch_sites["x86_64"])
                path = os.path.join(app, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "wb").write(img)
                bin_offsets[rel] = {"arm64": arm_off, "x86_64": x64_off}

            trials_run += 1
            idx_of = {id(m): idx for idx, m in plan["slot_meta"].items()}
            for cmd_i, cmd in enumerate(plan["seq"]):
                variant, _, only = cmd.partition(":only-")
                if cmd == "restore":
                    cli_args = ["restore", "--no-resign", "-a", app, "-c", cfg_path]
                else:
                    cli_args = ["patch", "--variant", variant, "--no-resign",
                                "-a", app, "-c", cfg_path]
                    if only:
                        cli_args += ["--only", only]
                rc, out = run_cli(cli, cli_args, env)

                prefix, entry_slot = simulate(version_entry, plan, plan["seq"][:cmd_i])
                should_fail = predict_failure(version_entry, plan, cmd, prefix, entry_slot)
                if should_fail:
                    if rc == 0:
                        diffs += 1
                        log.write(f"[{build}] trial{trial} cmd {cmd}: spec 预测失败但 CLI exit=0\n{out}\n")
                    continue
                if rc != 0:
                    diffs += 1
                    log.write(f"[{build}] trial{trial} cmd {cmd}: spec 预测成功但 CLI exit={rc}\n{out[-2000:]}\n")
                    continue

                cur, _ = simulate(version_entry, plan, plan["seq"][:cmd_i + 1])
                for idx, m in plan["slot_meta"].items():
                    va = plan["remap"][idx]
                    off = bin_offsets[m["binary"]][m["arch"]]
                    path = os.path.join(app, m["binary"])
                    actual = read_at(path, off + va, m["span"])
                    if not legal(m, actual):
                        diffs += 1
                        log.write(f"[{build}] trial{trial} cmd {cmd}: slot {m['arch']}@{m['va_orig']:x} "
                                  f"{m['binary']} 字节 {actual.hex().upper()} ∉ 合法集\n")
                    if any(a and "?" in a for (_, a, _) in m["entries"]):
                        masked_slots += 1
                        continue
                    pred = bytes(cur[idx])
                    if actual != pred:
                        diffs += 1
                        log.write(f"[{build}] trial{trial} cmd {cmd}: slot {m['arch']}@{m['va_orig']:x} "
                                  f"{m['binary']} actual {actual.hex().upper()} ≠ twin {pred.hex().upper()}\n")

    verdict = "L17 PASS" if diffs == 0 else "L17 FAIL"
    line = (f"{verdict} trials={trials_run} diffs={diffs} masked_slots={masked_slots} "
            f"seed={args.seed} ({time.time() - t0:.1f}s)")
    log.write(line + "\n"); log.close()
    print(line)
    print(f"台账: {log_path}")
    sys.exit(0 if diffs == 0 else 1)


if __name__ == "__main__":
    main()
