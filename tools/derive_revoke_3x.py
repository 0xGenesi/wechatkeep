#!/usr/bin/env python3
"""
derive_revoke_3x.py — 3.x（主程序/ObjC 时代）revoke 双变体条目派生器。

2026-10-30 收侧执行体裁决（83 轮）定案的补丁模型：
  - revoke（silent）= 撤回 sysmsg 入口方法裸 ret——整条撤回处理链（删原
    消息行 DeleteMsgListInDB + 清下载/上传/媒体任务 + notifyDelMsg 灰条
    广播 + FTS 删除广播 + 灰条 tip 行落库）全部不执行。WeChatTweak
    ≤1.3.5 吞此入口两年实证；83 轮反汇编复核（DelRevokedMsg 全貌在案）。
  - revoke-keeptip = 执行体 DelRevokedMsg:msgData: 裸 ret——DB 删除/
    清理/notifyDelMsg 被吞，调用方（入口）继续插灰条 tip 行并广播
    → 原消息+「xx撤回了一条消息」提示并存。

入口选择子四代改名谱系（分发器 xref + __FUNCTION__ 字面量双重裁决）：
  23440-25668 (3.5.5-3.7.1)  FFToNameFavChatZZ:sessionMsgList:
  26239      (3.8.0)         processNewXMLMsg:sessionMsgList:
  26638/27289(3.8.1/3.8.2)   onRevokeRoomHistory:   ← 撤回+房间历史撤回源码合并体
  27725-28564(3.8.4-3.8.9)   onSecMsg:syncMsgList:
执行体 DelRevokedMsg:msgData: 15/15 构建双架构全程稳定（3.2.2-3.8.9
wechaty tracker 外部 dump 互证）。两方法 types 均 v32@0:8@16@24（void
返回，裸 ret ABI 安全；x64=C3 / arm64=C0035FD6=ret）。

交叉验证门（防选择子撞名/错代际；2026-10-30 全 30 格信号可用性实测）：
  - ownlit 硬门（双架构 30/30 全绿）：入口跨度内必须引用自身源码名
    __FUNCTION__ 字面量 "-[MessageService <入口名>]"（imp↔名字绑定自证。
    arm64 3.6.2+ 撤回调用走 __objc_stubs，无 selector ref 标注——字面量
    是唯一全格稳定锚）
  - x64 selref 附加（15/15）：入口体内引用 DelRevokedMsg:msgData: 选择子
  - 执行体 x64 侧：体内引用 DeleteMsgListInDB* 选择子（DB 删除语义铁证）

产物：
  var/wxarm/<b>_main_<arch>.<b>.revoke.<arch>.json        （入口，silent）
  var/wxarm/<b>_main_<arch>.<b>.revoke-keeptip.<arch>.json（执行体，keeptip）
  var/staging/<b>.json                                     （整建形态）

用法: python3 tools/derive_revoke_3x.py [--build 28564 ...] [--dry-run]
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import locate_revoke_objc as L  # noqa: E402
import machutil  # noqa: E402

HOST_CLASS = "FFProcessReqsvrZZ"
EXECUTOR_SEL = "DelRevokedMsg:msgData:"
# 3.x 版本谱系（ROADMAP 79 轮深夜追加）；3.8.3 无 tag=线内天然缺口
BUILDS = {
    23440: ("3.5.5", "FFToNameFavChatZZ:sessionMsgList:"),
    24160: ("3.6.0", "FFToNameFavChatZZ:sessionMsgList:"),
    24205: ("3.6.1", "FFToNameFavChatZZ:sessionMsgList:"),
    24456: ("3.6.2", "FFToNameFavChatZZ:sessionMsgList:"),
    25067: ("3.7.0", "FFToNameFavChatZZ:sessionMsgList:"),
    25668: ("3.7.1", "FFToNameFavChatZZ:sessionMsgList:"),
    26239: ("3.8.0", "processNewXMLMsg:sessionMsgList:"),
    26638: ("3.8.1", "onRevokeRoomHistory:"),
    27289: ("3.8.2", "onRevokeRoomHistory:"),
    27725: ("3.8.4", "onSecMsg:syncMsgList:"),
    27885: ("3.8.5", "onSecMsg:syncMsgList:"),
    28076: ("3.8.6", "onSecMsg:syncMsgList:"),
    28245: ("3.8.7", "onSecMsg:syncMsgList:"),
    28486: ("3.8.8.18", "onSecMsg:syncMsgList:"),
    28564: ("3.8.9.17", "onSecMsg:syncMsgList:"),
    28632: ("3.8.10.17", "onSecMsg:syncMsgList:"),  # Rodert 归档补拉（83 轮）
}
MAIN_BINARY = "Contents/MacOS/WeChat"


def disasm_lines(path):
    r = subprocess.run(["otool", "-tV", path], capture_output=True, text=True)
    return r.stdout.splitlines()


def span_refs(dis, lo, hi, needle):
    """[lo,hi) 指令地址内是否出现含 needle 的标注行。"""
    for line in dis:
        m = re.match(r"^([0-9a-f]{16})\t", line)
        if m and lo <= int(m.group(1), 16) < hi and needle in line:
            return True
    return False


def sole_impl(methods, selector, build):
    impls = [m for m in methods
             if m["sel"] == selector and m["class"] == HOST_CLASS and m["imp"]]
    if len(impls) != 1:
        raise SystemExit(
            f"[{build}] {selector}: 期望 {HOST_CLASS} 唯一实现，实得 {len(impls)}")
    if not impls[0]["types"].startswith("v"):
        raise SystemExit(
            f"[{build}] {selector}: types={impls[0]['types']} 非 void 返回"
            "（裸 ret 不安全）")
    return impls[0]


def next_imp(methods, imp):
    imps = sorted(m["imp"] for m in methods if m["imp"])
    for v in imps:
        if v > imp:
            return v
    raise SystemExit(f"imp 0x{imp:x} 后无更大 imp（元数据异常）")


def make_entry(arch, imp, prologue, source):
    ret = "C3" if arch == "x86_64" else "C0035FD6"
    return {
        "arch": arch,
        "addr": format(imp, "x"),
        "expected": [prologue[:16]],
        "asm": ret,
        "source": source,
    }


def derive_build(build, ver, entry_sel, dry):
    staging = {"build": str(build), "targets": [
        {"identifier": "revoke", "binary": MAIN_BINARY, "entries": []},
        {"identifier": "revoke-keeptip", "binary": MAIN_BINARY, "entries": []},
    ]}
    for arch_key, arch_cfg in (("x64", "x86_64"), ("arm64", "arm64")):
        path = os.path.join(ROOT, "var", "wxarm", f"{build}_main_{arch_key}")
        if not os.path.exists(path):
            raise SystemExit(f"[{build}] 切片缺失: {path}")
        methods = L.parse_objc(path)
        entry = sole_impl(methods, entry_sel, build)
        execu = sole_impl(methods, EXECUTOR_SEL, build)
        arch, thin = L.thin_slice(path)
        if arch != arch_cfg:
            raise SystemExit(f"[{build}] 切片架构反常: {arch}")

        dis = disasm_lines(path)
        # ownlit 硬门：入口体内引用自身源码名 __FUNCTION__ 字面量
        e_nxt = next_imp(methods, entry["imp"])
        own = f'"-[MessageService {entry_sel}]"'
        if not span_refs(dis, entry["imp"], e_nxt, "literal pool for: " + own):
            raise SystemExit(
                f"[{build}/{arch_key}] 入口 {entry_sel} 体内无自身 "
                f"__FUNCTION__ 字面量（ownlit 失败）——选择子代际错误")
        # selref 附加：x64 体内引用执行体选择子（arm64 3.6.2+ 走
        # __objc_stubs 无标注，跳过）
        selref = span_refs(dis, entry["imp"], e_nxt,
                           f"Objc selector ref: {EXECUTOR_SEL}")
        if arch_key == "x64" and not selref:
            raise SystemExit(
                f"[{build}] x64 入口 {entry_sel} 体内无 {EXECUTOR_SEL} "
                "选择子引用——结构漂移")
        # 执行体语义门：x64 体内引用 DeleteMsgListInDB*
        x_nxt = next_imp(methods, execu["imp"])
        dbref = span_refs(dis, execu["imp"], x_nxt, "DeleteMsgListInDB")
        if arch_key == "x64" and not dbref:
            raise SystemExit(
                f"[{build}] x64 执行体 {EXECUTOR_SEL} 体内无 "
                "DeleteMsgListInDB 引用——非 DB 删除执行体")

        for spec, m in (("revoke", entry), ("revoke-keeptip", execu)):
            off = machutil.va2off(thin, m["imp"])
            pro = thin[off:off + 16].hex().upper()
            e = make_entry(arch_cfg, m["imp"], pro,
                           f"wxkeep:objc3x:{HOST_CLASS}::{m['sel']}@{build}"
                           f"（{ver}）")
            staging["targets"][0 if spec == "revoke" else 1]["entries"].append(e)
            if not dry:
                out = os.path.join(
                    ROOT, "var", "wxarm",
                    f"{build}_main_{arch_key}.{build}.{spec}.{arch_key}.json")
                json.dump([e], open(out, "w"), ensure_ascii=False, indent=1)
        marks = "✓ownlit" + ("+selref" if selref else "")
        print(f"[{build}/{arch_key}] {ver} 入口={entry_sel}"
              f"@0x{entry['imp']:x} 执行体@0x{execu['imp']:x} {marks}")
    if not dry:
        out = os.path.join(ROOT, "var", "staging", f"{build}.json")
        json.dump(staging, open(out, "w"), ensure_ascii=False, indent=1)
    return staging


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="append", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    targets = args.build or sorted(BUILDS)
    for b in targets:
        if b not in BUILDS:
            raise SystemExit(f"未知构建 {b}（不在 3.x 谱系表）")
        ver, sel = BUILDS[b]
        derive_build(b, ver, sel, args.dry_run)
    print(f"完成 {len(targets)} 构建 × 双变体"
          f"{'（dry-run）' if args.dry_run else ''}")


if __name__ == "__main__":
    main()
