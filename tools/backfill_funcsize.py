#!/usr/bin/env python3
"""
backfill_funcsize.py — 对已知 hook 行回填 func_size（函数级身份门，77 续⑤同口径）。

输入：pristine thin dylib + 行字段（build/uuid/arch/hook_off/expected）。
三重校验（77 续⑤「本地 pristine 切片三重校验」同款）：
  ① hook_off 必为 LC_FUNCTION_STARTS 起点（非起点 = 行错/切片错，拒绝）；
  ② 切片 LC_UUID 与行 uuid 全同；
  ③ hook_off 处实际字节 == 行 expected（序言门复核）。
输出：func_size = hook_off 到 FUNCTION_STARTS 下一非零增量条目的距离
     （与 tools/machutil.py / runtime.m func_size_matches / derive_runtime_hooks
      同一语义：布局距离不是函数字节数）。

用法: python3 tools/backfill_funcsize.py <thin.dylib> <build> <uuid> <arch> <hook_off_hex> <expected_hex>
"""
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import machutil


def func_size_at(d, hook_off):
    starts = machutil.function_starts(d)
    # starts: 已解析的绝对 VA 列表（machutil 语义 = __TEXT.vmaddr 基 + ULEB128 增量）
    if hook_off not in starts:
        return None
    later = sorted(s for s in starts if s > hook_off)
    if not later:
        return None
    return later[0] - hook_off


def main():
    path, build, uuid, arch, off_s, exp_s = sys.argv[1:7]
    cputype = machutil.CPU_ARM64 if arch == "arm64" else machutil.CPU_X86_64
    d = machutil.load_slice(path, cputype)
    hook_off = int(off_s, 16)
    exp = bytes.fromhex(exp_s)

    # ② UUID 门
    slice_uuid = None
    for cmd, p in machutil._load_commands(d):
        if cmd == 0x1B:  # LC_UUID
            import struct
            b = d[p + 8:p + 24]
            import uuid as _u
            slice_uuid = str(_u.UUID(bytes=b))
    if slice_uuid != uuid:
        print(f"FAIL uuid: slice={slice_uuid} row={uuid}")
        sys.exit(1)

    # ③ 序言门
    off = machutil.va2off(d, hook_off)
    got = d[off:off + len(exp)]
    if got != exp:
        print(f"FAIL prologue @ {off_s}: got={got.hex().upper()} want={exp_s}")
        sys.exit(1)

    # ① FUNCTION_STARTS 起点 + 距离
    fs = func_size_at(d, hook_off)
    if fs is None:
        print(f"FAIL: {off_s} 非 FUNCTION_STARTS 起点（或无下一函数）")
        sys.exit(1)
    print(f"{build} {arch} hook_off={off_s} func_size={fs} (0x{fs:x})")


if __name__ == "__main__":
    main()
