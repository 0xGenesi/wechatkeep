#!/usr/bin/env python3
"""R6 收口扫描：全部 str xN,[xM,#0xb78] 写入者函数清单 + 工厂区调用图求交。

- 全 __TEXT 扫 str xN,[xM,#0xb78]（imm12*8=0xb78 → imm 编码 0x56f：
  STR (imm, unsigned offset) 64-bit: size=11 V=00 opc=00 imm12 Rn Rt，
  word = 0xF9000000 | (0x56f << 10) | (Rn << 5) | Rt）。
- 输出每个站点所在函数；与工厂链（0x4540e80 区/0x4541be0/0x45416cc/
  0x4542950/0x4542474/0x666ab58/0x454182c/0x4540bd8/0x268f370）的
  idx calls 图对照，找出被工厂链调用的写入者。
"""
import os
import sys, bisect, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm64_index as ai
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")  # 仓库根（脚本入 tools/，工件在 var/ab——本地未分发）

SLICE = os.path.join(ROOT, "var/ab/270135_arm64.dylib")
ix, func_of = ai.load(os.path.join(ROOT, "var/ab/270135_arm64.idx"))
funcs = ix["funcs"]
data = open(SLICE, "rb").read()

# __TEXT: fileoff 0..0x9b34000 (段表见 r6_ctor_hunt 输出)
TEXT_END = 0x9B34000

writers = {}   # func -> [(va, rn, rt)]
for off in range(0, TEXT_END - 3, 4):
    w = struct.unpack_from("<I", data, off)[0]
    if (w & 0xFFC00000) == 0xF9000000 and ((w >> 10) & 0xFFF) == 0x56F:
        f = func_of(off)
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        writers.setdefault(f, []).append((off, rn, rt))

print(f"+0xb78 STR 写入者：{len(writers)} 函数，{sum(len(v) for v in writers.values())} 站点")
for f in sorted(writers):
    sites = writers[f]
    print(f"  0x{f:x}: {len(sites)} 站 " +
          " ".join(f"[x{rt}→x{rn}]" for _, rn, rt in sites[:6]))

# 工厂链函数清单：其 BL 出边（idx calls）与写入者求交
FACTORY = [0x268f370, 0x4540bd8, 0x4540e80, 0x4541be0, 0x45416cc, 0x4542950,
           0x4542474, 0x666ab58, 0x454182c, 0x4541d70, 0x45a4948]
print("\n工厂链 BL 出边 → 写入者交集：")
writer_set = set(writers)
for ff in FACTORY:
    outs = sorted(set(t for site, (t, cf) in
                      [(s, e) for s, e in []]))
# idx['calls'] 结构：{target: [(site, caller_func), ...]}
# 需要反向：遍历 calls 找 caller∈FACTORY
hits = []
for tgt, entries in ix["calls"].items():
    for site, caller in entries:
        if caller in FACTORY and tgt in writer_set:
            hits.append((caller, site, tgt))
for caller, site, tgt in sorted(set(hits)):
    print(f"  caller 0x{caller:x} @0x{site:x} → 0x{tgt:x}（+0xb78 写入者！）")
if not hits:
    print("  （无直接交集——构造在更深层：vtable 虚调用/模板内联）")
