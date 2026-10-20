#!/bin/bash
# run_fuzz.sh — L3②/L3⑤ 一键执行：
#   1) ASan+UBSan 重编 runtime.m + 确定性驱动（内置语料 + corpus 目录）
#   2) libFuzzer（ASan+UBSan）对同一批测试缝跑 -runs（默认 200000 ≥ 1e5）
#   3) Swift 侧解析面（ExpectedPattern / MachOInjector）随机畸形注入
# 用法: bash tools/fuzz/run_fuzz.sh [fuzz-runs]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUNS="${1:-200000}"
OUT="$ROOT/var/logs/fuzz-$(date +%Y%m%d)"
mkdir -p "$OUT"
cd "$ROOT"

INC="Sources/WxkeepRuntime/include"
SRC="Sources/WxkeepRuntime/runtime.m"

echo "== [1/3] ASan+UBSan 确定性驱动 =="
clang -x objective-c -fobjc-arc -g -O1 \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  "$SRC" tools/fuzz/runtime_driver.c -I "$INC" \
  -framework Foundation -framework AppKit \
  -o "$OUT/runtime_driver"
"$OUT/runtime_driver" tools/fuzz/corpus 2>&1 | tee "$OUT/driver.log"

echo "== [2/3] 随机模糊 x${RUNS}（ASan+UBSan；CLT 无 libFuzzer 运行时的等价实现）=="
clang -x objective-c -fobjc-arc -g -O1 \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  "$SRC" tools/fuzz/runtime_random.c -I "$INC" \
  -framework Foundation -framework AppKit \
  -o "$OUT/runtime_random"
"$OUT/runtime_random" tools/fuzz/corpus "$RUNS" 2>&1 | tee "$OUT/fuzz.log"

echo "== [3/3] Swift 解析面随机畸形注入 =="
# 本机 macOS 27 CLT 的 TestingMacros 插件会话楔死间歇发作（org.swift.*
# 临时目录/swiftpm 缓存积累）——判据命中即清理重试，与 verify_staging 的
# 构建抖动重试同族但根因不同（这里是插件服务器失效不是宏发现竞态）。
for attempt in 1 2 3 4 5 6; do
  TM=/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib
  out=$(swift test --disable-sandbox -Xswiftc -load-plugin-library -Xswiftc "$TM" \
        --filter FuzzParseSurfaces 2>&1)
  if echo "$out" | grep -q "plugin for module 'TestingMacros' not found\|nProcPluginServer"; then
    echo "（插件会话楔死，清理重试 $attempt/6）"
    find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'org.swift*' -exec rm -rf {} + 2>/dev/null
    rm -rf ~/Library/Caches/org.swift.swiftpm 2>/dev/null
    sleep 4
    continue
  fi
  break
done
echo "$out" | tee "$OUT/swift-fuzz.log" | grep -aE "Test run with|✔ Test|✘ Test" | head -4

echo "全部完成：$OUT"
