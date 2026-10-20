#!/bin/bash
# verify_manifest_openssl.sh — 旁路项①（ROADMAP 72）：用 openssl 独立验证
# manifest 的 Ed25519 签名与受保护文件哈希——完全不经过 CryptoKit，防
# 「Swift 侧自证」（同一实现的可能共因缺陷测不出来）。
#
# 独立性说明：canonical 字节串重算与 sha256 用 python 标准库（OpenSSL 家
# 族实现），签名验证用 openssl pkeyutl（手构 SPKI DER，不从仓库工具导入
# 任何密码学代码）。与 sign_manifest.py 的 PyNaCl / Swift CryptoKit 三方
# 互异。
#
# 用法: bash tools/verify_manifest_openssl.sh [目录=仓库根]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${1:-$(cd "$HERE/.." && pwd)}"
OPENSSL="${OPENSSL:-openssl}"   # 默认 PATH 里的（本机 OpenSSL 4.x；可覆写

cd "$ROOT"
python3 - "$ROOT" > /tmp/wxkeep-canonical.bin.$$ <<'EOF'
import base64, json, sys, os
root = sys.argv[1]
m = json.load(open(os.path.join(root, "manifest.json")))
# 与 Manifest.canonicalData / sign_manifest.py 同算法：sort_keys + 紧凑分隔
canonical = json.dumps(m, sort_keys=True, separators=(",", ":")).encode()
sys.stdout.buffer.write(canonical)
EOF

# SPKI（SubjectPublicKeyInfo）Ed25519 DER：302a300506032b6570032100 + pub32
python3 - "$ROOT" > /tmp/wxkeep-pub.der.$$ <<'EOF'
import base64, sys
raw = base64.b64decode(open(sys.argv[1] + "/keys/release.pub").read().strip())
assert len(raw) == 32, f"release.pub 非 raw32: {len(raw)}"
sys.stdout.buffer.write(bytes.fromhex("302a300506032b6570032100") + raw)
EOF
tr -d '\n' < "$ROOT/manifest.sig" | base64 -d > /tmp/wxkeep-sig.raw.$$

if "$OPENSSL" pkeyutl -verify -pubin -inkey /tmp/wxkeep-pub.der.$$ \
     -sigfile /tmp/wxkeep-sig.raw.$$ -rawin -in /tmp/wxkeep-canonical.bin.$$ 2>&1 | grep -q "Signature Verified Successfully"; then
  echo "✓ Ed25519 签名验证通过（openssl $(${OPENSSL} version 2>/dev/null || echo '?')，独立于 CryptoKit）"
else
  echo "✗ 签名验证失败"; exit 1
fi

# 受保护文件哈希独立复算（sha256 命令，非 python/非 CryptoKit）
python3 - "$ROOT" <<'EOF'
import hashlib, json, os, subprocess, sys
root = sys.argv[1]
m = json.load(open(os.path.join(root, "manifest.json")))
ok = True
for rel, want in sorted(m["files"].items()):
    got = subprocess.run(["shasum", "-a", "256", os.path.join(root, rel)],
                         capture_output=True, text=True).stdout.split()[0]
    mark = "✓" if got == want else "✗"
    if got != want: ok = False
    print(f"  {mark} {rel}: {got}")
sys.exit(0 if ok else 1)
EOF
rm -f /tmp/wxkeep-canonical.bin.$$ /tmp/wxkeep-pub.der.$$ /tmp/wxkeep-sig.raw.$$
echo "✓ 独立验签完成：manifest 与受保护文件全部吻合"
