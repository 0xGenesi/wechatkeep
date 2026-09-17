#!/usr/bin/env python3
"""
sign_manifest.py — 生成并签署发布清单（供应链防篡改，RecallKeeper 模式的开源版）。

清单：manifest.json = 受保护文件的 sha256 集合（config.json / signatures.json 等）
签名：manifest.sig = 对 manifest.json **规范字节串**的 Ed25519 签名（raw, base64）
密钥：openssl 生成的 Ed25519 PEM；公钥的 raw 32 字节 base64 存 keys/release.pub

用法:
  python3 tools/sign_manifest.py --key /path/to/priv.pem            # 签署仓库当前状态
  python3 tools/sign_manifest.py --key ... --dry-run                # 只打印

客户端校验：`wxkeep manifest`（CryptoKit Ed25519，公钥内嵌于二进制 + keys/release.pub）
"""
import argparse, base64, hashlib, json, subprocess, sys, tempfile, os, time

PROTECTED = [
    "config.json",
    "signatures.json",
]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', required=True, help='Ed25519 私钥 PEM 路径')
    ap.add_argument('--root', default='.', help='仓库根目录')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    files = {}
    for rel in PROTECTED:
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            sys.exit(f'缺少受保护文件: {rel}')
        files[rel] = sha256_file(p)

    manifest = {
        'schema': 1,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'files': files,
    }
    # 规范字节串：sorted keys、无缩进、紧凑分隔符——与 Swift 侧 canonicalData() 一致
    canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()

    def sign_pynacl(pem_path: str, message: bytes) -> bytes:
        """PKCS8 Ed25519 PEM → PyNaCl 签名（macOS 自带 LibreSSL 不支持 pkeyutl -rawin）。"""
        import base64, re
        from nacl.signing import SigningKey
        pem = open(pem_path).read()
        b64 = re.sub(r'-----[^-]+-----|\s', '', pem)
        der = base64.b64decode(b64)
        seed = der[-32:]   # PKCS8 Ed25519: ...04 22 04 20 <32-byte seed>
        if len(seed) != 32:
            raise ValueError('not an Ed25519 PKCS8 key')
        return SigningKey(seed).sign(message).signature

    try:
        sig = sign_pynacl(args.key, canonical)
    except ImportError:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(canonical)
            payload = tf.name
        try:
            sig = subprocess.run(
                ['openssl', 'pkeyutl', '-sign', '-inkey', args.key, '-rawin', '-in', payload],
                capture_output=True, check=True).stdout
        finally:
            os.unlink(payload)

    sig_b64 = base64.standard_b64encode(sig).decode()
    if args.dry_run:
        print(json.dumps(manifest, indent=2))
        print('sig:', sig_b64)
        return

    open(os.path.join(root, 'manifest.json'), 'w').write(json.dumps(manifest, indent=2) + '\n')
    open(os.path.join(root, 'manifest.sig'), 'w').write(sig_b64 + '\n')
    print('已写 manifest.json + manifest.sig')
    print('受保护文件:')
    for k, v in files.items():
        print(f'  {k}: {v[:16]}…')

if __name__ == '__main__':
    main()
