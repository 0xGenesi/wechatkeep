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
        # PKCS8 Ed25519 DER 恒为 48 字节：302e020100300506032b657004220420 <seed32>。
        # 旧版 der[-32:] 切片恒 32 字节、长度检查形同虚设——传错 PEM 类型
        # （如 RSA/EC）会静默抠出 32 字节垃圾签出无效签名（2026-09 审计修复）。
        PKCS8_ED25519_PREFIX = bytes.fromhex('302e020100300506032b657004220420')
        if not der.startswith(PKCS8_ED25519_PREFIX) or len(der) != 48:
            raise ValueError('not an Ed25519 PKCS8 key '
                             '(expect: openssl genpkey -algorithm ed25519)')
        return SigningKey(der[16:48]).sign(message).signature

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

    # 幂等门：受保护文件哈希与现有清单一致 = 数据未变，保留现有清单
    # （generated_at 每次重写都会让 CI 产生空转 bot 提交，迫使下次推送
    # rebase——2026-09-19 连续三轮实历）。仅 schema/files 变化才重写。
    mpath = os.path.join(root, 'manifest.json')
    try:
        cur = json.load(open(mpath))
        if isinstance(cur, dict) and cur.get('schema') == manifest['schema'] \
                and cur.get('files') == files:
            print('清单无变化（受保护文件哈希一致，保留现有 manifest）')
            for k, v in files.items():
                print(f'  {k}: {v[:16]}…')
            return
    except (OSError, ValueError):
        pass

    open(mpath, 'w').write(json.dumps(manifest, indent=2) + '\n')
    open(os.path.join(root, 'manifest.sig'), 'w').write(sig_b64 + '\n')
    print('已写 manifest.json + manifest.sig')
    print('受保护文件:')
    for k, v in files.items():
        print(f'  {k}: {v[:16]}…')

if __name__ == '__main__':
    main()
