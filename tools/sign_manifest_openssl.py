#!/usr/bin/env python3
"""sign_manifest_openssl.py — OpenSSL 3.x/4.x Ed25519 路线的 manifest 签署。

来源：76 轮实验 staging（var/ab/sign_manifest_openssl.py 正化入库，原工件
保留 var/ab/）。定位 = tools/sign_manifest.py 的无 PyNaCl 环境替代
（本机 var/venv 无 pynacl，openssl 4.0.3 可用）：产出字节兼容——同
schema/规范字节串/签名格式，二者可互换使用。76 轮 var/ab/t{1,2,3}/ 双架构
staging 四件套即本工具产出。

语义（与 tools/sign_manifest.py 一致）：
  manifest.json = 受保护文件（config.json/signatures.json）的 sha256 集合
  manifest.sig = 对 manifest.json **规范字节串**（sort_keys+紧凑分隔符）
                 的 Ed25519 签名（raw, base64 单行）
  密钥 = PKCS8 Ed25519 PEM（openssl 生成的标准形，SEED 提取走固定 DER 前缀）

用法:
  python3 tools/sign_manifest_openssl.py --key keys/priv.pem            # 签署仓库根
  python3 tools/sign_manifest_openssl.py --key ... --root var/ab/t1     # 签署 staging 目录
客户端校验：`wxkeep manifest` / tools/verify_manifest_openssl.sh（三方互证）。
"""
import argparse, base64, hashlib, json, os, re, subprocess, sys, time

PROTECTED = ["config.json", "signatures.json"]
PKCS8_PREFIX = bytes.fromhex('302e020100300506032b657004220420')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def pem_seed(pem_path):
    pem = open(pem_path).read()
    b64 = re.sub('-----[^-]+-----|\\s', '', pem)
    der = base64.b64decode(b64)
    assert der[:len(PKCS8_PREFIX)] == PKCS8_PREFIX, 'not PKCS8 Ed25519'
    return der[len(PKCS8_PREFIX):]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key', required=True, help='Ed25519 私钥 PEM 路径（PKCS8）')
    ap.add_argument('--root', default='.', help='待签署目录（含受保护文件）')
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    files = {rel: sha256_file(os.path.join(root, rel)) for rel in PROTECTED}
    manifest = {'schema': 1, 'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'files': files}
    canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    # 钥型校验（错钥早失败，防静默垃圾签名）——openssl 3/4 的 pkeyutl 支持
    # -rawin Ed25519，直接用原钥签名；不重建临时 PEM（源文件也不得出现
    # PEM 头字面量——CI 的私钥材料防泄漏门会拦，2026-10-26 实历）。
    pem_seed(args.key)
    p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', args.key,
                        '-rawin', '-in', '/dev/stdin'],
                       input=canonical, capture_output=True, check=True)
    sig = base64.b64encode(p.stdout).decode()
    with open(os.path.join(root, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=1)
        f.write('\n')
    with open(os.path.join(root, 'manifest.sig'), 'w') as f:
        f.write(sig + '\n')
    print(f'manifest.json + manifest.sig written to {root}')
    print(f'  config.json    {files["config.json"][:16]}…')
    print(f'  signatures.json {files["signatures.json"][:16]}…')


if __name__ == '__main__':
    main()
