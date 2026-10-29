#!/usr/bin/env python3
"""xml_row_forensics.py — XML 灰条行 ↔ 原消息行 svrid 关联取证（不打印内容）。

问题：type=10000 的 sysmsg 原文行，其 <newmsgid> 指向的原消息行是否在表内？
输出：local_id / target(newmsgid) / original_present / orig_type / orig_status。
判别逻辑：
  v1 期间原消息在场 → sysmsg 行是消费端被 silence 后的残留（非改写原行）
  无补丁日原消息不在场 → 原生 miss 路径落库
"""
import json
import re
import subprocess
import sys

BASE = ("~/Library/Containers/com.tencent.xinWeChat/Data/Documents/"
        "xwechat_files/huanlinchen_dfea/db_storage/message")
SQLC = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
KEYS = json.load(open("var/dbkeys/keys.json"))["dbs"]
CHAT = sys.argv[1] if len(sys.argv) > 1 else "45845756908@chatroom"
import hashlib
TBL = "Msg_" + hashlib.md5(CHAT.encode()).hexdigest()

PRAGMAS = """PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 256000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"""


def query(db, key, sql):
    p = subprocess.run([SQLC, "-readonly", "-noheader", db],
                       input=f"PRAGMA key = \"x'{key}'\";\n{PRAGMAS}\n{sql}\n",
                       capture_output=True, text=True)
    return [l for l in p.stdout.splitlines() if l and l != "ok"]


def decompress(raw: bytes) -> bytes:
    import subprocess, tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zst") as f:
        f.write(raw)
        p = f.name
    try:
        r = subprocess.run(["/opt/homebrew/bin/zstd", "-dc", p],
                           capture_output=True)
        return r.stdout
    finally:
        os.unlink(p)


def main():
    # 表在哪个库
    for n in range(8):
        k = KEYS.get(f"message_{n}.db")
        if not k:
            continue
        import os
        path = os.path.expanduser(f"{BASE}/message_{n}.db")
        if not os.path.exists(path):
            continue
        rows = query(path, k, f"SELECT count(*) FROM sqlite_master WHERE name='{TBL}';")
        if rows and rows[0] != "0":
            break
    else:
        print("table not found")
        return
    print(f"# {CHAT} -> {TBL} in message_{n}.db")

    # 全部 10000 行：local_id, svrid, create_time, hex(content)
    rows = query(path, k, (
        f"SELECT local_id, server_id, create_time, hex(message_content) "
        f"FROM {TBL} WHERE local_type=10000 AND WCDB_CT_message_content=4 "
        f"ORDER BY create_time;"))
    xml_rows = []
    for r in rows:
        parts = r.split("|")
        if len(parts) != 4:
            continue
        lid, svrid, ts, hx = parts
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            continue
        body = decompress(raw) if raw[:4] == b"\x28\xb5\x2f\xfd" else raw
        m = re.search(rb"<newmsgid>(\d+)</newmsgid>", body)
        if not m:
            continue
        xml_rows.append((int(lid), int(svrid), int(ts), int(m.group(1))))

    # 原消息在场性
    allsvr = {}
    for r in query(path, k, (
            f"SELECT server_id, local_type, status FROM {TBL};")):
        p = r.split("|")
        if len(p) == 3 and p[0] not in ("", "ok"):
            try:
                allsvr[int(p[0])] = (p[1], p[2])
            except ValueError:
                pass

    hit = miss = 0
    for lid, svrid, ts, target in xml_rows:
        orig = allsvr.get(target)
        import datetime
        d = datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S")
        if orig:
            hit += 1
            print(f"{d} lid={lid} target={target} PRESENT(type={orig[0]},status={orig[1]})")
        else:
            miss += 1
            print(f"{d} lid={lid} target={target} absent")
    print(f"# 总计: 原消息在场={hit} 不在={miss}")


if __name__ == "__main__":
    main()
