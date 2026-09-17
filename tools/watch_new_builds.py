#!/usr/bin/env python3
"""watch-wechat 流水线的「新构建收集器」。

输入：zsbai/wechat-versions 最近若干个 release 的 JSON（已由调用方下载到
/tmp/zsbai_releases.json）+ 本仓 config.json 的最大已知构建号。

输出（stdout）：每行 `<build> <dmg_asset_url>`（无 asset 则 URL 为空），
按 release 时间倒序去重，只保留高于 known 的构建。归档源不可达时输出为空
（干净跳过，不算失败）——构建号↔dmg 用 release asset 精确对应，修复旧流水线
「只看 latest release 漏掉同日多发子构建」与「官网首页直链只对应当前版」两处。

本地实测：python3 tools/watch_new_builds.py <(curl -sf \
  "https://api.github.com/repos/zsbai/wechat-versions/releases?per_page=15") config.json
"""
import json
import sys


def dest_version(body: str):
    """release body 里的 DestVersion（构建号）——取首个独立数字段。

    body 形如 "…DestVersion: 270099…"（历史格式有过冒号/引号变体，宽松匹配）。
    """
    if not body:
        return None
    for tok in body.replace(":", " ").replace('"', " ").split():
        if tok.isdigit() and len(tok) >= 5:   # 构建号至少 5 位（31927 起）
            return int(tok)
    return None


def main() -> int:
    releases_path, config_path = sys.argv[1], sys.argv[2]
    with open(config_path) as f:
        known = max(int(v["version"]) for v in json.load(f))
    try:
        with open(releases_path) as f:
            releases = json.load(f)
    except (OSError, ValueError):
        return 0   # 归档源不可达/非法 JSON → 调用方按「无新构建」干净跳过

    seen, out = set(), []
    for rel in releases:
        build = dest_version(rel.get("body") or "")
        if build is None or build <= known or build in seen:
            continue
        dmg = next(
            (a["browser_download_url"] for a in rel.get("assets", [])
             if a["name"].lower().endswith((".dmg", ".img"))),
            "",
        )
        seen.add(build)
        out.append(f"{build} {dmg}")
    if out:
        print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
