#!/usr/bin/env python3
"""watch-wechat 流水线的「新构建收集器」。

输入：zsbai/wechat-versions 最近若干个 release 的 JSON（已由调用方下载到
/tmp/zsbai_releases.json）+ 本仓 config.json 的最大已知构建号。

输出（stdout，按 release 时间倒序）：
- `<build> <dmg_asset_url> <tag>`：DestVersion 为数字且高于 known 的构建。
- `? <dmg_asset_url> <tag>`：DestVersion 为点分格式（4.x 时代）拿不到构建号
  的 release——由流水线下载 dmg、挂载读 Info.plist 的 CFBundleVersion 判新
  （解析结果 ≤ known 即停：release 倒序，其后只会更旧；稳态每天恰好一次
  下载）。归档源不可达时输出为空（干净跳过，不算失败）——构建号↔dmg 用
  release asset 精确对应，修复旧流水线「只看 latest release 漏掉同日多发
  子构建」与「官网首页直链只对应当前版」两处。

本地实测：python3 tools/watch_new_builds.py <(curl -sf \
  "https://api.github.com/repos/zsbai/wechat-versions/releases?per_page=15") config.json
"""
import json
import sys


def dest_version(body: str):
    """release body 里的 DestVersion（构建号）——行锚定取「DestVersion:」
    字段的纯数字值。

    body 形如 "…DestVersion: 270099…"（历史格式有过冒号/引号变体，宽松匹配）。
    注意必须行/字段锚定：现行 body 还带 ContentLength 等大数字字段，
    按任意 token 抓 5+ 位数字会把 ContentLength 误当构建号（4.x 时代
    DestVersion 是点分版本号，抓不到构建号时返回 None，交由调用方处理）。
    """
    if not body:
        return None
    for line in body.splitlines():
        if "DestVersion" not in line:
            continue
        value = line.split(":", 1)[1] if ":" in line else ""
        for tok in value.replace('"', " ").split():
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
        dmg = next(
            (a["browser_download_url"] for a in rel.get("assets", [])
             if a["name"].lower().endswith((".dmg", ".img"))),
            "",
        )
        tag = rel.get("tag_name", "")
        if build is None:
            # 4.x 时代 DestVersion 为点分格式（如 4.1.15.19）——构建号只有
            # dmg 内的 Info.plist 知道。有 asset 才值得让流水线挂载解析；
            # 无 asset 的点分 release 无法判新，跳过（与数字路径同保守）。
            if dmg:
                out.append(f"? {dmg} {tag}")
            continue
        if build <= known or build in seen:
            continue
        seen.add(build)
        # 第三字段 = release tag（营销版本号）——供流水线在 asset 失败时
        # 构造官方 CDN 构建归档直链（xWeChatMac_universal_<tag>_<build>.dmg）
        out.append(f"{build} {dmg} {tag}")
    if out:
        print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
