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

--cdn-probe（2026-10-19，270131/270132 漏报教训）：zsbai 之外的官方 CDN
线性探测。点分版本无法从构建号反推，但线内映射线性（4.1.15.N ↔ 270080+N、
4.1.13.N ↔ 269568+N），由此构造 `…_universal_<点分>_<构建>.dmg` 归档直链
做 range GET 探测（404=不存在、206=在档，2026-10-17 实证口径）。锚定两路：
① 老 body 带**数字** DestVersion → (tag, 构建) 对多点一致即基；② 现行 body
DestVersion 已是**点分**（2026-10-19 实测，数字锚点恒缺）→ 取最高 tag 定线
与线内 N 集，对最新 tag 在 CDN 上做 X-搜索定其真实构建号（稳态 = known，
首个候选即命中；zsbai 领先/滞后于 known 各留窗口），base = X - maxN。候选
= known+1 … X+8，dotted 按线性映射反推，**线内已有 tag 的 N 排除**（那些
release 由 `?` 点分行处理，防双重下载 500MB dmg），zsbai 已列构建号按 seen
去重。锚点不可得/X 不可定/CDN 连续不可达 → 探测安静跳过（zsbai 主路径不受
影响）。新营销线（如 4.1.16）上线后最高 tag 换线即自动跟随。

本地实测：python3 tools/watch_new_builds.py <(curl -sf \
  "https://api.github.com/repos/zsbai/wechat-versions/releases?per_page=15") config.json
"""
import json
import sys
import urllib.error
import urllib.request

CDN_URL_FMT = ("https://dldir1v6.qq.com/weixin/Universal/Mac/"
               "xWeChatMac_universal_{dotted}_{build}.dmg")
PROBE_AHEAD = 8        # 超过线内最高点再向前探的构建数（day-0 早发现）
PROBE_CAP = 96         # 单轮探测请求封顶（X-搜索 ≤49 + 候选扫描）


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


def infer_line(releases):
    """锚定路径①：老格式 body 带数字 DestVersion → (tag, 构建) 锚点对。
    返回 (family, base, line_max) 使 build = base + N；锚点缺失或 base
    不一致（非线性）返回 None。"""
    pairs = []
    for rel in releases:
        tag = (rel.get("tag_name") or "").strip().lstrip("vV")
        build = dest_version(rel.get("body") or "")
        parts = tag.split(".")
        if build and len(parts) >= 3 and all(p.isdigit() for p in parts):
            pairs.append((".".join(parts[:-1]), int(parts[-1]), build))
    if not pairs:
        return None
    top = max(b for _, _, b in pairs)
    fam = next(f for f, _, b in pairs if b == top)
    bases = {b - n for f, n, b in pairs if f == fam}
    if len(bases) != 1:
        return None
    return fam, bases.pop(), max(b for f, _, b in pairs if f == fam)


def tag_line(releases):
    """锚定路径②的数据源：最高版本 tag 定线。返回 (family, 线内 N 集, maxN)
    ——现行 zsbai body 的 DestVersion 是点分格式，构建号只有 dmg 知道，
    但 tag 本身给出线名与线内已归档的 N 集。"""
    tags = []
    for rel in releases:
        parts = (rel.get("tag_name") or "").strip().lstrip("vV").split(".")
        if len(parts) >= 3 and all(p.isdigit() for p in parts):
            tags.append(tuple(int(p) for p in parts))
    if not tags:
        return None
    top = max(tags)
    fam = top[:-1]
    ns = {t[-1] for t in tags if t[:-1] == fam}
    return (".".join(str(p) for p in fam), ns, top[-1])


def cdn_exists(url, timeout=10):
    """range GET bytes=0-0：206/200 = 在档（0 字节也当在档——存在性即目的），
    404 = 不存在，连接层异常返回 None（与「不存在」区分，供早停判定）。"""
    req = urllib.request.Request(url, headers={
        "Range": "bytes=0-0", "User-Agent": "wxkeep-watch"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status in (200, 206)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


class Prober:
    """探测预算 + 连续连接层异常早停（CDN 不可达时 zsbai 主路径不担责）。"""

    def __init__(self):
        self.budget = PROBE_CAP
        self.netfail = 0

    def exists(self, url):
        if self.budget <= 0:
            return None
        self.budget -= 1
        r = cdn_exists(url)
        if r is None:
            self.netfail += 1
        else:
            self.netfail = 0
        return r

    @property
    def dead(self):
        return self.budget <= 0 or self.netfail >= 3


def find_newest_build(prober, fam, maxN, known):
    """X-搜索：最新 tag 的真实构建号。稳态（zsbai 最新 = known）首个候选
    即命中；zsbai 领先（新 release 未入库，66 轮实测 33 个）在 known+1..+64；
    CDN-probe 先行入库后的滞后态在 known-1..-16。找不到 → None（诚实跳过）。
    """
    order = [known] + list(range(known + 1, known + 65)) \
        + list(range(known - 1, known - 17, -1))
    for b in order:
        if prober.dead:
            return None
        if prober.exists(CDN_URL_FMT.format(dotted=f"{fam}.{maxN}", build=b)):
            return b
    return None


def cdn_probe(known, releases, seen):
    """CDN 线性探测主入口：返回 [(build, cdn_url, dotted_tag)]。
    路径①数字锚点优先（精确线信息）；否则路径②tag 定线 + X-搜索。"""
    prober = Prober()

    line = infer_line(releases)     # 路径①：老格式数字锚点
    if line is not None:
        fam, base, line_max = line
        hi = max(known + PROBE_AHEAD, line_max)
        found = []
        for build in range(known + 1, hi + 1):
            if prober.dead or build in seen:
                continue
            dotted = f"{fam}.{build - base}"
            if prober.exists(CDN_URL_FMT.format(dotted=dotted, build=build)):
                found.append((build, CDN_URL_FMT.format(dotted=dotted, build=build),
                              dotted))
        return found, f"线 {fam} base={base} line_max={line_max}"

    tl = tag_line(releases)         # 路径②：现行点分 body
    if tl is None:
        return [], None
    fam, ns, maxN = tl
    x = find_newest_build(prober, fam, maxN, known)
    if x is None:
        return [], f"线 {fam} 最新 tag {fam}.{maxN} 的构建号未能在 CDN 定位"
    base = x - maxN
    found = []
    for build in range(known + 1, x + PROBE_AHEAD + 1):
        if prober.dead or build in seen:
            continue
        n = build - base
        if n in ns:
            continue   # 线内已归档 release：由「?」点分行挂载处理，防双重下载
        dotted = f"{fam}.{n}"
        if prober.exists(CDN_URL_FMT.format(dotted=dotted, build=build)):
            found.append((build, CDN_URL_FMT.format(dotted=dotted, build=build),
                          dotted))
    return found, f"线 {fam} base={base}（X={x}）tag排除{len(ns)}个N"


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    releases_path, config_path = args[0], args[1]
    with open(config_path) as f:
        known = max(int(v["version"]) for v in json.load(f))
    try:
        with open(releases_path) as f:
            releases = json.load(f)
    except (OSError, ValueError):
        releases = []   # 归档源不可达/非法 JSON → zsbai 面按「无新构建」跳过

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

    probe_rows = []
    if "--cdn-probe" in flags:
        found, note = cdn_probe(known, releases, seen)
        if note is None:
            print("cdn-probe: 无可用锚点（无 tag/数字 DestVersion），本轮跳过探测",
                  file=sys.stderr)
        else:
            print(f"cdn-probe: {note} known={known}", file=sys.stderr)
            for build, url, dotted in found:
                # 探测行必须排在 release 行之前：流水线「?」点分行解析到
                # ≤ known 即 break（其后 release 只会更旧），追加在末尾的
                # 行永远不被处理。探测行自带精确构建号，无次序依赖。
                probe_rows.append(f"{build} {url} {dotted}")
    if probe_rows or out:
        print("\n".join(probe_rows + out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
