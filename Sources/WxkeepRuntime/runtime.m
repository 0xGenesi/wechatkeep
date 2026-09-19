#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <string.h>
#import <stdlib.h>
#import <os/log.h>
#include <libkern/OSCacheControl.h>

#include "wxkeep_runtime.h"

// wxkeep 运行时组件（可选功能）。
// M-R1：加载证明 + 标记文件。
// M-R2：撤回提示文本替换——hook 撤回解析汇点 wrapper，在其入口把
//       sysmsg XML 中 <replacemsg> 的内文等长改写为 runtime.json 文案，
//       下游（解析结果/入库/会话预览/渲染/历史重扫）全部拿到自定义文本。
//       文案支持 {from} 占位符（展开为撤回者昵称，取自原提示内文的首对
//       引号）；自发撤回提示（"你撤回了一条消息"）默认不改写，rewrite_self
//       开启才一起换——自己的撤回保持诚实反馈（RecallKeeper 同款语义）。
//
// hook 点位（drive22 全链实证，docs/ROADMAP ⑦ 终验定案）：
//  - isRevokemsg 全程只收 "revokemsg" 类型串（40+ 次实测无一例外）——
//    「hook isRevokemsg 改写内容 SSO」前提证伪，isRevokemsg 是纯类型谓词。
//  - wrapper [0x537d910..0x537db40)@270099 是 A 到达解析 / B 二次解析 /
//    D 历史批扫三条路径的唯一公共汇点（每个 parse 命中的调用者都是
//    wrapper 内 0x537dad3 的 call）。
//  - 0.2.0 实机撤回验证：wrapper+0x130 静态推定未命中（fires=0），按预案
//    全家族切 parse 入口直挂——parse(rdi, rsi=XML SSO, &ok) 为 drive25
//    调试器实拍地面真值；wrapper 仅是 parse 的唯一调用者，覆盖面不变。
//  - 早期候选 0x538d700（排水函数，rsi=replacemsg 裸 SSO）只覆盖 async
//    路径，被 wrapper 方案取代。
//
// 工程约束（RUNTIME-DESIGN / 270090 启动闪退教训）：
//  - 一切初始化在构造器内**同步**完成（_dyld_register_func_for_add_image
//    回调 + 既有镜像线性扫描双保险），不派发异步任务。
//  - 目标函数按构建号 + LC_UUID 双门校验；未知构建一律不挂钩。
//  - hook 体只做「读字段 → 命中判定 → 缓冲内等长 memcpy → 放行」，
//    无锁、无分配、无外部调用，任意线程重入安全（文案为只读静态缓冲）。

// ---------------------------------------------------------------------------
// 地址表（expected = 目标函数入口原像，防漂移门）
//
// 两个来源，优先级：runtime.json 的 hooks 数组（外部表）> 编译期内置表。
// 外部表是新构建 day-0 支持的数据通道——`wxkeep runtime install` 把已知
// 行写进 runtime.json，研究产出新构建行后只需更新数据（update-data 或
// 重跑 install），dylib 不必重编。行内全部字段过门（UUID 形制、hex、
// expected 长度匹配 arch、arm64 序言无 PC 相对编码）才被接受。
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t hook_off;          // hook 目标（wrapper）在 wechat.dylib 内的 VM 偏移
    uint64_t msg_arg;           // 消息结构在第几个整型参数（x64: 1=rsi / arm64: 1=x1）
    uint64_t xml_sso_off;       // 撤回 XML SSO 字段在消息结构内的偏移
    uint8_t expected[16];       // 入口原像（x64 12B / arm64 16B，须可换址执行）
    uint8_t expected_len;       // 12（x86_64）或 16（arm64）
    uint8_t is_arm64;
    char uuid[40];              // LC_UUID 标准连字符形（身份门）
    char build[16];             // 诊断标注
} hook_target_t;

// 270099 x86_64 — hook 点 = parse 入口（drive25 地面真值：rsi 直挂 sysmsg
// XML SSO）。早期 wrapper+0x130 形态为静态推定，0.2.0 实机真实撤回
// fires=0 证伪后全家族切 parse 直挂（ROADMAP ㉑）。序言 12B 纯栈操作。
static const hook_target_t kTarget270099 = {
    .hook_off = 0x537db40,
    .msg_arg = 1,
    .xml_sso_off = 0,
    .expected = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54},
    .expected_len = 12,
    .is_arm64 = 0,
    .uuid = "97e21436-abda-3b79-bec0-ef2653c6b423",
    .build = "270099",
};

static const hook_target_t *const kBuiltins[] = { &kTarget270099 };
static const size_t kBuiltinCount = sizeof(kBuiltins) / sizeof(kBuiltins[0]);

// 20 = 4.1.15 全家族（除未发布的 270092）× 双架构；32 留 update-data
// 下发新构建行的余量（越限行被静默丢弃——parse 循环的 n >= 上限 break）。
enum { kMaxExtHooks = 32 };
static hook_target_t g_ext_hooks[kMaxExtHooks];
static int g_ext_hook_count;

// ---------------------------------------------------------------------------
// 配置（Application Support/wxkeep/runtime.json）
// ---------------------------------------------------------------------------

static char g_tip_text[128];       // 固定文案（NUL 结尾，UTF-8）
static size_t g_tip_len;
static int g_rewrite_self;         // 自发撤回提示是否也改写（默认 0=不改）
static int g_rewrite_hits;         // 撤回 needle 命中计数（含自发跳过/超长放弃）
static int g_rewrite_fires;        // 实际完成改写的计数（验证肉眼化的证据面）
static int g_keep_message = 1;     // 通用 keeptip：parse 前清零 XML newmsgid（默认开）
static int g_zero_fires;           // newmsgid 清零计数
static char g_last_fired[96];      // 最后一次改写后的内文前 95B（渲染问题取证）
static char g_last_inner[96];      // 最后一次 needle 命中时的原始内文前 95B
static int g_hook_installed;
// 诊断（marker 回写）：0=未尝试 1=UUID 不匹配 2=序言不匹配
// 3=mmap/mprotect 失败 4=已武装；bit8=回调已触发
static int g_hook_status;
enum { kStIdle = 0, kStUuidMismatch = 1, kStPrologueMismatch = 2,
       kStInstallFail = 3, kStArmed = 4, kStCallbackBit = 8,
       kStScanMissed = 16 };
static char g_probe_name[96];   // 构造器期匹配到的镜像名样本（诊断）
static int uuid_matches(const struct mach_header_64 *hdr, const char *want);

// marker 回写：armed 后状态翻转；构造器/武装路径 loud=1（带 NSLog），
// 周期证据回写 loud=0（30s 一次，刷计数器——不刷则 marker 永远停在启动
// 快照的 fires=0，`runtime status` 看不到会话内增长的证据）。
void write_marker(void);
static void write_marker_ex(int loud);

// 计数器/采样由 hook 线程写、marker 写线程读，无锁并存（诊断面，撕裂只
// 影响单次显示）。字符串采样必须先sanitize-copy：写方 memcpy 后才置 NUL，
// 读方直接 @(cstr) 在该窗口可能越过数组尾——本地副本强制尾 NUL 兜底。
static NSString *cstr_sample(const volatile char *src) {
    char local[sizeof(g_last_fired) + 1];
    memcpy(local, (const void *)src, sizeof(g_last_fired));
    local[sizeof(g_last_fired)] = 0;
    return local[0] ? @(local) : @"";
}
static volatile int32_t g_arm_done;   // 整个进程只装一次（多触发源竞态防御）
static const char kTarget270099_uuid[] = "97e21436-abda-3b79-bec0-ef2653c6b423";
static char g_last_uuid[40];     // 回调收到的最后一个镜像 UUID
static int g_cb_count;           // 回调触发计数
static int g_scan_missed;

// ---------------------------------------------------------------------------
// 配置路径策略（2026-09-19 沙盒修复）：
//   微信是沙盒应用（app-sandbox + App Group 5A4RE8SF68.com.tencent.xinWeChat），
//   NSSearchPath 的 ~/Library 在其内部展开到**容器**路径——CLI（沙盒外）写的
//   runtime.json（真实 home）dylib 根本读不到，marker 也写进容器导致
//   `runtime status` 永远「无记录」（marker=marker-only status=9 实证）。
//   唯一双端可达的位点是 App Group Container：dylib 在沙盒内用
//   containerURL(forSecurityApplicationGroupIdentifier:)（框架映射到真实
//   group 目录，非沙盒宿主返回 nil）；CLI 直接拼真实 home 写入。
//   旧 NSSearchPath 路径保留为回落（非沙盒宿主兼容 + 历史文件迁移）。
// ---------------------------------------------------------------------------

static NSString *runtimeAppGroupID(void) {
    return @"5A4RE8SF68.com.tencent.xinWeChat";
}

static NSString *groupContainerConfigPath(void) {
    @autoreleasepool {
        NSURL *url = nil;
        @try {
            url = [[NSFileManager defaultManager]
                containerURLForSecurityApplicationGroupIdentifier:runtimeAppGroupID()];
        } @catch (NSException *e) {
            return nil;   // 非沙盒宿主/无授权：回落 legacy 路径
        }
        if (url.path.length == 0) return nil;
        return [[url.path stringByAppendingPathComponent:@"wxkeep"]
            stringByAppendingPathComponent:@"runtime.json"];
    }
}

static NSString *runtimeConfigPath(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, YES);
    if (dirs.count == 0) return nil;
    return [[dirs[0] stringByAppendingPathComponent:@"wxkeep"]
        stringByAppendingPathComponent:@"runtime.json"];
}

/// 首个可解析的配置文件（Group 容器优先），两处都无效返回 nil。
static NSDictionary *read_runtime_config(void) {
    NSString *group = groupContainerConfigPath();
    if (group) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:group];
        if ([d isKindOfClass:[NSDictionary class]]) return d;
    }
    NSString *legacy = runtimeConfigPath();
    if (legacy) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:legacy];
        if ([d isKindOfClass:[NSDictionary class]]) return d;
    }
    return nil;
}

// ---------------------------------------------------------------------------
// runtime.json hooks 行解析（外部地址表）
// ---------------------------------------------------------------------------

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// "5548…" → 原始字节。非法字符/悬挂半字节/超 cap → 0（长度）。
static size_t parse_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1]) {
        int hi = hex_nibble(s[0]), lo = hex_nibble(s[1]);
        if (hi < 0 || lo < 0 || n >= cap) return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    if (*s) return 0;
    return n;
}

/// 标准连字符 UUID 形制（36 字符，连字符位于 8/13/18/23，其余小写十六进制）
/// —— 与 uuid_matches 的消费字符集一致（大写不接受）。
static int uuid_str_valid(const char *s) {
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return 0;
        } else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return s[36] == 0;
}

/// arm64 序言可换址性：蹦床把入口 16B 原样换址执行，任何 PC 相对编码
/// （ADRP/ADR/B/BL/CBZ 系/TBZ 系/LDR-literal 族）在换址后都会指向错误
/// 目标——出现即拒绝该行。x64 同等保证由「纯栈操作序言」的字节门 +
/// 表作者负责（与内置表同规）；arm64 加这道编码级防线是因为 16B 序言
/// 更容易含早期分支。
static int arm64_prologue_relocatable(const uint8_t *p, size_t n) {
    for (size_t i = 0; i + 4 <= n; i += 4) {
        uint32_t w;
        memcpy(&w, p + i, 4);
        if ((w & 0x9F000000u) == 0x90000000u) return 0;   // ADRP
        if ((w & 0x9F000000u) == 0x10000000u) return 0;   // ADR
        if ((w & 0x7C000000u) == 0x14000000u) return 0;   // B / BL
        if ((w & 0x7E000000u) == 0x34000000u) return 0;   // CBZ / CBNZ
        if ((w & 0x7E000000u) == 0x36000000u) return 0;   // TBZ / TBNZ
        if ((w & 0xBF000000u) == 0x18000000u) return 0;   // LDR/LDRSW/PRFM literal
    }
    return 1;
}

/// runtime.json hooks 行 → hook_target_t。字段：build(诊断)/uuid/arch/
/// hook_off(hex)/msg_arg/xml_sso_off/expected(hex)。任何字段坏 → 整行
/// 丢弃（宁可不挂也不挂错——与 expected 门的哲学一致）。
static int hook_row_parse(NSDictionary *row, hook_target_t *out) {
    if (![row isKindOfClass:[NSDictionary class]]) return 0;
    NSString *uuid = row[@"uuid"];
    NSString *arch = [row[@"arch"] isKindOfClass:[NSString class]] ? row[@"arch"] : @"x86_64";
    NSString *off = row[@"hook_off"];
    NSString *exp = row[@"expected"];
    NSNumber *marg = [row[@"msg_arg"] isKindOfClass:[NSNumber class]] ? row[@"msg_arg"] : nil;
    NSNumber *soff = [row[@"xml_sso_off"] isKindOfClass:[NSNumber class]] ? row[@"xml_sso_off"] : nil;
    if (![uuid isKindOfClass:[NSString class]] || uuid.length != 36) return 0;
    if (![off isKindOfClass:[NSString class]] || ![exp isKindOfClass:[NSString class]]) return 0;

    memset(out, 0, sizeof(*out));
    if (!uuid_str_valid(uuid.UTF8String)) return 0;
    out->hook_off = strtoull(off.UTF8String, NULL, 16);   // 接受 0x 前缀
    if (out->hook_off == 0 || out->hook_off >= (1ULL << 32)) return 0;
    out->msg_arg = marg ? marg.unsignedLongValue : 1;
    out->xml_sso_off = soff ? soff.unsignedLongValue : 0x130;
    if (out->msg_arg > 5 || out->xml_sso_off > 0x1000) return 0;
    out->is_arm64 = [arch isEqualToString:@"arm64"];
    out->expected_len = out->is_arm64 ? 16 : 12;
    if (parse_hex(exp.UTF8String, out->expected, sizeof(out->expected)) != out->expected_len) {
        return 0;
    }
    if (out->is_arm64 && !arm64_prologue_relocatable(out->expected, 16)) return 0;
    strlcpy(out->uuid, uuid.UTF8String, sizeof(out->uuid));
    NSString *build = [row[@"build"] isKindOfClass:[NSString class]] ? row[@"build"] : @"?";
    strlcpy(out->build, build.UTF8String, sizeof(out->build));
    return 1;
}

/// 从已解析的配置字典装载外部 hooks 表；无合法行则保持 0（回落内置表）。
static void load_hooks_from(NSDictionary *cfg) {
    id hooks = cfg[@"hooks"];
    if (![hooks isKindOfClass:[NSArray class]]) return;
    int n = 0;
    for (id row in hooks) {
        if (n >= kMaxExtHooks) break;
        if (hook_row_parse(row, &g_ext_hooks[n])) n++;
    }
    if (n > 0) g_ext_hook_count = n;
}

/// 镜像与地址表的匹配入口：外部表在场则只查外部表（数据权威），
/// 否则查内置表。返回命中行，未命中返回 NULL。
static const hook_target_t *match_target(const struct mach_header_64 *hdr) {
    if (g_ext_hook_count > 0) {
        for (int i = 0; i < g_ext_hook_count; i++) {
            if (uuid_matches(hdr, g_ext_hooks[i].uuid)) return &g_ext_hooks[i];
        }
        return NULL;
    }
    for (size_t i = 0; i < kBuiltinCount; i++) {
        if (uuid_matches(hdr, kBuiltins[i]->uuid)) return kBuiltins[i];
    }
    return NULL;
}

static void apply_config_dict(NSDictionary *cfg) {
    NSString *text = cfg[@"tip_text"];
    if ([text isKindOfClass:[NSString class]] && text.length > 0) {
        NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
        if (data.length > 0 && data.length < sizeof(g_tip_text)) {
            // 文案最终嵌入 XML 文本节点：剥掉会破坏标签/实体的 < > & 三种
            // 字符（长度随之收缩），其余（含 emoji/引号）原样保留。
            // 服务端 replacemsg 含昵称，内文普遍 ≥30B，128B 上限足够。
            const uint8_t *src = data.bytes;
            size_t o = 0;
            for (size_t i = 0; i < data.length; i++) {
                if (src[i] == '<' || src[i] == '>' || src[i] == '&') continue;
                if (o >= sizeof(g_tip_text) - 1) break;
                g_tip_text[o++] = src[i];
            }
            g_tip_text[o] = 0;
            g_tip_len = o;
        }
    }
    // 自发撤回（“你撤回了一条消息”）默认不改写——自己的撤回保持诚实反馈；
    // 置 true 才连自发提示一起换文案。
    g_rewrite_self = [cfg[@"rewrite_self"] boolValue];
    // keep_message 缺省即开（runtime hook 的核心价值）；显式 false 关闭
    id km = cfg[@"keep_message"];
    g_keep_message = (km == nil) ? 1 : [km boolValue];
    load_hooks_from(cfg);
}

static void load_config(void) {
    NSDictionary *cfg = read_runtime_config();
    if ([cfg isKindOfClass:[NSDictionary class]]) apply_config_dict(cfg);
}

// ---------------------------------------------------------------------------
// 微信 SSO 字符串（drive17/22 实测布局）：
//   byte0 = len<<1 | isLong；短串数据在 +1；长串 size@+8 ptr@+0x10
//   —— hook 只读头部（tag/size/ptr），改写发生在 SSO 指向的
//      XML 缓冲内部（等长替换），SSO 结构与分配器零接触。
// ---------------------------------------------------------------------------

static const char kRevokeNeedle[] = "\xe6\x92\xa4\xe5\x9b\x9e";  // “撤回” UTF-8
enum { kNeedleLen = sizeof(kRevokeNeedle) - 1 };
static const char kCdataOpen[] = "<![CDATA[";   // 9B，可选包裹
enum { kCdataLen = sizeof(kCdataOpen) - 1 };
// 提示文本承载元素：drive25 实测 270099 推送撤回 XML 用 <content>；
// <replacemsg> 为静态分析所见的另一分支形态，按序尝试。
static const char kContentOpen[] = "<content>",   kContentClose[] = "</content>";
static const char kReplaceOpen[] = "<replacemsg>", kReplaceClose[] = "</replacemsg>";

/// 受限 memmem：在 [hay, hay+hay_len) 内找 needle 首次出现。
static uint8_t *find_bytes(uint8_t *hay, uint64_t hay_len,
                           const char *needle, size_t needle_len) {
    if (hay_len < needle_len) return NULL;
    uint64_t last = hay_len - needle_len;
    for (uint64_t i = 0; i <= last; i++) {
        if (hay[i] == (uint8_t)needle[0] &&
            memcmp(hay + i, needle, needle_len) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/// 内文里提取撤回者昵称：线上形态 `"昵称" 撤回了一条消息`（私聊实测，
/// 群聊同形）。取首对 ASCII 双引号内的文本；无引号形态返回 0。
static size_t extract_from(const uint8_t *inner, uint64_t inner_len,
                           const uint8_t **from) {
    if (inner_len < 2 || inner[0] != '"') return 0;
    for (uint64_t i = 1; i < inner_len; i++) {
        if (inner[i] == '"') {
            if (i == 1) return 0;   // 空昵称
            *from = inner + 1;
            return (size_t)(i - 1);
        }
    }
    return 0;   // 只有开引号：不解析
}

static const char kFromPh[] = "{from}";
enum { kFromPhLen = sizeof(kFromPh) - 1 };

static int bytes_contain(const char *hay, size_t hay_len,
                         const char *needle, size_t needle_len) {
    if (hay_len < needle_len) return 0;
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

/// 把文案中的 {from} 占位符替换为昵称 → eff（栈缓冲，hook 上下文无锁）。
/// 全部出现都替换；昵称不可解析 → 展开为空；昵称 >64B 或结果超缓冲 →
/// 返回 0（调用方放弃改写保原文——截断昵称会切碎 UTF-8）。
static size_t expand_tip(const char *tip, size_t tip_len,
                         const uint8_t *from, size_t from_len,
                         char *eff, size_t cap) {
    if (from_len > 64) return 0;
    size_t o = 0;
    for (size_t i = 0; i < tip_len; ) {
        if (i + kFromPhLen <= tip_len
            && memcmp(tip + i, kFromPh, kFromPhLen) == 0) {
            if (from_len) {
                if (o + from_len > cap) return 0;
                memcpy(eff + o, from, from_len);   // from 可为 NULL（len=0），先判后拷
                o += from_len;
            }
            i += kFromPhLen;
        } else {
            if (o + 1 > cap) return 0;
            eff[o++] = tip[i++];
        }
    }
    return o;
}

/// 提示内文等长改写（M-R2 核心，drive25 实弹定案语义）：
///  ⚠️ 渲染约束（0.2.0 实机发现）：持久化后的提示由渲染层按官方骨架
///  （`"…" 撤回了一条消息`）匹配显示——tip_text 必须保持该骨架，
///  非规范内容渲染为 "Unsupported message" 占位（内容字节本身无损）。
///  - 只动 SSO 指向的数据缓冲内部，SSO 结构/分配器零接触；
///  - 内文须含「撤回」needle（类型门：非撤回消息绝不动）；
///  - 自发撤回（内文以「你撤回」起头）默认跳过——自己的撤回保持诚实
///    反馈；rewrite_self 开启才一起换；
///  - 文案含 {from} 时以原内文首对引号内的昵称展开（M-R3-lite）；
///  - 依次尝试 <content>（270099 实测线上形态）与 <replacemsg>（静态备选），
///    内文可选 <![CDATA[ 包裹（跳过前缀、闭合标签定界）；
///  - 展开后文案长于内文 → 放弃（保原文）；短于内文 → 空格填充到等长。
/// 返回 1 表示发生改写。
static int rewrite_inner_with(uint8_t *ptr, uint64_t size,
                              const char *open_tag, size_t open_len,
                              const char *close_tag, size_t close_len) {
    uint8_t *open = find_bytes(ptr, size, open_tag, open_len);
    if (!open) return 0;
    uint8_t *inner = open + open_len;
    int cdata = 0;
    if (size - (uint64_t)(inner - ptr) >= kCdataLen
        && memcmp(inner, kCdataOpen, kCdataLen) == 0) {
        inner += kCdataLen;
        cdata = 1;
    }
    uint64_t remain = size - (uint64_t)(inner - ptr);
    uint8_t *close = find_bytes(inner, remain, close_tag, close_len);
    if (!close) return 0;
    uint64_t inner_len = (uint64_t)(close - inner);
    // CDATA 形态：闭合 ]]> 必须紧邻闭合标签前并在位（否则改写后 CDATA 段
    // 永不闭合、XML 破坏）——不在位即放弃，保原文。
    if (cdata) {
        if (inner_len < 3 || memcmp(close - 3, "]]>", 3) != 0) return 0;
        inner_len -= 3;
    }
    if (inner_len < kNeedleLen) return 0;
    if (!find_bytes(inner, inner_len, kRevokeNeedle, kNeedleLen)) return 0;
    g_rewrite_hits++;   // needle 命中（含自发跳过/超长放弃——marker 可观测）
    {
        size_t snap = inner_len < sizeof(g_last_inner) - 1 ? (size_t)inner_len : sizeof(g_last_inner) - 1;
        memcpy(g_last_inner, inner, snap);
        g_last_inner[snap] = 0;
    }
    // 自发撤回门（“你” = E4BDA0，“撤回” needle 前缀）
    if (!g_rewrite_self && inner_len >= 9
        && memcmp(inner, "\xe4\xbd\xa0\xe6\x92\xa4\xe5\x9b\x9e", 9) == 0) return 0;
    // {from} 展开（仅当文案里真的写了占位符）
    char eff[sizeof(g_tip_text) + 64];
    size_t eff_len;
    if (bytes_contain(g_tip_text, g_tip_len, kFromPh, kFromPhLen)) {
        const uint8_t *from = NULL;
        size_t from_len = extract_from(inner, inner_len, &from);
        eff_len = expand_tip(g_tip_text, g_tip_len, from, from_len,
                             eff, sizeof(eff));
    } else {
        memcpy(eff, g_tip_text, g_tip_len);
        eff_len = g_tip_len;
    }
    if (eff_len == 0 || eff_len > inner_len) return 0;
    memcpy(inner, eff, eff_len);
    memset(inner + eff_len, ' ', inner_len - eff_len);
    g_rewrite_fires++;
    size_t snap = inner_len < sizeof(g_last_fired) - 1 ? (size_t)inner_len : sizeof(g_last_fired) - 1;
    memcpy(g_last_fired, inner, snap);
    g_last_fired[snap] = 0;
    return 1;
}

/// 通用 keeptip 核心（0.2.x 降维实现）：不改任何指令，直接把 XML 里
/// <newmsgid> 的数字等长清零（'1'-'9' → '0'）——parse 读到 0 → 撤回删除
/// 按目标查不到 → 原消息保留（v1 语义），提示文本不受影响。不依赖任何
/// 指令地址：hook 能武装的构建即工作，跨构建通用。
/// 返回清零的数字个数（0 = 无 <newmsgid> 或已是 0）。
static int zero_newmsgid_digits(uint8_t *buf, uint64_t size) {
    static const char tag[] = "<newmsgid>";
    uint8_t *p = find_bytes(buf, size, tag, sizeof(tag) - 1);
    if (!p) return 0;
    uint64_t i = (uint64_t)(p - buf) + (sizeof(tag) - 1);
    int n = 0;
    while (i < size && buf[i] != '<') {
        if (buf[i] >= '1' && buf[i] <= '9') { buf[i] = '0'; n++; }
        else if (buf[i] != '0') break;   // 非数字（空白/异常形态）即停
        i++;
    }
    return n;
}

static int rewrite_replacemsg_inner(uint8_t *sso) {
    uint8_t tag = sso[0];
    if (!(tag & 1)) return 0;   // 短串装不下完整撤回 XML（≥60B），必非撤回
    uint64_t size;
    uint8_t *ptr;
    memcpy(&size, sso + 8, 8);
    memcpy(&ptr, sso + 16, 8);
    if (size < kNeedleLen || size > (1 << 20) || ptr < (uint8_t *)0x10000) return 0;
    if (!find_bytes(ptr, size, kRevokeNeedle, kNeedleLen)) return 0;  // 快速门
    if (rewrite_inner_with(ptr, size, kContentOpen, sizeof(kContentOpen) - 1,
                           kContentClose, sizeof(kContentClose) - 1)) return 1;
    return rewrite_inner_with(ptr, size, kReplaceOpen, sizeof(kReplaceOpen) - 1,
                              kReplaceClose, sizeof(kReplaceClose) - 1);
}

// ---------------------------------------------------------------------------
// inline hook
//   x86_64：入口 12B → movabs rax, hook; jmp rax；蹦床 = saved 12B +
//           movabs r11, target+12; jmp r11（CISC 变长指令，12B 恰好覆盖）
//   arm64 ：入口 16B → ldr x17,#8; br x17; .quad hook；蹦床 = saved 16B +
//           ldr x17,#8; br x17; .quad target+16（定长 4B 指令，16B 覆盖
//           整 4 条；写后必须 sys_icache_invalidate——arm64 icache 不自闭
//           一致，2026-09 实证 wechat.dylib arm64 切片无 PAC/BTI，
//           蹦床无需签名/对齐处理）
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t saved[16];        // 原入口字节（已重定位的运行时原像）
    void *trampoline;         // RWX 蹦床：saved 原像 + 跳回 target+len
    uintptr_t target;
    uint64_t msg_arg;
    uint64_t xml_sso_off;
} hook_ctx_t;

static hook_ctx_t g_hook;

// 调用约定透传：x64 前六整型参 rdi..r9 / arm64 前八整型参 x0..x7——取六参
// 足够还原 wrapper 的 (rdi=信息对象, rsi=消息结构) 形态（arm64 为 x0/x1）。
static void *(*g_real_wrapper)(void *, void *, void *, void *, void *, void *);

static void *revoke_wrapper_hook(void *a0, void *a1, void *a2,
                                 void *a3, void *a4, void *a5) {
    if (g_hook.target && (g_tip_len || g_keep_message)) {
        void *args[6] = {a0, a1, a2, a3, a4, a5};
        uint8_t *msg = (uint8_t *)args[g_hook.msg_arg];
        if (msg > (uint8_t *)0x10000) {
            uint8_t *sso = msg + g_hook.xml_sso_off;
            if (sso[0] & 1) {   // 长串形态（撤回 XML 必为长串）
                uint64_t size;
                uint8_t *ptr;
                memcpy(&size, sso + 8, 8);
                memcpy(&ptr, sso + 16, 8);
                if (size >= 32 && size <= (1 << 20) && ptr >= (uint8_t *)0x10000) {
                    if (g_keep_message) {
                        if (zero_newmsgid_digits(ptr, size) > 0) g_zero_fires++;
                    }
                    if (g_tip_len) rewrite_replacemsg_inner(sso);
                }
            }
        }
    }
    return g_real_wrapper(a0, a1, a2, a3, a4, a5);
}

static int install_hook(const hook_target_t *t, uintptr_t base) {
    int32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_arm_done, &expected, 1, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return -2;   // 别的触发源已装
    }
    uintptr_t target = base + t->hook_off;
    size_t len = t->expected_len;               // x64 12 / arm64 16
    uint8_t prologue[16];
    memcpy(prologue, (void *)target, len);
    if (memcmp(prologue, t->expected, len) != 0) {
        os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] prologue mismatch — hook skipped");
        g_hook_status |= kStPrologueMismatch;
        return -1;
    }
    // arm64 的 PC 相对编码在换址执行时会指向错误目标——外部表已在解析期
    // 过滤，这里对实际内存再验一次（内置表同受保护）。
    if (t->is_arm64 && !arm64_prologue_relocatable(prologue, len)) {
        g_hook_status |= kStPrologueMismatch;
        return -1;
    }
    // 蹦床：RWX 页内 = 原入口原像 + 跳回 target+len。
    uint8_t *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) { g_hook_status |= kStInstallFail; return -1; }
    memcpy(mem, prologue, len);
    uint64_t back = target + len;
    if (t->is_arm64) {
        memcpy(mem + len, "\x51\x00\x00\x58", 4);        // ldr x17, #8
        memcpy(mem + len + 4, "\x20\x02\x1f\xd6", 4);    // br x17
        memcpy(mem + len + 8, &back, 8);
        sys_icache_invalidate(mem, len + 16);
    } else {
        memcpy(mem + 12, "\x49\xbb", 2);                 // movabs r11, imm64
        memcpy(mem + 14, &back, 8);
        memcpy(mem + 22, "\x41\xff\xe3", 3);             // jmp r11
    }

    g_hook.target = target;
    g_hook.msg_arg = t->msg_arg;
    g_hook.xml_sso_off = t->xml_sso_off;
    memcpy(g_hook.saved, prologue, len);
    g_hook.trampoline = mem;
    g_real_wrapper = (void *(*)(void *, void *, void *, void *, void *, void *))mem;

    uintptr_t page = target & ~(uintptr_t)0xfff;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        g_hook_status |= kStInstallFail;
        // 失败清理：蹦床页归还 + 复位 g_hook（此刻 entry 尚未改写、hook 未
        // 到达，g_real_wrapper 不可能有调用者——g_arm_done 已置位不再重试，
        // 残留武装态字段只会误导诊断）。
        g_hook.target = 0;
        g_hook.trampoline = NULL;
        g_real_wrapper = NULL;
        munmap(mem, 4096);
        return -1;
    }
    uint8_t stub[16];
    uint64_t hook = (uint64_t)&revoke_wrapper_hook;
    if (t->is_arm64) {
        memcpy(stub, "\x51\x00\x00\x58", 4);             // ldr x17, #8
        memcpy(stub + 4, "\x20\x02\x1f\xd6", 4);         // br x17
        memcpy(stub + 8, &hook, 8);
        memcpy((void *)target, stub, 16);
        sys_icache_invalidate((void *)target, 16);
    } else {
        memcpy(stub, "\x48\xb8", 2);                     // movabs rax, imm64
        memcpy(stub + 2, &hook, 8);
        memcpy(stub + 10, "\xff\xe0", 2);                // jmp rax
        memcpy((void *)target, stub, 12);
    }
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    return 0;
}

// ---------------------------------------------------------------------------
// 镜像定位（构造器同步执行：先扫既有镜像，再挂回调兜底后续加载）
// ---------------------------------------------------------------------------

// LC_UUID 提取 + 与标准连字符 UUID 串比对（逐半字节，双向跳过连字符，
// 双侧必须同时耗尽）。注意不能先在 buf 里补 '-' 再比较：want 耗尽时 a
// 停在填充字符上，收尾的 `*a == 0 && *b == 0` 恒假——任何镜像（含目标
// 本尊）都会被判不匹配，hook 永不安装。
static int uuid_matches(const struct mach_header_64 *hdr, const char *want) {
    uint8_t uuid[16];
    int found = 0;
    const uint8_t *p = (const uint8_t *)hdr + sizeof(struct mach_header_64);
    const uint8_t *end = p + hdr->sizeofcmds;
    // p+8<=end：cmd/size 字段本身 8B——缓冲式调用（probe_match_target 的
    // malloc 缓冲）下防病态尾部 4B 越读；合法镜像每条 cmd ≥8B 不受影响
    while (p + 8 <= end) {
        uint32_t cmd, size;
        memcpy(&cmd, p, 4); memcpy(&size, p + 4, 4);
        if (cmd == LC_UUID && size >= 24) {
            memcpy(uuid, p + 8, 16);
            found = 1;
            break;
        }
        if (size < 8) break;   // 非法 cmdsize：停走防死循环——合法镜像最小命令也是 8B
        p += size;
    }
    if (!found) return 0;
    static const char hex[] = "0123456789abcdef";
    const char *b = want;
    for (int i = 0; i < 16; i++) {
        while (*b == '-') b++;
        if (*b != hex[uuid[i] >> 4]) return 0;
        b++;
        while (*b == '-') b++;
        if (*b != hex[uuid[i] & 0xf]) return 0;
        b++;
    }
    return *b == 0;
}

static void try_hook_image(const struct mach_header_64 *hdr, intptr_t slide) {
    (void)slide;
    // UUID 即身份门（构建+切片唯一），不做镜像名匹配——名字反查需要
    // _dyld_image_count()，在 add_image 回调上下文里不可靠（实测 status=24：
    // 名字链提前 return，UUID 检查从未到达）。直接读 header 的 LC_UUID。
    const hook_target_t *t = match_target(hdr);
    if (t) {
        if (install_hook(t, (uintptr_t)hdr) == 0) {
            g_hook_installed = 1;
            g_hook_status = kStArmed;
            os_log(OS_LOG_DEFAULT,
                   "[wxkeep-runtime] M-R2 hook armed build=%{public}@",
                   @(t->build));
            // marker 不在这里回写：本函数可能在 add_image 回调（dyld 持锁）
            // 上下文执行，Foundation 磁盘 I/O 不该发生在那里；armed 态的
            // marker 由构造器尾部 / arm_late / 定时器在安全上下文回写。
        }
        return;
    }
    g_hook_status |= kStUuidMismatch;   // 每个非目标镜像都会置位（诊断噪音可接受）
}

static void on_image_add(const struct mach_header *mh, intptr_t slide) {
    g_hook_status |= kStCallbackBit;
    g_cb_count++;
    {
        // 记录最后一个到达镜像的 UUID（诊断：wechat.dylib 是否经过回调）
        const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
        const uint8_t *end = p + mh->sizeofcmds;
        while (p + 8 <= end) {
            uint32_t cmd, size;
            memcpy(&cmd, p, 4); memcpy(&size, p + 4, 4);
            if (cmd == LC_UUID && size >= 24) {
                static const char hx[] = "0123456789abcdef";
                char *o = g_last_uuid;
                for (int i = 0; i < 16; i++) {
                    *o++ = hx[p[8 + i] >> 4]; *o++ = hx[p[8 + i] & 0xf];
                }
                o[0] = 0;
                break;
            }
            if (size < 8) break;   // 与 uuid_matches 同规：非法 cmdsize 停走防死循环
            p += size;
        }
        if (uuid_matches((const struct mach_header_64 *)mh, kTarget270099_uuid)) {
            // wechat.dylib 确实从回调到达——记下这一事实
            strlcpy(g_probe_name, "callback-saw-wechat-uuid", sizeof(g_probe_name));
        }
    }
    try_hook_image((const struct mach_header_64 *)mh, slide);
}

// ---------------------------------------------------------------------------
// M-R1：标记文件
// ---------------------------------------------------------------------------

void write_marker(void) { write_marker_ex(1); }

static void write_marker_ex(int loud) {
    @autoreleasepool {
        // 与配置同策略：Group 容器优先（CLI/runtime status 在沙盒外读同一路
        // 径），legacy NSSearchPath 路径回落——容器内 ~/ 展开曾让 marker 对
        // CLI 不可见（沙盒实证）。
        NSString *dir = nil;
        NSURL *groupURL = nil;
        @try {
            groupURL = [[NSFileManager defaultManager]
                containerURLForSecurityApplicationGroupIdentifier:runtimeAppGroupID()];
        } @catch (NSException *e) {
            groupURL = nil;
        }
        if (groupURL.path.length > 0) {
            dir = [groupURL.path stringByAppendingPathComponent:@"wxkeep"];
        } else {
            dir = @"~/Library/Application Support/wxkeep";
            dir = [dir stringByExpandingTildeInPath];
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *marker = [dir stringByAppendingPathComponent:@"runtime.marker"];
        NSString *now = [NSString stringWithFormat:
            @"loaded ts=%f mr2=%@ status=%d fires=%d hits=%d zero=%d last=%@ inner=%@ probe=%@\n",
            [NSDate date].timeIntervalSince1970,
            g_hook_installed ? @"hook-armed" : @"marker-only", g_hook_status,
            g_rewrite_fires, g_rewrite_hits, g_zero_fires,
            g_last_fired[0] ? cstr_sample(g_last_fired) : @"<none>",
            g_last_inner[0] ? cstr_sample(g_last_inner) : @"<none>",
            [NSString stringWithFormat:@"cb=%d last=%@ scanmiss=%d probe=%@",
                g_cb_count,
                g_last_uuid[0] ? @(g_last_uuid) : @"<none>",
                g_scan_missed,
                g_probe_name[0] ? @(g_probe_name) : @"<none>"]];
        [now writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if (loud) {
            NSLog(@"[wxkeep-runtime] loaded, marker at %@, mr2=%d", marker, g_hook_installed);
        }
    }
}

// ---- 周期证据回写 ----
// marker 只在启动路径写的话，fires/hits/zero 永远是启动快照（≈0）——
// 「读 marker 即得改写证据」需要会话内的周期刷新。30s 一次 Foundation
// 写在后台队列，与武装路径的 marker 回写同上下文模型；进程生命周期内
// 常驻（微信退出即随进程消失，marker 留最后一次快照）。
static void start_evidence_timer(void) {
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    if (!timer) return;
    dispatch_source_set_timer(timer,
                              dispatch_walltime(NULL, (int64_t)30 * NSEC_PER_SEC),
                              (int64_t)30 * NSEC_PER_SEC, 0);
    dispatch_source_set_event_handler(timer, ^{ write_marker_ex(0); });
    dispatch_resume(timer);
    // 刻意被静态引用持有、永不 cancel：source→handler→全局函数 无环，
    // 常驻即设计（进程内一次性安装）。
    static dispatch_source_t keep;
    keep = timer;
}

// ---- 迟到装载兜底 ----
// 实证（2026-09-18，macOS 15 dyld4）：wechat.dylib 由壳程序延迟装载且
// **不经过 add_image 通知**（回调 1000+ 次无它，但它确在 dyld 镜像表中，
// index 209 >> 本 dylib 的 2）。因此除回调外增加两个兜底触发源：
//   a) NSApplicationDidFinishLaunchingNotification —— UI 就绪即 wechat.dylib
//      已完全初始化，此时刻挂 inline hook 是各注入框架的标准时机；
//   b) 有界轮询（30 次 × 500ms，全局队列）—— 非 UI 辅助进程兜底。
// g_arm_done CAS 保证只装一次；扫到即装，无 tap 亦无害。
static uintptr_t find_wechat_base_by_region_scan(void);
static int probe_match_target(uintptr_t addr);

static uintptr_t find_wechat_base_by_region_scan(void) {
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = 1;
    for (;;) {
        mach_vm_size_t size = 0;
        struct vm_region_basic_info_64 bi;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        if (mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&bi, &cnt, &obj) != KERN_SUCCESS)
            break;
        if (obj != MACH_PORT_NULL) mach_port_deallocate(task, obj);
        // protection 只是启发式预筛（缩小探针范围）；可访问性的唯一权威
        // 是 probe_match_target 的 mach 读探针——保护位报告与真实可访问性
        // 可能不一致（0x7ff800000000 实测），直解引用在任何分支都禁止。
        if ((bi.protection & VM_PROT_READ)
            && (bi.max_protection & VM_PROT_EXECUTE) && size >= 0x4000000
            && (addr & 0xfff) == 0
            && probe_match_target((uintptr_t)addr)) {
            return (uintptr_t)addr;
        }
        addr += size;
        if (addr < size) break;    // 回绕保护
    }
    return 0;
}

// 区域扫描的安全探针：不直解引用，用 mach_vm_read_overwrite 把
// header+load commands 拷进本地缓冲再比对。实证（2026-09-19 真机崩溃
// WeChat-2026-09-19-010934.ips）：共享缓存孔洞 0x7ff800000000 的
// vm_region basic_info 报告 protection 含 R，但访问即 KERN_INVALID_
// ADDRESS——「查当前 protection 可读」的防线在该区域不成立，唯有
// mach 读探针本身是安全的（失败返回错误码，不崩）。
static int probe_match_target(uintptr_t addr) {
    mach_port_t task = mach_task_self();
    uint8_t hdr[32];
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(task, (mach_vm_address_t)addr, sizeof(hdr),
                               (mach_vm_address_t)(unsigned long)hdr, &got) != KERN_SUCCESS
        || got != sizeof(hdr)) {
        return 0;
    }
    const struct mach_header_64 *h = (const struct mach_header_64 *)hdr;
    if (h->magic != MH_MAGIC_64 || h->sizeofcmds > 0x40000) return 0;
    uint32_t len = (uint32_t)(sizeof(hdr) + h->sizeofcmds);
    uint8_t *buf = malloc(len);
    if (!buf) return 0;
    int hit = 0;
    if (mach_vm_read_overwrite(task, (mach_vm_address_t)addr, len,
                               (mach_vm_address_t)(unsigned long)buf, &got) == KERN_SUCCESS
        && got == len) {
        hit = match_target((const struct mach_header_64 *)buf) != NULL;
    }
    free(buf);
    return hit;
}

static void scan_and_arm(void) {
    if (g_hook_installed) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (match_target((const struct mach_header_64 *)mh) != NULL) {
            try_hook_image((const struct mach_header_64 *)mh,
                           _dyld_get_image_vmaddr_slide(i));
            return;
        }
    }
    // dyld 镜像表对本构建的 wechat.dylib 不可见（壳程序手动映射，绕过
    // add_image 通知，2026-09-18 实测 cb=1000+ 无它）——退化为纯内存扫描:
    // 找 ≥64MB 的可执行区域并验证 Mach-O header UUID。
    uintptr_t base = find_wechat_base_by_region_scan();
    if (base) {
        strlcpy(g_probe_name, "region-scan-found", sizeof(g_probe_name));
        try_hook_image((const struct mach_header_64 *)base, 0);
    }
}

static void arm_late(void) {
    scan_and_arm();
    if (g_hook_installed) {
        write_marker();   // 覆盖构造器期的 marker-only（时序假象防御）
        return;
    }
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    if (!timer) return;
    __block int ticks = 0;
    dispatch_source_set_timer(timer, dispatch_walltime(NULL, 0),
                              (int64_t)500 * NSEC_PER_MSEC, 0);
    // __weak 打破 retain cycle：source 强持有 handler block，block 若强捕
    // timer 则成环（ARC 下一次性泄漏；M-R2 安装失败时每 500ms 重扫的
    // handler 会随 source 一起常驻）。resumed 态的 source 由 libdispatch
    // 持有、handler 执行期间必然存活，weak 取值安全；cancel 前仍加 nil 门
    // （dispatch_source_cancel(NULL) 在 libdispatch 显式 CRASH）。
    __weak dispatch_source_t weakTimer = timer;
    dispatch_source_set_event_handler(timer, ^{
        scan_and_arm();
        if (g_hook_installed || ++ticks >= 30) {
            if (g_hook_installed) write_marker();
            if (weakTimer) dispatch_source_cancel(weakTimer);
        }
    });
    dispatch_resume(timer);
}

// 宿主门：整个机制只在微信主程序里运行。dylib 一旦被其他进程链接
// （单测 runner 就是活例），构造器里的全地址空间扫描、500ms 定时器、
// marker 写盘对宿主只有风险没有收益——还可能把 `runtime status` 的
// 「已加载」判定污染成假阳性。
static int host_is_wechat(void) {
    const char *exe = _dyld_get_image_name(0);   // index 0 = 主程序
    if (!exe) return 0;
    const char *slash = strrchr(exe, '/');
    const char *base = slash ? slash + 1 : exe;
    return strcmp(base, "WeChat") == 0;
}

__attribute__((constructor)) static void wxkeep_runtime_init(void) {
    if (!host_is_wechat()) return;   // 非微信宿主：零副作用（测试缝为直接函数调用，不受影响）
    load_config();
    // 既有镜像线性扫描（wechat.dylib 可能早于本 dylib 加载）——按地址表直查
    {
        uint32_t n = _dyld_image_count();
        int found = 0;
        for (uint32_t i = 0; i < n; i++) {
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (match_target((const struct mach_header_64 *)mh) != NULL) {
                found = 1;
                strlcpy(g_probe_name, "scan-saw-wechat-uuid", sizeof(g_probe_name));
                try_hook_image((const struct mach_header_64 *)mh,
                               _dyld_get_image_vmaddr_slide(i));
                break;
            }
        }
        if (!found) g_scan_missed = 1;
    }
    // 后续加载兜底（同步回调，无异步时序）——对本构建的 wechat.dylib
    // 实证不触发，见 arm_late 注释；保留以覆盖其他正常装载路径。
    _dyld_register_func_for_add_image(on_image_add);

    [[NSNotificationCenter defaultCenter]
        addObserverForName:NSApplicationDidFinishLaunchingNotification
                    object:nil queue:nil
                usingBlock:^(NSNotification *note){ arm_late(); }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                   ^{ arm_late(); });

    start_evidence_timer();   // fires/hits/zero 会话内周期回写（marker 证据闭环）
    write_marker();
}

// ---------------------------------------------------------------------------
// 测试缝
// ---------------------------------------------------------------------------

/// UUID 门回归缝：对调用方构造的伪 mach_header_64（含 LC_UUID）执行一次
/// 身份判定。锁死「比对逻辑恒假 → hook 永不安装」这类静默失效。
int wxkeep_runtime_test_uuid_match(const void *hdr) {
    return uuid_matches((const struct mach_header_64 *)hdr, kTarget270099_uuid);
}

/// rewrite_self 策略缝：测试里切换自发撤回门的开关。
void wxkeep_runtime_test_set_policy(int rewrite_self) {
    g_rewrite_self = rewrite_self;
}

/// hooks 表解析缝：喂 JSON 字节，解析进 g_ext_hooks（重置旧态保证测试
/// 隔离），返回被接受的行数——0 表示外部表不启用（回落内置表）。
int wxkeep_runtime_test_parse_hooks(const char *json, unsigned long json_len) {
    memset(g_ext_hooks, 0, sizeof(g_ext_hooks));
    g_ext_hook_count = 0;
    if (json_len == 0 || json_len > (1 << 20)) return -1;
    NSData *data = [NSData dataWithBytes:json length:json_len];
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![obj isKindOfClass:[NSDictionary class]]) return -1;
    int n = 0;
    @autoreleasepool {
        load_hooks_from(obj);
        n = g_ext_hook_count;
    }
    return n;
}

/// 外部表行读取缝：拷出第 idx 行的核心字段（越界返回 -1）。
int wxkeep_runtime_test_hook_row(int idx, unsigned long *hook_off,
                                 unsigned long *msg_arg, unsigned long *xml_sso_off,
                                 int *is_arm64, int *expected_len) {
    if (idx < 0 || idx >= g_ext_hook_count) return -1;
    const hook_target_t *t = &g_ext_hooks[idx];
    *hook_off = (unsigned long)t->hook_off;
    *msg_arg = (unsigned long)t->msg_arg;
    *xml_sso_off = (unsigned long)t->xml_sso_off;
    *is_arm64 = t->is_arm64;
    *expected_len = t->expected_len;
    return 0;
}

/// 通用 keeptip 缝：对 XML 缓冲执行 <newmsgid> 数字清零（等长），
/// 返回清零的数字个数。锁死 v1 语义的 runtime 化实现。
int wxkeep_runtime_test_zero(unsigned char *data, unsigned long len) {
    return zero_newmsgid_digits(data, (uint64_t)len);
}

/// 配置文件端到端缝：按生产路径（dictionaryWithContentsOfFile 的 plist
/// 语义）读取任意路径的配置文件并应用，返回接受的 hooks 行数（-1 =
/// 文件不可解析）。锁死「CLI 写 JSON / dylib 读 plist」这类跨格式静默
/// 回落——应用前重置 tip/策略/hooks 保证测试确定性。
int wxkeep_runtime_test_load_config_file(const char *path) {
    if (!path) return -1;
    @autoreleasepool {
        NSString *p = [NSString stringWithUTF8String:path];
        NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:p];
        if (![cfg isKindOfClass:[NSDictionary class]]) return -1;
        g_tip_text[0] = 0; g_tip_len = 0; g_rewrite_self = 0;
        memset(g_ext_hooks, 0, sizeof(g_ext_hooks));
        g_ext_hook_count = 0;
        apply_config_dict(cfg);
        return g_ext_hook_count;
    }
}

/// 当前生效文案的字节长度（load_config_file 缝的 tip 断言用）。
int wxkeep_runtime_test_tip_len(void) {
    return (int)g_tip_len;
}

long wxkeep_runtime_test_rewrite(unsigned char *data, unsigned long data_len,
                                 const char *tip, unsigned long tip_len) {
    uint8_t sso[24];
    memset(sso, 0, sizeof(sso));
    sso[0] = 1;                                   // 长串形态
    uint64_t size = data_len;
    memcpy(sso + 8, &size, 8);
    uint8_t *ptr = data;
    memcpy(sso + 16, &ptr, 8);
    char saved_buf[sizeof(g_tip_text)];
    size_t saved_len = g_tip_len;
    memcpy(saved_buf, g_tip_text, sizeof(saved_buf));
    if (tip_len >= sizeof(g_tip_text)) return -1;
    memcpy(g_tip_text, tip, tip_len);
    g_tip_text[tip_len] = 0;
    g_tip_len = tip_len;
    int r = rewrite_replacemsg_inner(sso);
    g_tip_len = saved_len;
    memcpy(g_tip_text, saved_buf, sizeof(saved_buf));
    if (r != 1) return -1;
    // 返回命中标签的内文长度（改写后前 tip_len 字节 = 文案，其余为空格填充）
    for (int t = 0; t < 2; t++) {
        const char *ot = t == 0 ? kContentOpen : kReplaceOpen;
        const char *ct = t == 0 ? kContentClose : kReplaceClose;
        uint8_t *open = find_bytes(data, size, ot, strlen(ot));
        if (!open) continue;
        uint8_t *inner = open + strlen(ot);
        if (size - (uint64_t)(inner - data) >= kCdataLen
            && memcmp(inner, kCdataOpen, kCdataLen) == 0) {
            inner += kCdataLen;
        }
        uint8_t *close = find_bytes(inner, size - (uint64_t)(inner - data),
                                    ct, strlen(ct));
        if (close) {
            long n = (long)(close - inner);
            if (n >= 3 && memcmp(close - 3, "]]>", 3) == 0) n -= 3;
            return n;
        }
    }
    return -1;
}
