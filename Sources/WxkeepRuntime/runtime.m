#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/thread_act.h>
#import <mach-o/loader.h>
#import <dlfcn.h>

@class NSString;
static NSDictionary *read_runtime_config_at(NSString **usedPath);
#import <sys/mman.h>
#import <pthread.h>
#ifndef MAP_JIT
#define MAP_JIT 0x800
#endif
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
// expected 长度匹配 arch、arm64 序言无 PC 相对编码）才被接受；可选的
// 函数级身份字段（func_size/anchor，77 续——见 hook_target_t 注释）
// 带即启用安装期二次核对。
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
    // 函数级身份门（77 续，2026-10-26）：序言门对「同序言不同函数」无分辨力
    // ——10-03 自更新（同 UUID 新字节）把 270100 arm64 0x4bc4d34 换成了
    // 另一个同家族序言的函数，hook 破坏消息解析（台账 T4 推进轮二实证）。
    // 两字段均可选：旧行不带则不启用该门（向后兼容）；带则 install 期按
    // 镜像自身元数据二次核对，不符即拒装（宁可不挂也不挂错）。
    uint32_t func_size;         // 门①：目标函数起点到 LC_FUNCTION_STARTS 下一
                                // 函数起点的距离（派生期布局指纹；与运行时
                                // 镜像的同一距离比对——重编译挪动函数即失配）
    uint8_t has_func_size;
    uint32_t anchor_va;         // 门②：锚点在切片内的 VM 偏移（与 hook_off 同基准）
    uint8_t anchor[64];         //     锚点期望字节（hex ≤64B；建议取目标函数
                                //     体内 distinctive 指令序列或其引用常量）
    uint8_t anchor_len;
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

// 44 = 4.1.15 全家族（除从未发布的 270087/270092）+ 270131-270135 × 双架构
// （2026-10-20 补齐 270101/270102 后的 knownHooks 现量）；128 留 update-data
// 分发新构建行的余量（越限行被静默丢弃——parse 循环的 n >= 上限 break，
// 丢的是追加在尾部的最新构建行：容量必须显著大于 knownHooks 现量，
// RuntimeHookTests 有 128 行全收的容量回归锁）。
enum { kMaxExtHooks = 128 };
static hook_target_t g_ext_hooks[kMaxExtHooks];
static int g_ext_hook_count;

// ---------------------------------------------------------------------------
// 配置（Application Support/wxkeep/runtime.json）
// ---------------------------------------------------------------------------

// tip 双缓冲（77 续㉘ 热重载）：写方填非活动槽后原子翻转，读方取槽即用
// ——槽内容写完才可见，热重载撕裂窗为零。写频=配置变更，读频=撤回命中。
static char g_tip_store[2][128];
static size_t g_tip_store_len[2];
static volatile int g_tip_which;
static const char *tip_text_active(void) { return g_tip_store[g_tip_which]; }
static size_t tip_len_active(void) { return g_tip_store_len[g_tip_which]; }
static void tip_store_write(const char *src, size_t len) {
    if (len > sizeof(g_tip_store[0]) - 1) len = sizeof(g_tip_store[0]) - 1;
    int nxt = 1 - g_tip_which;
    memcpy(g_tip_store[nxt], src, len);
    g_tip_store[nxt][len] = 0;
    g_tip_store_len[nxt] = len;
    __atomic_store_n(&g_tip_which, nxt, __ATOMIC_RELEASE);
}
// 自发撤回判别（77 续㉘，T5 F1 修复）：撤回 XML 的提示内文以「你撤回」
// 起头 = 本机自发——keep/zero 门对其放行原生行为（本地删除+原生提示），
// 不再误伤（T5 实测：清零自发 XML 使提示落「暂不支持该内容」占位）。
static const char kSelfNeedle[] = "\xe4\xbd\xa0\xe6\x92\xa4\xe5\x9b\x9e";  // “你撤回”
static int g_self_skips;
static int g_rewrite_self;         // 自发撤回提示是否也改写（默认 0=不改）
static int g_rewrite_hits;         // 撤回 needle 命中计数（含自发跳过/超长放弃）
static int g_rewrite_fires;        // 实际完成改写的计数（验证肉眼化的证据面）
static int g_keep_message = 1;     // 通用 keeptip：parse 前清零 XML newmsgid（默认开）
static int g_zero_msgid;           // T4 实验（2026-10-25）：清零 <msgid>（本地号）——
                                   // 裁决原生删除键与 tip 锚是否同字段（newmsgid vs msgid）
static int g_allow_runtime_prologue;  // 序言门自适应（默认关）：270100 的 10-03 自更新
                                   // 后 libwxld 壳改写 parse 入口运行时字节（磁盘=expected
                                   // 而运行时≠，实证 2026-10-26 真机 status=11）——开时
                                   // memcmp 失败可接受运行时字节，但仍必须过 arm64 可换址
                                   // 编码门/x64 转移编码门。威胁模型变化：expected 从「字
                                   // 节锁」降为「构建 UUID 锁+编码锁」，RUNTIME-DESIGN
                                   // 72·L3④ 分析需按此更新。
static int g_zero_fires;           // 清零计数（newmsgid 与 msgid 共用，配置互斥使用）
static char g_last_fired[96];      // 最后一次改写后的内文前 95B（渲染问题取证）
static char g_last_inner[96];      // 最后一次 needle 命中时的原始内文前 95B
static int g_hook_installed;
// 诊断（marker 回写）——独立 bit 位形（77 续修复）。旧编码 kStInstallFail=3
// 是「值」不是位，与 uuid(1)+prologue(2) 的组合同形：status=11 曾被误读为
// 「回调+序言门」排障方向，实为 callback(8)+install-fail(3)——77 轮靠
// istep/errno 才纠偏（台账 T4）。现改为互不重叠的位（marker 带 enc=2 标记
// 新编码；CLI 判读见 WxkeepCLI.runtimeStatusFlags，mr2= 字段是武装态权威、
// 不受位形影响）：
//   1=UUID 不匹配 2=序言不匹配 4=安装失败(mmap/mprotect/vm_remap)
//   8=已武装 16=add_image 回调已触发 32=扫描未命中 64=函数身份门不符
static int g_hook_status;
enum { kStIdle = 0, kStUuidMismatch = 1, kStPrologueMismatch = 2,
       kStInstallFail = 4, kStArmed = 8, kStCallbackBit = 16,
       kStScanMissed = 32, kStFuncMismatch = 64 };
static char g_probe_name[96];   // 构造器期匹配到的镜像名样本（诊断）
static int uuid_matches(const struct mach_header_64 *hdr, const char *want,
                        size_t avail);

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
static int g_arm_via_slot;            // T6：经入口补丁 SLOT 数据写武装（vs 旧进程内写阶梯）
static const char kTarget270099_uuid[] = "97e21436-abda-3b79-bec0-ef2653c6b423";
static char g_last_uuid[40];     // 回调收到的最后一个镜像 UUID
static uint8_t g_saved_prologue[16];  // T4 排障：install_hook 序言比对现场快照
static int g_saved_prologue_valid;
static int g_install_errno;          // T4 排障：install 失败的 errno 与步骤
static int g_install_step;
static volatile int g_stub_alive = -1;   // T4 排障：入口 stub 在位判定（-1=未知）
                                     // 1=stub 在位 0=已被改写（壳吞 stub 的直接证据）
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
    return read_runtime_config_at(NULL);
}

/// 带路径诊断的变体（95/97 轮：配置三路陷阱的远程判读面）。
static NSDictionary *read_runtime_config_at(NSString **usedPath) {
    NSString *group = groupContainerConfigPath();
    if (group) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:group];
        if ([d isKindOfClass:[NSDictionary class]]) {
            if (usedPath) *usedPath = group;
            return d;
        }
    }
    NSString *legacy = runtimeConfigPath();
    if (legacy) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:legacy];
        if ([d isKindOfClass:[NSDictionary class]]) {
            if (usedPath) *usedPath = legacy;
            return d;
        }
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

/// 严格 hex 整数（可选 0x 前缀，值域 ≤0xFFFFFFFF）——strtoull 会静默吞
/// 尾部垃圾，身份门字段（anchor_va）不能接受半合法输入。非法返回 0。
static int parse_hex_u32(const char *s, uint32_t *out) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!s[0]) return 0;
    uint64_t v = 0;
    for (; *s; s++) {
        int n = hex_nibble(*s);
        if (n < 0) return 0;
        v = (v << 4) | (uint64_t)n;
        if (v > 0xFFFFFFFFULL) return 0;
    }
    *out = (uint32_t)v;
    return 1;
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

/// x64 序言可换址性（72·L3④，启发式字节扫描）：蹦床把入口 12B 换址重放，
/// 含 PC 相对转移编码（E8/E9 call/jmp rel32、EB/7x 短转移、0F 8x jcc
/// rel32、FF /2 /4 间接转移）的字节序列换址后跳向错误目标——runtime.json
/// 在微信自己的 App Group 容器（腾讯可写，见 RUNTIME-DESIGN 信任边界节），
/// 行作者可自选 expected，这道门把「换址破坏控制流」的随意性压到需要
/// 精心构造且绕过字节扫描。启发式非反汇编：零散命中同值字节会误拒——
/// 按「宁可不挂也不挂错」接受（家族序言 554889E54157415641554154 实测
/// 不含这些字节；误拒的可见后果是 hook 不武装，status 可诊断）。
static int x64_prologue_relocatable(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] == 0xE8 || p[i] == 0xE9 || p[i] == 0xEB) return 0;
        if (p[i] >= 0x70 && p[i] <= 0x7F) return 0;            // jcc rel8
        if (p[i] == 0x0F && i + 1 < n
            && p[i + 1] >= 0x80 && p[i + 1] <= 0x8F) return 0; // jcc rel32
        if (p[i] == 0xFF && i + 1 < n
            && ((p[i + 1] & 0x38) == 0x10 || (p[i + 1] & 0x38) == 0x20)) return 0; // call/jmp /2 /4
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
    // xml_sso_off 必须显式给出：它决定 hook 从哪个地址读 SSO 头，缺省值
    // （旧 wrapper 模型的 0x130）在 parse 直挂语义下是错误偏移——缺字段
    // 的行按「宁可不挂也不挂错」整行拒绝，而不是静默读错位置。
    if (!soff) return 0;
    out->xml_sso_off = soff.unsignedLongValue;
    if (out->msg_arg > 5 || out->xml_sso_off > 0x1000) return 0;
    out->is_arm64 = [arch isEqualToString:@"arm64"];
    out->expected_len = out->is_arm64 ? 16 : 12;
    if (parse_hex(exp.UTF8String, out->expected, sizeof(out->expected)) != out->expected_len) {
        return 0;
    }
    if (out->is_arm64 && !arm64_prologue_relocatable(out->expected, 16)) return 0;
    if (!out->is_arm64 && !x64_prologue_relocatable(out->expected, 12)) return 0;
    // 函数级身份门字段（可选）：出现即解析并校验，坏值整行拒绝（与既有
    // 门的哲学一致）——半合法的 func_size/anchor 比没有更糟（假身份门）。
    // 旧行不带这些键 → 全部保持 0，install 期不启用该门（向后兼容）。
    NSNumber *fsz = [row[@"func_size"] isKindOfClass:[NSNumber class]] ? row[@"func_size"] : nil;
    if (fsz) {
        unsigned long v = fsz.unsignedLongValue;
        // 函数距离上界 2MB：wechat.dylib 最大函数 ~0x7e0B 量级，2MB 是
        // 宽松界——防的是垃圾值（负数/越界）不是精确性
        if (v == 0 || v > (1UL << 21)) return 0;
        out->func_size = (uint32_t)v;
        out->has_func_size = 1;
    }
    NSString *ava = [row[@"anchor_va"] isKindOfClass:[NSString class]] ? row[@"anchor_va"] : nil;
    NSString *aby = [row[@"anchor_bytes"] isKindOfClass:[NSString class]] ? row[@"anchor_bytes"] : nil;
    if (ava || aby) {
        // 成对出现：半个锚点字段 = 行作者笔误，拒绝
        if (!(ava && aby)) return 0;
        if (!parse_hex_u32(ava.UTF8String, &out->anchor_va)) return 0;
        size_t n = parse_hex(aby.UTF8String, out->anchor, sizeof(out->anchor));
        if (n == 0) return 0;
        out->anchor_len = (uint8_t)n;
    }
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
/// 否则查内置表。返回命中行，未命中返回 NULL。`avail` = hdr 起可读字节
/// 数（缓冲式调用传真实长度；dyld 已装载镜像传 SIZE_MAX——内核映射 +
/// dyld 自身解析过头部，sizeofcmds 与映射自洽）。
static const hook_target_t *match_target(const struct mach_header_64 *hdr,
                                         size_t avail) {
    if (g_ext_hook_count > 0) {
        for (int i = 0; i < g_ext_hook_count; i++) {
            if (uuid_matches(hdr, g_ext_hooks[i].uuid, avail)) return &g_ext_hooks[i];
        }
        return NULL;
    }
    for (size_t i = 0; i < kBuiltinCount; i++) {
        if (uuid_matches(hdr, kBuiltins[i]->uuid, avail)) return kBuiltins[i];
    }
    return NULL;
}

// 策略键应用（77 续㉘ 从 apply_config_dict 拆出）：tip 双缓冲写入 + 四个
// 开关。可被热重载安全调用（见 maybe_reload_config）——不触碰 hooks 表。
static void apply_policy_dict(NSDictionary *cfg) {
    NSString *text = cfg[@"tip_text"];
    if ([text isKindOfClass:[NSString class]] && text.length > 0) {
        NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
        if (data.length > 0 && data.length < sizeof(g_tip_store[0])) {
            // 文案最终嵌入 XML 文本节点：剥掉会破坏标签/实体的 < > & 三种
            // 字符（长度随之收缩），其余（含 emoji/引号）原样保留。
            // 服务端 replacemsg 含昵称，内文普遍 ≥30B，128B 上限足够。
            const uint8_t *src = data.bytes;
            char staged[sizeof(g_tip_store[0])];
            size_t o = 0;
            for (size_t i = 0; i < data.length; i++) {
                if (src[i] == '<' || src[i] == '>' || src[i] == '&') continue;
                if (o >= sizeof(staged) - 1) break;
                staged[o++] = (char)src[i];
            }
            tip_store_write(staged, o);
        }
    }
    // 自发撤回（“你撤回了一条消息”）默认不改写——自己的撤回保持诚实反馈；
    // 置 true 才连自发提示一起换文案。
    g_rewrite_self = [cfg[@"rewrite_self"] boolValue];
    // keep_message 缺省即开（runtime hook 的核心价值）；显式 false 关闭
    id km = cfg[@"keep_message"];
    g_keep_message = (km == nil) ? 1 : [km boolValue];
    // zero_msgid：T4 实验键（默认关，77 续㉑ 后仅为诊断面）
    id zm = cfg[@"zero_msgid"];
    g_zero_msgid = (zm == nil) ? 0 : [zm boolValue];
    // allow_runtime_prologue：壳改写入口后的自适应开关（默认关，见全局注释）
    id ar = cfg[@"allow_runtime_prologue"];
    g_allow_runtime_prologue = (ar == nil) ? 0 : [ar boolValue];
}

static void apply_config_dict(NSDictionary *cfg) {
    apply_policy_dict(cfg);
    load_hooks_from(cfg);
}

static double g_cfg_stamp;   // 已应用配置文件的双路径 mtime 之和（热重载探测）
static uint64_t g_cfg_hash;  // 已应用配置文件内容的 FNV-1a 64（cfg_hash 告警面，
                             // V4 需求 3：mtime 可被 touch -r 还原，内容哈希不能）

// 配置内容哈希：对生效路径（group 优先/legacy 回落，同 read_runtime_config
// 选径）的原始字节 FNV-1a 64。文件缺失/不可读 = 0（与未装载区分开靠
// marker 的 cfg= 戳）。只做身份指纹，不做完整性安全（算法无密钥）。
static uint64_t fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t config_content_hash(void) {
    // 与 read_runtime_config 同选径语义：group 优先、读失败回落 legacy
    // （只构造不校验时 group 路径常在但文件未必在——不能就此返回 0）。
    NSString *group = groupContainerConfigPath();
    if (group) {
        NSData *d = [NSData dataWithContentsOfFile:group];
        if (d) return fnv1a64(d.bytes, d.length);
    }
    NSString *legacy = runtimeConfigPath();
    if (legacy) {
        NSData *d = [NSData dataWithContentsOfFile:legacy];
        if (d) return fnv1a64(d.bytes, d.length);
    }
    return 0;
}

// 双路径戳（77 续㉘补丁）：生产装载序 = group 优先、legacy（沙盒容器内
// 展开）回落——只盯 group 会让回落位的变更永远探测不到（T4 在案场景：
// 沙盒 group 写被拒，marker/配置全走 legacy）。两路径 mtime 求和即可：
// 任一变更都会改变和值；重读仍走 read_runtime_config 的正式选径。
static double config_stamp(NSString *path) {
    NSDictionary *attr = [[NSFileManager defaultManager]
        attributesOfItemAtPath:path error:nil];
    return [attr fileModificationDate].timeIntervalSince1970;
}

static double config_stamps_both(void) {
    double sum = 0;
    NSString *g = groupContainerConfigPath();
    if (g) sum += config_stamp(g);
    NSString *l = runtimeConfigPath();
    if (l) sum += config_stamp(l);
    return sum;
}

// 热重载（77 续㉘，T5 对照轮教训：配置只在进程启动读一次，改键必须重启
// 进程才能生效——账号切换不重启进程的实测踩坑）。30s 证据定时器顺带探测
// mtime：变化则重读并热应用**策略键**（tip/四开关）；hooks 表不热换
// （换表仍需重启——武装中的地址行换血没有安全序）。坏文件也先立戳，
// 不再每 tick 重读。
static void maybe_reload_config(void) {
    @autoreleasepool {
        NSString *p = groupContainerConfigPath();
        if (!p) p = runtimeConfigPath();
        if (!p) return;
        double st = config_stamps_both();
        if (st == g_cfg_stamp) return;
        NSDictionary *cfg = read_runtime_config();   // 正式选径（group 优先/legacy 回落）
        g_cfg_stamp = st;                             // 先立戳：坏文件不再每 tick 重读
        if ([cfg isKindOfClass:[NSDictionary class]]) apply_policy_dict(cfg);
        g_cfg_hash = config_content_hash();
    }
}

static void load_config(void) {
    NSDictionary *cfg = read_runtime_config();
    if ([cfg isKindOfClass:[NSDictionary class]]) apply_config_dict(cfg);
    g_cfg_stamp = config_stamps_both();
    g_cfg_hash = config_content_hash();
}

// ---------------------------------------------------------------------------
// 微信串对象（77 续⑧ per-arch 布局，读取统一走 sso_head）：
//   x86_64（drive17/22 实测）：byte0 奇 = 长串；size@+8；ptr@+0x10；短串数据在 +1
//   arm64（77 续⑧ 静态实证 + T4 取证）：[0x17] 符号负 = 长串；size@+8；ptr@+0
//   —— hook 只读头部（判长/size/ptr），改写发生在串指向的
//      XML 缓冲内部（等长替换），串结构与分配器零接触。
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
    char eff[128 + 64];
    size_t eff_len;
    const char *tip_now = tip_text_active();
    size_t tip_now_len = tip_len_active();
    if (bytes_contain(tip_now, tip_now_len, kFromPh, kFromPhLen)) {
        const uint8_t *from = NULL;
        size_t from_len = extract_from(inner, inner_len, &from);
        eff_len = expand_tip(tip_now, tip_now_len, from, from_len,
                             eff, sizeof(eff));
    } else {
        memcpy(eff, tip_now, tip_now_len);
        eff_len = tip_now_len;
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

/// <tag> 的数字等长清零（'1'-'9' → '0'）——parse 读到 0 → 下游按该键定位失败。
/// 返回清零的数字个数（0 = 无该 tag 或已是 0）。
static int zero_tag_digits(uint8_t *buf, uint64_t size, const char *tag, uint64_t taglen) {
    uint8_t *p = find_bytes(buf, size, tag, taglen);
    if (!p) return 0;
    uint64_t i = (uint64_t)(p - buf) + taglen;
    int n = 0;
    while (i < size && buf[i] != '<') {
        if (buf[i] >= '1' && buf[i] <= '9') { buf[i] = '0'; n++; }
        else if (buf[i] != '0') break;   // 非数字（空白/异常形态）即停
        i++;
    }
    return n;
}

/// 通用 keeptip 核心（0.2.x 降维实现）：不改任何指令，直接把 XML 里
/// <newmsgid> 的数字等长清零（'1'-'9' → '0'）——parse 读到 0 → 撤回删除
/// 按目标查不到 → 原消息保留（v1 语义），提示文本不受影响。不依赖任何
/// 指令地址：hook 能武装的构建即工作，跨构建通用。
/// 返回清零的数字个数（0 = 无 <newmsgid> 或已是 0）。
static int zero_newmsgid_digits(uint8_t *buf, uint64_t size) {
    return zero_tag_digits(buf, size, "<newmsgid>", sizeof("<newmsgid>") - 1);
}

// ---------------------------------------------------------------------------
// 串对象头读取（per-arch 布局，77 续⑧——T4 x1 取证 + 参考切片反汇编双证）：
//   x86_64（标准 libc++，drive17/22 实测）：byte0 奇 = 长串；size@+8；ptr@+0x10
//   arm64（变体，0x4a7d6ac 形态 + 0x17=+0x10 qword MSB 实证）：
//         [0x17] 符号负 = 长串；size@+8；ptr@+0（[0x10] = cap|flag）
//   两架构 size 偏移相同、ptr 偏移与判长门不同——T4 实测 arm64 x1 =
//   {data=0x79b72ded80, size=0x338(824B XML)} 与变体布局逐字段吻合；
//   按 x64 模型读（ptr@+0x10 取到 cap）→ byte0 奇偶门永假 → hits=0。
// 仅长串路径被实证钉死（撤回 XML ≥60B 必为长串，短串一律跳过——与既有
// 语义一致）。短串 size 编码未验证，不做推断。
// ---------------------------------------------------------------------------

static int g_sso_layout_arm64;   // 安装时按行 arch 置位；测试缝可切换

/// 从串对象头提取 (size, ptr)。返回 1 = 长串且字段已填；0 = 非长串/放弃。
static int sso_head(const uint8_t *obj, uint64_t *size, uint8_t **ptr) {
    if (g_sso_layout_arm64) {
        if ((int8_t)obj[0x17] >= 0) return 0;   // 短串
        memcpy(size, obj + 8, 8);
        memcpy(ptr, obj, 8);
    } else {
        if (!(obj[0] & 1)) return 0;            // 短串
        memcpy(size, obj + 8, 8);
        memcpy(ptr, obj + 16, 8);
    }
    return 1;
}

static int rewrite_replacemsg_inner(uint8_t *sso) {
    uint64_t size;
    uint8_t *ptr;
    if (!sso_head(sso, &size, &ptr)) return 0;  // 短串装不下完整撤回 XML（≥60B）
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

// 调用约定透传：x64 前六整型参 rdi..r9 / arm64 前八整型参 x0..x7。arm64 走
// naked thunk 全寄存器保存/恢复（77 续⑨，见 revoke_wrapper_hook 注释）；x64
// 整型参寄存器全集恰好 6 个，C 形态即完整透传（hook 行契约 = 目标函数无 FP 参）。
static void *(*g_real_wrapper)(void *, void *, void *, void *, void *, void *);

static volatile int g_hook_calls;    // T4 排障：stub 调用计数（诊断）
static uint8_t g_arg1_head[24];      // T4 排障：最近一次 x1 头 24B（参数语义取证）
static volatile int g_arg1_valid;

/// hook 主体（与形态无关）：args = 目标函数整型参镜像（arm64 thunk 的
/// x0-x5 栈帧槽 / x64 调用点的局部数组）。只读 args[g_hook.msg_arg] 与
/// args[1]（诊断面）；一切改写只发生在 XML 缓冲内部。
// used：静态函数只被 naked thunk 的内联 asm 引用（C 侧零引用），无此标
// 注会被编译器当 dead code 删除 → 链接期 undefined symbol（实测）。
__attribute__((used)) static void revoke_hook_body(void *const *args) {
    g_hook_calls++;
    if (args[1] > (void *)0x10000) {
        memcpy((void *)g_arg1_head, args[1], sizeof(g_arg1_head));
        g_arg1_valid = 1;
    }
    // g_hook.target 以 acquire 读，与 install_hook 的 release 存储配对
    //（见安装侧注释）：acquire 命中非零值时，发布序在它之前的
    // msg_arg/xml_sso_off/saved/trampoline/g_real_wrapper 全部可见——
    // 杜绝「他核已见入口 stub 却读到陈旧 g_real_wrapper=NULL → 跳 0」
    // 的弱序窗口（arm64 弱内存序下 C 语义无保证的路径）。
    if (__atomic_load_n(&g_hook.target, __ATOMIC_ACQUIRE)
        && (tip_len_active() > 0 || g_keep_message)) {
        uint8_t *msg = (uint8_t *)args[g_hook.msg_arg];
        if (msg > (uint8_t *)0x10000) {
            uint8_t *sso = msg + g_hook.xml_sso_off;
            uint64_t size;
            uint8_t *ptr;
            if (sso_head(sso, &size, &ptr)) {   // per-arch 长串判定 + 字段提取
                if (size >= 32 && size <= (1 << 20) && ptr >= (uint8_t *)0x10000) {
                    if (find_bytes(ptr, size, kSelfNeedle, sizeof(kSelfNeedle) - 1)) {
                        g_self_skips++;   // 自发撤回：放行原生删除+原生提示（T5 F1）
                    } else {
                        if (g_keep_message) {
                            if (zero_newmsgid_digits(ptr, size) > 0) g_zero_fires++;
                        }
                        if (g_zero_msgid) {
                            if (zero_tag_digits(ptr, size, "<msgid>", sizeof("<msgid>") - 1) > 0)
                                g_zero_fires++;
                        }
                    }
                    if (tip_len_active() > 0) rewrite_replacemsg_inner(sso);
                }
            }
        }
    }
}

#if defined(__arm64__) || defined(__aarch64__)
// AAPCS64 全参透传 thunk（77 续⑨）：x0-x8（8 整型参 + sret 隐参）与
// q0-q7（FP/SIMD 参）全量保存/恢复；尾跳 g_real_wrapper 前 sp 已复原到
// 入口值，第 9+ 参的栈参原位可读。x16/x17 是 IP 草稿寄存器（非参数位）。
//
// 取代 6 参 C 透传形态的动机（结构保证，不是代码生成运气）：hook 行挂
// 的目标函数签名未知（77 续⑦ 已证 arm64 行的 x1 语义与 x64 行不同构），
// 6 参 C 形态下编译器可把 x6/x7/x8 当草稿寄存器清掉（Release 尾跳
// `ldr x6,…; br x6` 实测）、hook 体调用 memcpy 清 v0-v7——目标函数若有
// 更多整型参/FP 参即被破坏。77 续⑩ 静态裁决：现行 270100 arm64 目标
// 只消费 x0-x2（x3-x8 首触全为自身写、v0-v7 无入参读）——寄存器清坏
// 不是 T4 渲染破坏的机制，但透传仍是未来行（签名未知）的结构前提，
// 且透传契约测试抓出过手写帧三类槽重叠真 bug（见 MAINTAINING 77 续⑨）。
// x64 切片的整型参寄存器全集恰好 6 个，C 形态对整型参完整（见下方
// #else 分支）。
__attribute__((naked)) static void *revoke_wrapper_hook(void *a0, void *a1, void *a2,
                                                        void *a3, void *a4, void *a5) {
    // 帧布局（0xE0）：[0x00]=x29/x30；[0x10..0x3F]=x0..x5（args[0..5]，8B 槽）；
    // [0x50]=x8；[0x60..0xCF]=q0..q7（**16B 槽**）。槽间距三类踩坑都被透传
    // 测试当场抓出：q 按 8B 排 → q7 溢出帧砸调用方栈参 + q1/q2 互踩；
    // x8 放 0x48 → 撞 x6/x7 对的 x7 槽。
    __asm__ volatile(
        "stp x29, x30, [sp, #-0xe0]!\n"
        "stp x0, x1, [sp, #0x10]\n"     // args[0..5]（body 的 msg_arg 索引面）
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "str x8,      [sp, #0x50]\n"    // sret 隐参（C++ 按值返回大对象）
        "stp q0, q1, [sp, #0x60]\n"     // FP/SIMD 参 v0-v7（body 会经 memcpy 清掉）
        "stp q2, q3, [sp, #0x80]\n"
        "stp q4, q5, [sp, #0xa0]\n"
        "stp q6, q7, [sp, #0xc0]\n"
        "add x0, sp, #0x10\n"           // body(void *const *args)
        "bl _revoke_hook_body\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldr x8,      [sp, #0x50]\n"
        "ldp q0, q1, [sp, #0x60]\n"
        "ldp q2, q3, [sp, #0x80]\n"
        "ldp q4, q5, [sp, #0xa0]\n"
        "ldp q6, q7, [sp, #0xc0]\n"
        "ldp x29, x30, [sp], #0xe0\n"   // sp 复原（栈参原位）
        "adrp x16, _g_real_wrapper@PAGE\n"
        "ldr x16, [x16, _g_real_wrapper@PAGEOFF]\n"
        "br x16\n");
}
#else
// x86_64：整型参寄存器全集 = rdi/rsi/rdx/rcx/r8/r9 恰好 6 个，C 形态即
// 完整透传；栈参由编译器自然产生的尾跳保持 rsp 原值（x64 行实弹多年，
// parse(rdi,rsi,&ok) 无 FP 参/栈参）。
static void *revoke_wrapper_hook(void *a0, void *a1, void *a2,
                                 void *a3, void *a4, void *a5) {
    void *args[6] = {a0, a1, a2, a3, a4, a5};
    revoke_hook_body(args);
    return g_real_wrapper(a0, a1, a2, a3, a4, a5);
}
#endif

// ---------------------------------------------------------------------------
// 函数级身份核对（77 续）：install 期按镜像自身元数据（段表 +
// LC_FUNCTION_STARTS）核对行携带的 func_size/anchor。语义与 tools/machutil.py
// 同源（VA 换算走段表、function starts 基址 = __TEXT 段 vmaddr、0 增量条目
// 跳过），保证「派生时算的值」与「安装时核的值」是同一个定义。
//
// 两种上下文：dyld 已装载镜像（avail == SIZE_MAX，段 VM 布局成立，
// addr = hdr + (vmaddr - text_vmaddr) 即 slide 换算）/ 裸缓冲（测试缝；
// 文件布局成立，addr = hdr + fileoff）。生产路径只有前者。
// ---------------------------------------------------------------------------

enum { kMaxSegs = 16 };   // wechat.dylib 实际 ~6 段；越界段忽略（核对失败兜底）

typedef struct {
    const struct mach_header_64 *hdr;
    size_t avail;               // SIZE_MAX = 已装载镜像
    uint64_t text_vmaddr;       // 含 fileoff==0 的段（__TEXT）vmaddr = 布局原点
    int has_text;
    struct { uint64_t vmaddr, vmsize, fileoff, filesize; } segs[kMaxSegs];
    int nsegs;
    const uint8_t *fs_blob;     // LC_FUNCTION_STARTS blob（裸缓冲=借指针；装载镜像=堆副本）
    size_t fs_len;
    uint8_t *fs_copy;           // 装载镜像上下文的 mach 读副本（free 归属本结构）
} image_layout_t;

static void image_layout_free(image_layout_t *im) {
    free(im->fs_copy);
    im->fs_copy = NULL;
    im->fs_blob = NULL;
}

/// 命令区游走边界（与 uuid_matches 同规）：装载镜像信 dyld，裸缓冲信 avail。
static const uint8_t *layout_cmd_end(const struct mach_header_64 *hdr, size_t avail) {
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64)
                         + hdr->sizeofcmds;
    if (avail != (size_t)-1) {
        const uint8_t *hard = (const uint8_t *)hdr + avail;
        if (end > hard) end = hard;
    }
    return end;
}

/// 段表 + FUNCTION_STARTS 定位。返回 0 = 元数据不可用（缺 __TEXT 段 /
/// 命令区损坏）——调用方按「无法核对」处理。
static int image_layout(const struct mach_header_64 *hdr, size_t avail,
                        image_layout_t *out) {
    memset(out, 0, sizeof(*out));
    out->hdr = hdr;
    out->avail = avail;
    const uint8_t *base = (const uint8_t *)hdr;
    const uint8_t *p = base + sizeof(struct mach_header_64);
    const uint8_t *end = layout_cmd_end(hdr, avail);
    uint32_t fs_off = 0, fs_len = 0;
    int has_fs = 0;
    while (p + 8 <= end) {
        uint32_t cmd, size;
        memcpy(&cmd, p, 4); memcpy(&size, p + 4, 4);
        if (cmd == LC_SEGMENT_64 && size >= 72 && (size_t)(end - p) >= size) {
            uint64_t vmaddr, vmsize, fileoff, filesize;
            memcpy(&vmaddr, p + 24, 8);
            memcpy(&vmsize, p + 32, 8);
            memcpy(&fileoff, p + 40, 8);
            memcpy(&filesize, p + 48, 8);
            if (fileoff == 0 && !out->has_text) {
                out->text_vmaddr = vmaddr;
                out->has_text = 1;
            }
            if (out->nsegs < kMaxSegs) {
                out->segs[out->nsegs].vmaddr = vmaddr;
                out->segs[out->nsegs].vmsize = vmsize;
                out->segs[out->nsegs].fileoff = fileoff;
                out->segs[out->nsegs].filesize = filesize;
                out->nsegs++;
            }
        } else if (cmd == LC_FUNCTION_STARTS && size >= 16
                   && (size_t)(end - p) >= size) {
            memcpy(&fs_off, p + 8, 4);
            memcpy(&fs_len, p + 12, 4);
            has_fs = 1;
        }
        if (size < 8) break;   // 与 uuid_matches 同规：非法 cmdsize 停走
        p += size;
    }
    if (!out->has_text) return 0;
    if (has_fs && fs_len > 0 && fs_len <= (1u << 23)) {
        for (int i = 0; i < out->nsegs; i++) {
            uint64_t fo = out->segs[i].fileoff, fl = out->segs[i].filesize;
            if (!(fo <= fs_off && fs_off + fs_len <= fo + fl)) continue;
            if (avail == (size_t)-1) {
                // 装载镜像：直解引用 linkedit 尾部有未映射风险（SIGSEGV = 杀
                // 微信）——与 probe_match_target 同规走 mach 读探针，失败即
                // 元数据不可用（fail closed），不崩。
                mach_vm_address_t src = (mach_vm_address_t)base
                    + (out->segs[i].vmaddr - out->text_vmaddr) + (fs_off - fo);
                uint8_t *copy = malloc(fs_len);
                mach_vm_size_t got = 0;
                if (copy
                    && mach_vm_read_overwrite(mach_task_self(), src, fs_len,
                                              (mach_vm_address_t)(unsigned long)copy,
                                              &got) == KERN_SUCCESS
                    && got == fs_len) {
                    out->fs_copy = copy;
                    out->fs_blob = copy;
                    out->fs_len = fs_len;
                } else {
                    free(copy);
                }
            } else {
                // 裸缓冲 = 文件布局，blob 就在界内
                if ((size_t)fs_off + fs_len <= avail) {
                    out->fs_blob = base + fs_off;
                    out->fs_len = fs_len;
                }
            }
            break;
        }
    }
    return 1;
}

/// 门①：hook_off 处函数的「到下一函数起点的距离」== func_size？
/// 返回 1=匹配 0=失配（含 hook_off 非函数起点/是末条目无下一函数）。
/// 缺 FUNCTION_STARTS 元数据 → -1（无法核对，调用方决定拒或放——生产
/// install 路径按带字段即拒处理：宁可假阴性不可假阳性）。
static int func_size_matches(const image_layout_t *im, uint64_t hook_off,
                             uint32_t want) {
    if (!im->fs_blob) return -1;
    uint64_t want_va = im->text_vmaddr + hook_off;
    uint64_t cur = im->text_vmaddr;
    const uint8_t *p = im->fs_blob, *end = im->fs_blob + im->fs_len;
    while (p < end) {
        uint64_t delta = 0;
        int shift = 0, complete = 0;
        while (p < end) {
            uint8_t b = *p++;
            delta |= (uint64_t)(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) { complete = 1; break; }
        }
        if (!complete) break;             // 截断尾部：当作表尽
        if (delta == 0) continue;         // 0 增量 = 重复地址（machutil 同规）
        cur += delta;
        if (cur == want_va) {
            // 找到目标起点；下一非零增量条目给出大小
            uint64_t next = cur;
            while (p < end) {
                uint64_t d2 = 0;
                int sh2 = 0, ok = 0;
                while (p < end) {
                    uint8_t b = *p++;
                    d2 |= (uint64_t)(b & 0x7f) << sh2;
                    sh2 += 7;
                    if (!(b & 0x80)) { ok = 1; break; }
                }
                if (!ok) return 0;        // 表在目标后截断：无下一函数 → 失配
                if (d2 == 0) continue;
                next = cur + d2;
                break;
            }
            if (next == cur) return 0;    // 目标是末条目：无下一函数 → 失配
            return ((next - cur) == (uint64_t)want) ? 1 : 0;
        }
        if (cur > want_va) return 0;      // 起点表越过 hook_off：非函数起点
    }
    return 0;                             // 表内无 hook_off 起点
}

/// 门②：anchor_va（切片内 VM 偏移，与 hook_off 同基准）处字节 == anchor？
/// 返回 1=匹配 0=失配/越段（越段按失配处理——fail closed）。装载镜像走
/// mach 读探针（段表说可读 ≠ 真可读，直解引用在保护空段上会 SIGSEGV——
/// probe_match_target 的既有教训），裸缓冲直读。
static int anchor_matches(const image_layout_t *im, uint32_t anchor_va,
                          const uint8_t *bytes, uint8_t len) {
    uint64_t va = im->text_vmaddr + anchor_va;
    for (int i = 0; i < im->nsegs; i++) {
        if (va < im->segs[i].vmaddr || va >= im->segs[i].vmaddr + im->segs[i].vmsize) {
            continue;
        }
        uint8_t local[64];
        const uint8_t *ptr;
        if (im->avail == (size_t)-1) {
            mach_vm_address_t src = (mach_vm_address_t)im->hdr + (va - im->text_vmaddr);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(mach_task_self(), src, len,
                                       (mach_vm_address_t)(unsigned long)local,
                                       &got) != KERN_SUCCESS || got != len) {
                return 0;
            }
            ptr = local;
        } else {
            uint64_t off = im->segs[i].fileoff + (va - im->segs[i].vmaddr);
            if (off + len > im->avail) return 0;   // 裸缓冲：锚点须整体在界内
            ptr = (const uint8_t *)im->hdr + off;
        }
        return memcmp(ptr, bytes, len) == 0 ? 1 : 0;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 蹦床/入口 stub 公共路径（77 续⑨从 install_hook 提出）：install 与透传
// 契约测试缝（wxkeep_runtime_test_hook_transparency）经同一代码驱动——
// 测到的就是生产路径，不是副本。
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t *mem;          // 蹦床页（4096；调用方负责 munmap）
    uint8_t stub[16];      // 入口 stub（写前构造；arm64 16B / x64 12B）
    size_t stub_len;
} hook_trampoline_t;

/// 蹦床页创建 + 装填（原入口原像 + 跳回 target+len）。arm64 走 MAP_JIT
/// （np 开写 → icache 失效 → np 关写），x64 走匿名 RWX。失败时 errno/step
/// 已记录（g_install_step=1 = mmap）。
static int prepare_trampoline(uintptr_t target, const uint8_t *prologue,
                              size_t len, int is_arm64,
                              hook_trampoline_t *out) {
    memset(out, 0, sizeof(*out));
    int jit = is_arm64;
    uint8_t *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE | (jit ? MAP_JIT : 0), -1, 0);
    if (mem == MAP_FAILED) { g_install_errno = errno; g_install_step = 1; return -1; }
    if (jit) pthread_jit_write_protect_np(0);
    memcpy(mem, prologue, len);
    uint64_t back = target + len;
    if (is_arm64) {
        memcpy(mem + len, "\x51\x00\x00\x58", 4);        // ldr x17, #8
        memcpy(mem + len + 4, "\x20\x02\x1f\xd6", 4);    // br x17
        memcpy(mem + len + 8, &back, 8);
        sys_icache_invalidate(mem, len + 16);
        pthread_jit_write_protect_np(1);
    } else {
        memcpy(mem + 12, "\x49\xbb", 2);                 // movabs r11, imm64
        memcpy(mem + 14, &back, 8);
        memcpy(mem + 22, "\x41\xff\xe3", 3);             // jmp r11
    }
    out->mem = mem;
    uint64_t hook = (uint64_t)&revoke_wrapper_hook;
    if (is_arm64) {
        memcpy(out->stub, "\x51\x00\x00\x58", 4);        // ldr x17, #8
        memcpy(out->stub + 4, "\x20\x02\x1f\xd6", 4);    // br x17
        memcpy(out->stub + 8, &hook, 8);
        out->stub_len = 16;
    } else {
        memcpy(out->stub, "\x48\xb8", 2);                // movabs rax, imm64
        memcpy(out->stub + 2, &hook, 8);
        memcpy(out->stub + 10, "\xff\xe0", 2);           // jmp rax
        out->stub_len = 12;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 线程静默写窗（77 续⑩，仅 arm64）：入口 stub 的 16B memcpy 是非原子
// 写，与并发执行流存在撕裂窗——T4 渲染破坏的存活候选①（77 续⑩ 静态
// 裁决已否决寄存器清坏候选：目标函数只消费 x0-x2，见 RUNTIME-DESIGN；
// 撕裂取指 = 半截序言 + stub 混合执行 → hook 带坏 sp 进场 → 蹦床重放
// 完整序言 = 双重 prologue → 帧腐坏静默传播为解析损坏，可不崩）。
// 写窗收窄 = suspend 全部同任务线程（除自身）→ store → icache 失效
// （广播到内共享域）→ resume。与 ElleKit stopAllThreads/frida 同一做法。
// 已知残余风险（记录不修）：task_threads 枚举后新建的线程不在静默集
// （窗微秒级，接受）；被挂起线程若恰持 vm 锁，icache 系统调用可能等锁
// （同窗微秒级，业界同款接受）。x64 维持直写（12B、实弹多年、本轮不动）。
// ---------------------------------------------------------------------------

static thread_act_array_t g_quiesce_list;
static mach_msg_type_number_t g_quiesce_n;
static int g_quiesce_threads;   // 诊断：上次安装静默的线程数（-1=枚举失败）

static void quiesce_begin(void) {
    g_quiesce_list = NULL;
    g_quiesce_n = 0;
    g_quiesce_threads = -1;
    if (task_threads(mach_task_self(), &g_quiesce_list, &g_quiesce_n) != KERN_SUCCESS) {
        g_quiesce_list = NULL;
        return;
    }
    thread_t self = mach_thread_self();
    int ok = 0;
    for (mach_msg_type_number_t i = 0; i < g_quiesce_n; i++) {
        if (g_quiesce_list[i] == self) continue;
        if (thread_suspend(g_quiesce_list[i]) == KERN_SUCCESS) ok++;
    }
    mach_port_deallocate(mach_task_self(), self);
    g_quiesce_threads = ok;
}

static void quiesce_end(void) {
    if (!g_quiesce_list) return;
    for (mach_msg_type_number_t i = 0; i < g_quiesce_n; i++)
        thread_resume(g_quiesce_list[i]);   // 未被我们挂起的线程 resume 报错，无害
    vm_deallocate(mach_task_self(), (vm_address_t)g_quiesce_list,
                  g_quiesce_n * sizeof(thread_act_t));
    g_quiesce_list = NULL;
    g_quiesce_n = 0;
}

/// 入口 stub 落写 + 写后读回（g_stub_alive）。page_already_writable=1：
/// 目标页已是本线程 MAP_JIT 页（测试缝的哨兵页）——np(0) 窗口直写；
/// 0 = 生产文件页：mprotect → vm_remap COW 舞步（语义见 install_hook 内
/// 注释）。失败时 errno/step 已记录（step=2 = 目标页可写化）。
/// arm64 的 store+icache 在线程静默窗内执行（77 续⑩，见上方块注释）。
// T6（94 轮）：入口补丁态识别 + SLOT 填充——macOS 27 进程内写化被策略
// 封死（mprotect errno 13 / COW 写副本 CS 击杀，T5 二分定案）后的唯一
// 武装通道。CLI 在装机时已把目标函数入口前 12B 改写为
//   adrp x16, <SLOT 页> ; ldr x16, [x16, #off] ; br x16
// （SLOT 落 __DATA 段尾文件填充）。本函数解码该形态并把蹦床地址写进
// SLOT——纯数据写（__DATA RW），合法。
// 返回：0=已填充；ENOENT=入口无补丁形态（调用方回落旧阶梯）；其余=错误。

// T6 诊断：武装决策点直接追加 boot log（进程可能死于任何一步——
// 逐点留痕才能远程定位；与 late20s 同写法）。
static void bootlog_line(const char *msg) {
    @autoreleasepool {
        NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                          NSHomeDirectory()];
        NSMutableString *acc = [NSMutableString stringWithContentsOfFile:boot
                                                                encoding:NSUTF8StringEncoding error:nil];
        [acc appendFormat:@"%s\n", msg];
        [acc writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

// 入口补丁形态解码（arm64）：adrp x16 / ldr x16,[x16,#imm] / br x16 →
// SLOT 绝对 VA。与 EntrySlot.swift decodeSlotVA 同构。0 = 非补丁形态。
static uint64_t slotfill_decode(const uint32_t *w, uintptr_t target) {
    if (!((w[0] >> 31) == 1 && ((w[0] >> 24) & 0x1F) == 0x10 && (w[0] & 0x1F) == 16))
        return 0;
    if (!((w[1] & 0xFFC00000u) == 0xF9400000u && ((w[1] >> 5) & 0x1F) == 16 && (w[1] & 0x1F) == 16))
        return 0;
    if (w[2] != 0xD61F0200u) return 0;
    int64_t immlo = (w[0] >> 29) & 0x3;
    int64_t immhi = (w[0] >> 5) & 0x7FFFF;
    int64_t imm = (immhi << 2) | immlo;
    if (imm & (1 << 20)) imm -= (1 << 21);
    uint64_t page = (target & ~(uint64_t)0xFFF) + ((uint64_t)imm << 12);
    return page + (((uint64_t)(w[1] >> 10) & 0xFFF) << 3);
}

// 内核级读 + 补丁态识别（用户态 memcpy 对已改写签名页有 CS 击杀实例——
// 95 轮副本实测——目标页访问一律走内核读）。
static int entry_patch_present(uintptr_t target) {
    uint32_t w[3] = {0, 0, 0};   // 12B 读入 12B 缓冲（slotfill_decode 按字读取）
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)target, 12,
                               (mach_vm_address_t)(unsigned long)w, &got) != KERN_SUCCESS
        || got != 12) return 0;
    return slotfill_decode(w, target) != 0;
}

/// SLOT 武装目标（97 轮）：= naked thunk（revoke_wrapper_hook = hook 逻辑
/// 入口：body→蹦床重放→原函数）。**不能指蹦床本体**——蹦床只重放序言
/// +跳回，指它 = 完全绕过 hook 逻辑（96 轮真机 fires=0 根因：武装成功
/// 但链路绕过了逻辑）。旧架构 stub 分支目标 = thunk（prepare_trampoline
/// 编码进 tr.stub 的 hook 地址），SLOT 语义与 stub 分支目标一致。安装路
/// 与回归缝（wxkeep_runtime_test_slot_chain）共用本函数——实参漂移即刻
/// 双侧同红。
static void *slot_arm_target(void) { return (void *)&revoke_wrapper_hook; }

static int try_slot_fill(uintptr_t target, void *trampoline) {
    const uint32_t br_x16 = 0xD61F0200u;
    uint32_t w[3];
    memcpy(w, (const void *)target, 12);
    uint64_t slot = slotfill_decode(w, target);
    if (slot == 0) {
        bootlog_line("slotfill: 入口非补丁形态（decode 失败）");
        return ENOENT;
    }
    // 双写一致性读回（数据写无需 icache；release 语义由 volatile+读回保证）
    *(volatile uint64_t *)slot = (uint64_t)(uintptr_t)trampoline;
    os_compiler_barrier();
    if (*(volatile uint64_t *)slot != (uint64_t)(uintptr_t)trampoline) {
        bootlog_line("slotfill: readback mismatch");
        return EIO;
    }
    { char b[128]; snprintf(b, sizeof(b), "slotfill: OK slot=0x%llx tramp=0x%llx",
        (unsigned long long)slot, (unsigned long long)(uintptr_t)trampoline); bootlog_line(b); }
    os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] slot-fill ok slot=0x%llx trampoline=0x%llx",
           (unsigned long long)slot, (unsigned long long)(uintptr_t)trampoline);
    return 0;
}

static int write_entry_stub(uintptr_t target, const uint8_t *stub, size_t stub_len,
                            int is_arm64, int page_already_writable) {
    uintptr_t page = target & ~(uintptr_t)0xfff;
    if (page_already_writable) {
        pthread_jit_write_protect_np(0);
        if (is_arm64) quiesce_begin();
        memcpy((void *)target, stub, stub_len);
        sys_icache_invalidate((void *)target, stub_len);
        if (is_arm64) quiesce_end();
        pthread_jit_write_protect_np(1);
    } else {
        int page_writable =
            (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
        if (!page_writable) {
            int mp1_errno = errno;   // 诊断编码 300+：首个 mprotect(RWX) 的 errno
            vm_address_t rw = (vm_address_t)page;
            vm_prot_t cur = 0, mx = 0;
            kern_return_t kr = vm_remap(mach_task_self(), &rw, 0x2000, 0,
                                        VM_FLAGS_OVERWRITE | VM_FLAGS_RETURN_DATA_ADDR,
                                        mach_task_self(), (vm_address_t)page, FALSE,
                                        &cur, &mx, VM_INHERIT_COPY);
            if (kr != KERN_SUCCESS) {
                // 诊断编码 100+kr：remap 失败（kern_return_t 值直接可读，
                // 2=KERN_PROTECTION_FAILURE 4=INVALID_ADDRESS 26=KERN_INVALID_OBJECT…）
                g_install_errno = 100 + (int)kr; g_install_step = 2; return -1;
            }
            // 270135 实战（77 续㊱ 诊断变体 21:15）：kr=SUCCESS，原地址
            // mprotect(RW) EINVAL——macOS 27.1 收紧。RETURN_DATA_ADDR 的
            // 输出 rw = COW 副本的 data address：对副本地址 mprotect，
            // 命中可写则写副本（原 VA 经重映射后指向同一物理副本时的
            // 语义分支），不行再回落原地址。
            if (mprotect((void *)rw, 0x2000, PROT_READ | PROT_WRITE) == 0) {
                page_writable = 1;
                memcpy((void *)target, stub, stub_len);
                if (is_arm64) sys_icache_invalidate((void *)target, stub_len);
                mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
                const uint8_t *now1 = (const uint8_t *)target;
                g_stub_alive = (memcmp(now1, stub, stub_len) == 0) ? 1 : 0;
                return g_stub_alive == 1 ? 0 : -1;
            }
            if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
                // 诊断编码 200+errno：remap 后两条 mprotect 路径全拒
                // —— 第四层（77 续㊱：substitute 路线，RUNTIME-DESIGN 社区
                // 备选入档项）：匿名页 MAP_FIXED 盖回。allow-unsigned-
                // executable-memory 容忍匿名可执行页；先存原内容再盖，
                // 内容逐字节保全，仅入口 stub 落上去。
                int saved_errno = errno;
                uint8_t *saved = (uint8_t *)malloc(0x2000);
                if (saved) {
                    memcpy(saved, (void *)page, 0x2000);
                    void *m = mmap((void *)page, 0x2000,
                                   PROT_READ | PROT_WRITE,
                                   MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
                    if (m == MAP_FAILED) {
                        g_install_errno = 300 + errno; g_install_step = 2;
                        free(saved); return -1;
                    }
                    memcpy((void *)page, saved, 0x2000);
                    free(saved);
                    memcpy((void *)target, stub, stub_len);
                    if (is_arm64) sys_icache_invalidate((void *)target, stub_len);
                    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
                    const uint8_t *now2 = (const uint8_t *)target;
                    g_stub_alive = (memcmp(now2, stub, stub_len) == 0) ? 1 : 0;
                    return g_stub_alive == 1 ? 0 : -1;
                }
                g_install_errno = 200 + saved_errno; g_install_step = 2; return -1;
            }
            page_writable = 1;
            (void)mp1_errno;
        }
        if (!page_writable) { g_install_errno = errno; g_install_step = 2; return -1; }
        if (is_arm64) quiesce_begin();
        memcpy((void *)target, stub, stub_len);
        if (is_arm64) sys_icache_invalidate((void *)target, stub_len);
        if (is_arm64) quiesce_end();
        mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    }
    // 写后读回：COW remap 写路径的直接验证（写丢失在此即现，不等撤回流量）
    const uint8_t *now = (const uint8_t *)target;
    g_stub_alive = (memcmp(now, stub, stub_len) == 0) ? 1 : 0;
    return 0;
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
    // T6（95 轮）：arm64 先做内核级补丁态识别。补丁态 = 入口已是我们的
    // 跳板——prologue 用行 expected（蹦床重放原始 16B、跳回 target+len，
    // 与未补丁语义一致），并跳过对目标页的一切用户态触碰（用户态
    // memcpy 读/写已改写签名页 = SIGKILL CS 击杀，95 轮副本实测）。
    int entry_patched = 0;
    if (t->is_arm64) entry_patched = entry_patch_present(target);
    if (entry_patched) {
        memcpy(prologue, t->expected, len);
    } else {
        memcpy(prologue, (void *)target, len);
    }
    memcpy(g_saved_prologue, prologue, 16);
    g_saved_prologue_valid = 1;
    if (!entry_patched && memcmp(prologue, t->expected, len) != 0) {
        // 自适应路径（allow_runtime_prologue，默认关）：270100 的 10-03 自更新
        // 后壳改写 parse 入口运行时字节——磁盘仍是 expected（我们的 RE/补丁
        // 位点不受影响，v1 字节补丁实证有效）。接受运行时原像的前提 = 它
        // 本身过可换址编码门（arm64 见下 / x64 转移编码拒绝），蹦床保存的
        // 就是壳填充后的真实原像，语义保全。构造身份仍由行 UUID 锁死。
        if (!(g_allow_runtime_prologue && (!t->is_arm64 ||
                arm64_prologue_relocatable(prologue, len)))) {
            os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] prologue mismatch — hook skipped");
            g_hook_status |= kStPrologueMismatch;
            return -1;
        }
    }
    // arm64 的 PC 相对编码在换址执行时会指向错误目标——外部表已在解析期
    // 过滤，这里对实际内存再验一次（内置表同受保护）。补丁态的 prologue
    // 来自行 expected（derive 期已过此门），豁免重验。
    if (t->is_arm64 && !entry_patched && !arm64_prologue_relocatable(prologue, len)) {
        g_hook_status |= kStPrologueMismatch;
        return -1;
    }
    // 函数级身份门（77 续）：序言只证明「该偏移处有一段长得像家族序言的
    // 字节」，不证明「它是当初 derive 的那个函数」——10-03 自更新（同 UUID
    // 新字节）后 0x4bc4d34 已是另一个同序言函数，hook 破坏消息解析。行带
    // func_size/anchor 时按镜像元数据二次核对；元数据缺失（无法核对）也拒
    // ——带身份字段的行宁可不挂（fail closed），旧行不带字段则不经过此门。
    if (t->has_func_size || t->anchor_len) {
        image_layout_t im;
        int bad = !image_layout((const struct mach_header_64 *)base, (size_t)-1, &im);
        if (!bad && t->has_func_size
            && func_size_matches(&im, t->hook_off, t->func_size) != 1) bad = 1;
        if (!bad && t->anchor_len
            && anchor_matches(&im, t->anchor_va, t->anchor, t->anchor_len) != 1) bad = 1;
        image_layout_free(&im);
        if (bad) {
            g_hook_status |= kStFuncMismatch;
            os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] func identity mismatch — hook skipped");
            return -1;
        }
    }
    // ---- 蹦床与入口 stub（77 续⑨提为公共路径：测试缝经同一代码驱动）----
    // 蹦床：RWX 页内 = 原入口原像 + 跳回 target+len。
    // arm64（macOS 27 微信进程实测 2026-10-26）：匿名 RWX mmap 被 W^X 拒
    // （EACCES → kStInstallFail；旧编码下其值 3 与序言门位形重叠致误读，
    // 77 续已改独立 bit——见 g_hook_status 注释）——与
    // Verifier 65 轮同坑同解：MAP_JIT 是无 entitlement 的官方通道，写入用
    // np(0) 开写 + icache 失效；页装成后只执行不再写。x64 无 MAP_JIT 语义，
    // 维持 RWX。
    hook_trampoline_t tr;
    if (prepare_trampoline(target, prologue, len, t->is_arm64, &tr) != 0) {
        g_hook_status |= kStInstallFail;   // errno/step 已在公共路径内记录
        return -1;
    }

    // 发布序（弱内存序防线，72·L3①）：依赖字段全部先写，g_hook.target
    // 最后以 release 存储——它是 hook 侧的唯一准入判据（acquire 读），
    // release/acquire 配对保证他核在看到 target 非零的同时必然看到完整
    // 的 msg_arg/xml_sso_off/saved/trampoline/g_real_wrapper。旧实现全部
    // 普通赋值且 target 先写：arm64 弱序下理论上另一核可见入口 stub 的
    // 同时读到陈旧 g_real_wrapper=NULL → 间接跳 0 崩溃（概率极低——
    // mprotect 系统调用事实提供屏障——但 C 语义不保证，装机量上去后
    // 不能赌）。失败清理路径同序复位（target=0 也走 release，保持配对
    // 对称；此刻 stub 未写、hook 无调用者，普通写本也安全）。
    g_hook.msg_arg = t->msg_arg;
    g_hook.xml_sso_off = t->xml_sso_off;
    g_sso_layout_arm64 = t->is_arm64;   // 串对象头布局随行 arch（77 续⑧）
    memcpy(g_hook.saved, prologue, len);
    g_hook.trampoline = tr.mem;
    g_real_wrapper = (void *(*)(void *, void *, void *, void *, void *, void *))tr.mem;
    __atomic_store_n(&g_hook.target, target, __ATOMIC_RELEASE);

    // 入口 stub 落写（最后一步：此刻 hook 侧上下文已完整发布）。
    // macOS 27 硬化（2026-10-26 实证 istep=2 errno=13）：entitlements 全在
    // （allow-jit / allow-unsigned-executable-memory），mprotect 给已签名
    // 镜像页加 W 仍 EACCES——27 的 W^X 只放行 MAP_JIT 区。合法通道 =
    // vm_remap COW：VM_INHERIT_COPY 让目标页获得私有副本（脱离 cs 只读
    // 强制），之后 mprotect RW 写 stub、恢复 R|X。9-25 的直接 mprotect
    // 成功是 macOS 26 语义（用户 10 月初升级 27——与 65 轮 Verifier
    // MAP_JIT SIGBUS 大战同期同硬化）。无 entitlement 的进程（本机实测
    // 2026-10-27）连 COW 后的 mprotect RW 也被拒——该舞步只在带
    // allow-unsigned-executable-memory 的宿主（微信）内成立。
    // T6（94 轮）：入口补丁态优先——数据写 SLOT 即武装。
    // 95 轮硬门：arm64 上 SLOT 路径失败（含无补丁形态）一律**不再回落旧
    // 阶梯**——2026-10-31 副本实测：macOS 27 的 COW 阶梯能走到最终 memmove
    // 而后 **SIGKILL(Code Signature Invalid)**（签名 __TEXT 页写 = 内核击
    // 杀，非可捕获信号、非 EACCES 优雅失败）——装了入口补丁的机器上
    // decode 必成；decode 失败=补丁缺失/漂移，此时跳过武装是唯一安全动作
    // （消息管线照常，防护由 v1 字节补丁承担）。x64 语义不同维持旧路。
    { char b[128]; snprintf(b, sizeof(b), "arm: target=0x%llx is_arm64=%d slot_rc_slotfill_next",
        (unsigned long long)target, t->is_arm64); bootlog_line(b); }
    // T6（97 轮修正）：SLOT 必须指 **naked thunk**（slot_arm_target——见其
    // 注释），而非蹦床本体。96 轮真机实弹 fires=0 的根因即此：武装成功但
    // 链路（stub→SLOT→蹦床→target+16）完全绕过了 hook 逻辑。
    int slot_rc = t->is_arm64 ? try_slot_fill(target, slot_arm_target()) : ENOENT;
    { char b[128]; snprintf(b, sizeof(b), "arm: slot_rc=%d", slot_rc); bootlog_line(b); }
    if (slot_rc == 0) {
        g_arm_via_slot = 1;
        return 0;
    }
    if (t->is_arm64) {
        g_hook_status |= kStInstallFail;
        os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] slot-fill rc=%d — arm64 legacy ladder disabled (CS kill risk)", slot_rc);
        g_hook.trampoline = NULL;
        g_real_wrapper = NULL;
        __atomic_store_n(&g_hook.target, 0, __ATOMIC_RELEASE);
        munmap(tr.mem, 4096);
        return -1;
    }
    if (write_entry_stub(target, tr.stub, tr.stub_len, t->is_arm64, 0) != 0) {
        g_hook_status |= kStInstallFail;   // errno/step 已在公共路径内记录
        // 失败清理：蹦床页归还 + 复位 g_hook（此刻 entry 尚未改写、hook 未
        // 到达，g_real_wrapper 不可能有调用者——g_arm_done 已置位不再重试，
        // 残留武装态字段只会误导诊断）。target=0 的 release 存储与 hook 侧
        // acquire 保持发布序对称。
        g_hook.trampoline = NULL;
        g_real_wrapper = NULL;
        __atomic_store_n(&g_hook.target, 0, __ATOMIC_RELEASE);
        munmap(tr.mem, 4096);
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 镜像定位（构造器同步执行：先扫既有镜像，再挂回调兜底后续加载）
// ---------------------------------------------------------------------------

// LC_UUID 提取 + 与标准连字符 UUID 串比对（逐半字节，双向跳过连字符，
// 双侧必须同时耗尽）。注意不能先在 buf 里补 '-' 再比较：want 耗尽时 a
// 停在填充字符上，收尾的 `*a == 0 && *b == 0` 恒假——任何镜像（含目标
// 本尊）都会被判不匹配，hook 永不安装。
//
// `avail` = hdr 起的真实可读字节数：命令区游走以 min(32+sizeofcmds,
// avail) 为界。只信 sizeofcmds 的旧契约对裸缓冲不安全——2026-10-20
// L3⑤ 模糊测试实锤：病态 sizeofcmds 让游走直冲未映射页（SIGBUS，
// runtime_random 复现）。生产两条缓冲式路径（probe_match_target 的
// malloc 块 / 测试缝的任意字节）现在都传真实长度；dyld 已装载镜像传
// SIZE_MAX（内核映射自洽，语义与旧版一致）。
static int uuid_matches(const struct mach_header_64 *hdr, const char *want,
                        size_t avail) {
    uint8_t uuid[16];
    int found = 0;
    const uint8_t *base = (const uint8_t *)hdr;
    const uint8_t *p = base + sizeof(struct mach_header_64);
    const uint8_t *end = p + hdr->sizeofcmds;
    if (avail != (size_t)-1 && end > base + avail) end = base + avail;
    // p+8<=end：cmd/size 字段本身 8B——缓冲式调用（probe_match_target 的
    // malloc 缓冲）下防病态尾部 4B 越读；合法镜像每条 cmd ≥8B 不受影响
    while (p + 8 <= end) {
        uint32_t cmd, size;
        memcpy(&cmd, p, 4); memcpy(&size, p + 4, 4);
        if (cmd == LC_UUID && size >= 24
            && (size_t)(end - p) >= size) {   // LC_UUID 的 16B 载荷须在界内
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

static void try_hook_image(const struct mach_header_64 *hdr, intptr_t slide,
                           size_t avail) {
    (void)slide;
    // UUID 即身份门（构建+切片唯一），不做镜像名匹配——名字反查需要
    // _dyld_image_count()，在 add_image 回调上下文里不可靠（实测 status=24：
    // 名字链提前 return，UUID 检查从未到达）。直接读 header 的 LC_UUID。
    const hook_target_t *t = match_target(hdr, avail);
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
    // T6（94 轮）：wechat.dylib 出现即同步武装。dlopen 的 add_image 通知
    // 在绑定完成后、初始化器运行前触发——SLOT 必须在这个窗口填充：初始化
    // 器/早期消息管线就会调 parse，SLOT=0 时 br x16 → 空 SLOT 崩溃（副本
    // 实测 2026-10-31：500ms 重试输了与初始化器的竞速）。名字识别
    // （dladdr）不走 uuid——uuid 门在历史运行中位形粘滞。
    {
        Dl_info info;
        if (dladdr((const void *)mh, &info) && info.dli_fname) {
            const char *leaf = strrchr(info.dli_fname, '/');
            leaf = leaf ? leaf + 1 : info.dli_fname;
            if (strcmp(leaf, "wechat.dylib") == 0) {
                strlcpy(g_probe_name, "callback-wechat-slotfill", sizeof(g_probe_name));
                const struct mach_header_64 *h64 = (const struct mach_header_64 *)mh;
                if (match_target(h64, (size_t)-1) != NULL) {
                    try_hook_image(h64, slide, (size_t)-1);
                }
            }
        }
    }
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
        if (uuid_matches((const struct mach_header_64 *)mh, kTarget270099_uuid,
                         (size_t)-1)) {
            // wechat.dylib 确实从回调到达——记下这一事实
            strlcpy(g_probe_name, "callback-saw-wechat-uuid", sizeof(g_probe_name));
        }
    }
    try_hook_image((const struct mach_header_64 *)mh, slide, (size_t)-1);
}

// ---------------------------------------------------------------------------
// M-R1：标记文件
// ---------------------------------------------------------------------------

void write_marker(void) { write_marker_ex(1); }

/// 按序尝试候选目录，首个「建目录成功 + marker 写成功」者胜（返回序号，
/// 全败 -1）。沙盒微信的 App Group 写被拒（ad-hoc 签名无 team，
/// containermanagerd 拒授权——T4 台账实证：containerURL 返回合法路径但
/// createDirectory/writeToFile 静默失败）时，这里让 legacy 路径（沙盒内
/// 展开 = 容器 Application Support，boot log 同源可达性）接管——marker
/// 通道不再永久盲区。路径选择「只认 Group」的旧行为因此缺陷在档。
static int write_marker_first_writable(NSString *const *dirs, int n,
                                       NSString *content) {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (int i = 0; i < n; i++) {
        if (![fm createDirectoryAtPath:dirs[i] withIntermediateDirectories:YES
                                    attributes:nil error:nil]) continue;
        NSString *path = [dirs[i] stringByAppendingPathComponent:@"runtime.marker"];
        if ([content writeToFile:path atomically:YES
                        encoding:NSUTF8StringEncoding error:nil]) {
            return i;
        }
    }
    return -1;
}

static NSString *legacyMarkerDir(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = dirs.count > 0 ? dirs[0] : @"~/Library/Application Support";
    return [[base stringByAppendingPathComponent:@"wxkeep"]
        stringByExpandingTildeInPath];
}

static void write_marker_ex(int loud) {
    @autoreleasepool {
        // 与配置同策略：Group 容器优先（CLI/runtime status 在沙盒外读同一路
        // 径），写失败回落 legacy——容器内 ~/ 展开曾让 marker 对 CLI 不可见
        // （沙盒实证），回落版至少对容器内诊断（boot log 同位面）可见。
        NSString *groupDir = nil;
        @try {
            NSURL *groupURL = [[NSFileManager defaultManager]
                containerURLForSecurityApplicationGroupIdentifier:runtimeAppGroupID()];
            if (groupURL.path.length > 0) {
                groupDir = [groupURL.path stringByAppendingPathComponent:@"wxkeep"];
            }
        } @catch (NSException *e) {
            groupDir = nil;
        }
        NSString *content = [NSString stringWithFormat:
            @"loaded ts=%f mr2=%@ status=%d enc=2 istep=%d ierr=%d fires=%d hits=%d zero=%d selfskip=%d cfg=%.0f cfgh=%016llx last=%@ inner=%@ probe=%@\n",
            [NSDate date].timeIntervalSince1970,
            g_hook_installed ? @"hook-armed" : @"marker-only", g_hook_status,
            g_install_step, g_install_errno,
            g_rewrite_fires, g_rewrite_hits, g_zero_fires,
            g_self_skips, g_cfg_stamp, g_cfg_hash,
            g_last_fired[0] ? cstr_sample(g_last_fired) : @"<none>",
            g_last_inner[0] ? cstr_sample(g_last_inner) : @"<none>",
            [NSString stringWithFormat:@"cb=%d last=%@ scanmiss=%d probe=%@",
                g_cb_count,
                g_last_uuid[0] ? @(g_last_uuid) : @"<none>",
                g_scan_missed,
                g_probe_name[0] ? @(g_probe_name) : @"<none>"]];
        NSString *legacyDir = legacyMarkerDir();
        NSString *dirs[2];
        int n = 0;
        if (groupDir) dirs[n++] = groupDir;
        dirs[n++] = legacyDir;
        int which = write_marker_first_writable(dirs, n, content);
        if (loud) {
            NSLog(@"[wxkeep-runtime] loaded, marker dir idx=%d, mr2=%d", which, g_hook_installed);
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
    dispatch_source_set_event_handler(timer, ^{
        maybe_reload_config();   // 策略键热重载（≤30s 生效；hooks 除外）
        write_marker_ex(0);
        // T4 排障：marker 通道在沙盒微信里写不出（Group 拒+不回落），计数器
        // 改走 boot log 通道（构造器诊断同款，沙盒 tmp 必可达）。
        @autoreleasepool {
            NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                              NSHomeDirectory()];
            NSMutableString *acc = [NSMutableString stringWithContentsOfFile:boot
                                                                    encoding:NSUTF8StringEncoding error:nil];
            if (g_hook_installed && g_hook.trampoline) {
                const uint8_t *now = (const uint8_t *)g_hook.target;
                g_stub_alive = (now && memcmp(now, "\x51\x00\x00\x58\x20\x02\x1f\xd6", 8) == 0) ? 1 : 0;
            }
            [acc appendFormat:@"tick installed=%d status=%d alive=%d calls=%d fires=%d hits=%d zero=%d selfskip=%d qz=%d arg1=",
                g_hook_installed, g_hook_status, g_stub_alive, g_hook_calls, g_rewrite_fires, g_rewrite_hits,
                g_zero_fires, g_self_skips, g_quiesce_threads];
            if (g_arg1_valid) {
                for (int k = 0; k < 24; k++) [acc appendFormat:@"%02x", g_arg1_head[k]];
            } else {
                [acc appendString:@"<none>"];
            }
            [acc appendFormat:@" last=%@ inner=%@\n",
                g_last_fired[0] ? cstr_sample(g_last_fired) : @"<none>",
                g_last_inner[0] ? cstr_sample(g_last_inner) : @"<none>"];
            [acc writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    });
    dispatch_resume(timer);
    // 刻意被静态引用持有、永不 cancel：source→handler→全局函数 无环，
    // 常驻即设计（进程内一次性安装）。
    static dispatch_source_t keep __attribute__((unused));
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
        hit = match_target((const struct mach_header_64 *)buf, len) != NULL;
    }
    free(buf);
    return hit;
}

static void scan_and_arm(void) {
    if (g_hook_installed) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (match_target((const struct mach_header_64 *)mh, (size_t)-1) != NULL) {
            try_hook_image((const struct mach_header_64 *)mh,
                           _dyld_get_image_vmaddr_slide(i), (size_t)-1);
            return;
        }
    }
    // dyld 镜像表对本构建的 wechat.dylib 不可见（壳程序手动映射，绕过
    // add_image 通知，2026-09-18 实测 cb=1000+ 无它）——退化为纯内存扫描:
    // 找 ≥64MB 的可执行区域并验证 Mach-O header UUID。
    uintptr_t base = find_wechat_base_by_region_scan();
    if (base) {
        strlcpy(g_probe_name, "region-scan-found", sizeof(g_probe_name));
        // probe_match_target 已 mach-读验证 32+sizeofcmds 全量可读——按同界传入
        try_hook_image((const struct mach_header_64 *)base, 0,
                       32 + ((const struct mach_header_64 *)(void *)base)->sizeofcmds);
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
    // 诊断通道（2026-10-26 T4 排障引入）：写沙盒容器 tmp——微信进程里
    // NSLog/marker 双失联时，这里是唯一保证可达的证据面。enter 行必须在
    // host 门**之后**（77 续⑪）：门前的写入让任何加载本 dylib 的非微信
    // 宿主（测试 runner/fuzz 驱动）都覆写 ~/tmp/wxkeep-boot.log——T4 时代
    // 的根目录取证连续性即被测试运行破坏（实证），微信侧（沙盒容器 tmp）
    // 与非微信宿主（真实 home tmp）本就走不同 NSHomeDirectory，门后写入
    // 两不相扰。
    if (!host_is_wechat()) return;   // 非微信宿主：零副作用（测试缝为直接函数调用，不受影响）
    @autoreleasepool {
        NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                          NSHomeDirectory()];
        NSString *line = [NSString stringWithFormat:
            @"enter exe=%@ ts=%f\n", @( _dyld_get_image_name(0) ?: "<nil>"),
            [NSDate date].timeIntervalSince1970];
        if (![[NSFileManager defaultManager] fileExistsAtPath:
                [NSHomeDirectory() stringByAppendingString:@"/tmp"]]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:
                [NSHomeDirectory() stringByAppendingString:@"/tmp"]
                withIntermediateDirectories:YES attributes:nil error:nil];
        }
        [line writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    load_config();
    // 既有镜像线性扫描（wechat.dylib 可能早于本 dylib 加载）——按地址表直查
    {
        uint32_t n = _dyld_image_count();
        int found = 0;
        for (uint32_t i = 0; i < n; i++) {
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (match_target((const struct mach_header_64 *)mh, (size_t)-1) != NULL) {
                found = 1;
                strlcpy(g_probe_name, "scan-saw-wechat-uuid", sizeof(g_probe_name));
                try_hook_image((const struct mach_header_64 *)mh,
                               _dyld_get_image_vmaddr_slide(i), (size_t)-1);
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
                usingBlock:^(NSNotification *note){ (void)note; arm_late(); }];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                   ^{ arm_late(); });

    start_evidence_timer();   // fires/hits/zero 会话内周期回写（marker 证据闭环）
    write_marker();
    // 诊断通道（T4 排障）：构造器走完的尾部标记
    @autoreleasepool {
        NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                          NSHomeDirectory()];
        NSMutableString *acc = [NSMutableString stringWithContentsOfFile:boot
                                                                encoding:NSUTF8StringEncoding error:nil];
        NSString *cfgPath = nil;
        NSDictionary *cfgDiag = read_runtime_config_at(&cfgPath);
        NSString *tipDiag = [cfgDiag objectForKey:@"tip_text"];
        [acc appendFormat:@"cfgdiag path=%@ tip=%@ rows=%@\n",
            cfgPath ?: @"<nil>",
            [tipDiag isKindOfClass:[NSString class]] && tipDiag.length > 0 ? @"set" : @"<empty>",
            cfgDiag[@"hooks"] ? @([(NSArray *)cfgDiag[@"hooks"] count]) : @"0"];
        [acc appendFormat:@"done config=%@ installed=%d status=%d scanmiss=%d cb=%d last_uuid=%s armed=%d\n",
            cfgDiag ? @"yes" : @"no", g_hook_installed, g_hook_status,
            g_scan_missed, g_cb_count,
            g_last_uuid[0] ? g_last_uuid : "<none>", g_hook_installed];
        [acc writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    // 诊断通道（T4 排障）：延迟采样——wechat.dylib 由 libwxld 在 main 内
    // dlopen，构造器期快照看不到它；20s 后回调证据已齐。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                              NSHomeDirectory()];
            NSMutableString *acc = [NSMutableString stringWithContentsOfFile:boot
                                                                    encoding:NSUTF8StringEncoding error:nil];
            [acc appendFormat:@"late20s installed=%d status=%d cb=%d last_uuid=%s scanmiss=%d istep=%d errno=%d slot=%d prologue=",
                g_hook_installed, g_hook_status, g_cb_count,
                g_last_uuid[0] ? g_last_uuid : "<none>", g_scan_missed,
                g_install_step, g_install_errno, g_arm_via_slot];
            if (g_saved_prologue_valid) {
                for (int k = 0; k < 16; k++) [acc appendFormat:@"%02x", g_saved_prologue[k]];
            } else {
                [acc appendString:@"<not-captured>"];
            }
            [acc appendString:@"\n"];
            [acc writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    });
}

// ---------------------------------------------------------------------------
// 测试缝
// ---------------------------------------------------------------------------

/// UUID 门回归缝：对调用方构造的伪 mach_header_64（含 LC_UUID）执行一次
/// 身份判定。锁死「比对逻辑恒假 → hook 永不安装」这类静默失效。
int wxkeep_runtime_test_uuid_match(const void *hdr, unsigned long len) {
    if (len < sizeof(struct mach_header_64)) return 0;   // 头本身都读不完整
    return uuid_matches((const struct mach_header_64 *)hdr, kTarget270099_uuid,
                        (size_t)len);
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

/// 函数级身份门核对缝（77 续）：对伪镜像缓冲（含段表 + LC_FUNCTION_
/// STARTS）执行与 install_hook 同一的核对。返回 1=匹配 0=失配
/// -1=元数据缺失。锁死「派生侧 machutil 语义 ≠ 安装侧核对语义」这类
/// 两处实现漂移（func_size 算的是到下一函数起点的距离，不是函数字节数）。
int wxkeep_runtime_test_func_size_verify(const void *hdr, unsigned long avail,
                                         unsigned long hook_off,
                                         unsigned long func_size) {
    image_layout_t im;
    if (!image_layout((const struct mach_header_64 *)hdr, avail, &im)) return -1;
    int r = func_size_matches(&im, hook_off, (uint32_t)func_size);
    image_layout_free(&im);
    return r;
}

/// 同上：anchor 门核对（bytes ≤64B）。
int wxkeep_runtime_test_anchor_verify(const void *hdr, unsigned long avail,
                                      unsigned long anchor_va,
                                      const unsigned char *bytes, unsigned long len) {
    if (len == 0 || len > 64) return -1;
    image_layout_t im;
    if (!image_layout((const struct mach_header_64 *)hdr, avail, &im)) return -1;
    int r = anchor_matches(&im, (uint32_t)anchor_va, bytes, (uint8_t)len);
    image_layout_free(&im);
    return r;
}

/// 通用 keeptip 缝：对 XML 缓冲执行 <newmsgid> 数字清零（等长），
/// 返回清零的数字个数。锁死 v1 语义的 runtime 化实现。
int wxkeep_runtime_test_zero(unsigned char *data, unsigned long len) {
    return zero_newmsgid_digits(data, (uint64_t)len);
}

/// T4 实验缝：对 XML 缓冲执行 <msgid> 数字清零（等长）——独立于配置
/// 全局，测试直接驱动改写逻辑本身。
int wxkeep_runtime_test_zero_msgid(unsigned char *data, unsigned long len) {
    return zero_tag_digits(data, (uint64_t)len, "<msgid>", sizeof("<msgid>") - 1);
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
        tip_store_write("", 0); g_rewrite_self = 0;
        memset(g_ext_hooks, 0, sizeof(g_ext_hooks));
        g_ext_hook_count = 0;
        g_sso_layout_arm64 = 0;
        apply_config_dict(cfg);
        return g_ext_hook_count;
    }
}

/// per-arch 串对象头布局缝（77 续⑧）：1 = arm64 变体布局
/// （flag=[0x17] 符号 / data@[0] / size@[8]），0 = x64 标准布局。
/// 生产路径由 install_hook 按行 arch 置位。
void wxkeep_runtime_test_set_arm64_layout(int arm64) {
    g_sso_layout_arm64 = arm64 ? 1 : 0;
}

// 透传缝的排障出口（双架构定义，非 arm64 宿主恒 0）
long g_wxkeep_transparency_diff;
long g_wxkeep_transparency_got;
uint64_t g_wxkeep_transparency_base_dump[13];
uint64_t g_wxkeep_transparency_hooked_dump[13];

#if defined(__arm64__) || defined(__aarch64__)
// ---------------------------------------------------------------------------
// 透传契约端到端缝（77 续⑨，仅 arm64 宿主）
//
// MAP_JIT 页内手工构造哨兵函数：8 个整型寄存器参（x0-x7）+ 1 个栈参
//（[sp]）+ 2 个 FP 参（v0/v1）全部 EOR 折进 x0 返回。经生产同一蹦床/
// stub 代码路径（prepare_trampoline + write_entry_stub，含 77 续⑩ 线程
// 静默写窗）挂钩后调用——hook 链上任何参数面被破坏都让哨兵失配：
// x6/x7 被当草稿寄存器、hook 体 memcpy 清 v0-v7、尾跳前 sp 未复原。
// 定位 = 对「签名未知的目标行」的结构保证（对现行 270100 行是超集：
// 77 续⑩ 已静态裁决其只消费 x0-x2——见 RUNTIME-DESIGN）。
// 哨兵 args[1] 传有效 32B 缓冲指针：hook 诊断面（24B 快照）与 sso_head
// 读取范围（arm64 布局 ≤0x18B）都落在界内，短串门自然关断（确定性）。
// 返回：1=全透传通过 0=参数失配 -1=装挂失败 -3=哨兵自检失败
//       -4=hook 链未实际到达（计数未增）。
// ---------------------------------------------------------------------------
static uint8_t *g_sentinel_page;
static uint8_t *g_dump_page;   // 转储哨兵的 RW 落页（RX 的哨兵页不可写）

long wxkeep_runtime_test_hook_transparency(void) {
    if (g_sentinel_page == NULL) {
        g_sentinel_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
        if (g_sentinel_page == MAP_FAILED) return -1;
        // 哨兵 arm64 机器码（入口 16B = 蹦床重放段，纯寄存器运算无 PC 相对）：
        //   eor x0,x0,x1..x4            ← 重放段（4 条 = 16B）
        //   eor x0,x0,x5/x6/x7          ← 续段（+16 起）
        //   ldr x9,[sp]; eor x0,x0,x9   ← 第 9 整型参 = 栈参（尾跳保 sp 才对）
        //   fmov x9,d0/d1; eor x0,x0,x9 ← FP 参 v0/v1 位级折叠
        //   ret
        // 转储哨兵（排障形态；正式形态见 git 历史）：入口 16B=4×NOP（可换址
        // 重放段），续段（+0x10 起，原址执行）先把 x0-x7/[sp]/v0/v1/x30/sp
        // 原样转储到页 +0x90，再 EOR 折叠返回。逐槽比对定位破坏点。
        static const uint32_t code[] = {
            0xD503201Fu, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu,  // nop ×4
            0x58000709u,   // ldr x9, [pc→+0xf0]（转储区绝对地址 literal）
            0xA9000520u,   // stp x0, x1, [x9]
            0xA9010D22u,   // stp x2, x3, [x9, #0x10]
            0xA9021524u,   // stp x4, x5, [x9, #0x20]
            0xA9031D26u,   // stp x6, x7, [x9, #0x30]
            0xF94003EAu,   // ldr x10, [sp]
            0xF900212Au,   // str x10, [x9, #0x40]   槽8=[sp] 栈参
            0x9E66000Au,   // fmov x10, d0
            0xF900252Au,   // str x10, [x9, #0x48]   槽9=d0
            0x9E66002Au,   // fmov x10, d1
            0xF900292Au,   // str x10, [x9, #0x50]   槽10=d1
            0xF9002D3Eu,   // str x30, [x9, #0x58]   槽11=x30
            0x910003EAu,   // mov x10, sp
            0xF900312Au,   // str x10, [x9, #0x60]   槽12=sp
            0xCA010000u, 0xCA020000u, 0xCA030000u, 0xCA040000u,
            0xCA050000u, 0xCA060000u, 0xCA070000u,
            0xF94003EBu, 0xCA0B0000u,
            0x9E66000Bu, 0xCA0B0000u,
            0x9E66002Bu, 0xCA0B0000u,
            0xD65F03C0u,
        };
        g_dump_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0);
        if (g_dump_page == MAP_FAILED) { g_sentinel_page = NULL; return -1; }
        pthread_jit_write_protect_np(0);
        memcpy(g_sentinel_page, code, sizeof(code));
        uint64_t dump_addr = (uint64_t)(uintptr_t)g_dump_page;
        memcpy(g_sentinel_page + 0xf0, &dump_addr, 8);   // literal 槽
        sys_icache_invalidate(g_sentinel_page, sizeof(code));
        pthread_jit_write_protect_np(1);
    }
    // 9 整型参 + 2 FP 参的 C 声明：arm64 ABI 恰好排进 x0-x7 + [sp] + v0/v1
    typedef long (*sentinel_t)(long, long, long, long, long, long, long, long,
                               long, double, double);
    sentinel_t fn = (sentinel_t)(void *)g_sentinel_page;
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));   // buf[0x17]=0：arm64 短串门关断（确定性）
    long v[9] = {0x1100000000000001L, 0, 0x3300000000000003L, 0x4400000000000004L,
                 0x5500000000000005L, 0x6600000000000006L, 0x7700000000000007L,
                 0x8800000000000008L, 0x9900000000000009L};
    v[1] = (long)(intptr_t)buf;    // args[1] = 可读指针（hook 诊断面约束）
    double d0 = 1.5, d1 = -2.25;
    uint64_t db0, db1;
    memcpy(&db0, &d0, 8);
    memcpy(&db1, &d1, 8);
    long expect = v[0];
    for (int i = 1; i < 9; i++) expect ^= v[i];
    expect ^= (long)db0 ^ (long)db1;
    long base = fn(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], d0, d1);
    if (base != expect) return -3;   // 哨兵自身或栈参读位不对（未挂钩就不对）
    memcpy(g_wxkeep_transparency_base_dump, g_dump_page,
           sizeof(g_wxkeep_transparency_base_dump));
    // 挂钩：与 install_hook 同构（公共路径 + 发布序），目标页 = 本线程
    // MAP_JIT 哨兵页（page_already_writable=1）
    uint8_t prologue[16];
    memcpy(prologue, g_sentinel_page, 16);
    hook_trampoline_t tr;
    if (prepare_trampoline((uintptr_t)g_sentinel_page, prologue, 16, 1, &tr) != 0) {
        return -1;
    }
    g_hook.msg_arg = 1;
    g_hook.xml_sso_off = 0;
    g_sso_layout_arm64 = 1;
    memcpy(g_hook.saved, prologue, 16);
    g_hook.trampoline = tr.mem;
    g_real_wrapper = (void *(*)(void *, void *, void *, void *, void *, void *))tr.mem;
    __atomic_store_n(&g_hook.target, (uintptr_t)g_sentinel_page, __ATOMIC_RELEASE);
    long calls_before = g_hook_calls;
    int w = write_entry_stub((uintptr_t)g_sentinel_page, tr.stub, tr.stub_len, 1, 1);
    long r = -100;
    if (w == 0) {
        r = fn(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], d0, d1);
    }
    // 清理：还原哨兵入口 + 复位武装态（与 install 失败清理同序），哨兵页
    // 留存（复用），蹦床页归还。
    pthread_jit_write_protect_np(0);
    memcpy(g_sentinel_page, prologue, 16);
    sys_icache_invalidate(g_sentinel_page, 16);
    pthread_jit_write_protect_np(1);
    g_hook.trampoline = NULL;
    g_real_wrapper = NULL;
    __atomic_store_n(&g_hook.target, 0, __ATOMIC_RELEASE);
    munmap(tr.mem, 4096);
    if (w != 0) return -1;
    if (g_hook_calls != calls_before + 1) return -4;
    memcpy(g_wxkeep_transparency_hooked_dump, g_dump_page,
           sizeof(g_wxkeep_transparency_hooked_dump));
    g_wxkeep_transparency_diff = r ^ expect;
    g_wxkeep_transparency_got = r;
    return (r == expect) ? 1 : 0;
}

// ---------------------------------------------------------------------------
// T6（97 轮）：SLOT 链回归缝（仅 arm64）——96 轮真机 fires=0 的机械根因 =
// SLOT 指了蹦床本体（蹦床=纯序言重放+跳回，控制流完全绕过 hook 逻辑；
// 表现为武装成功、消息管线正常、fires 恒 0——最阴的故障形态）。本缝把
// 生产链路原样架在哨兵函数上端到端走一遍：磁盘侧 entry patch 形态
//（adrp x16,SLOT / ldr x16,[x16] / br x16，EntrySlot.swift 同构编码）+
// 生产 try_slot_fill 实参（slot_arm_target）+ 生产发布序。断言面 =
// ①hook 逻辑到达（g_hook_calls +1——SLOT 语义回退成蹦床即刻红，即 96
// 故障形态）②全链透传（哨兵返回值逐位，链任何一环断即红）。
// 返回：1=链路通 0=返回值失配 -1=蹦床/武装失败 -3=哨兵自检失败
//       -4=hook 逻辑未到达（96 故障形态）-5=SLOT/JIT 页建设失败
//       -6=补丁编码/解码往返失配
// ---------------------------------------------------------------------------
long wxkeep_runtime_test_slot_chain(void) {
    // 1) SLOT 数据页（普通 RW——try_slot_fill 的裸 volatile store 不开 np
    //    写窗，落 JIT 页会 SIGBUS；生产位 = __DATA，同为普通 RW）。
    uint8_t *slot_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
    if (slot_page == MAP_FAILED) return -5;
    uint64_t slot = (uint64_t)(uintptr_t)slot_page;   // 页基 16K 对齐 ⇒ 8 对齐
    *(volatile uint64_t *)slot = 0;
    // 2) 哨兵页（MAP_JIT）：mmap 提示地址贴 SLOT 页，adrp ±4GB 可达性
    //    实测验证，不赌内核布局（提示被占即换挡重试）。
    uint8_t *jit = MAP_FAILED;
    const uint64_t hints_src[4] = {0x100000, 0x400000, 0x1000000, 0x4000000};
    for (int i = 0; i < 4 && jit == MAP_FAILED; i++) {
        void *hints[2] = {(void *)(uintptr_t)(slot + hints_src[i]),
                          (void *)(uintptr_t)(slot - hints_src[i])};
        for (int j = 0; j < 2; j++) {
            uint8_t *p = mmap(hints[j], 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
            if (p == MAP_FAILED) continue;
            int64_t delta = (int64_t)(uint64_t)(uintptr_t)p - (int64_t)slot;
            if (delta < -(int64_t)0xF0000000LL || delta > (int64_t)0xF0000000LL) {
                munmap(p, 4096);   // 超出 adrp ±4GB（0x100000<<12）保守界
                continue;
            }
            jit = p;
            break;
        }
    }
    if (jit == MAP_FAILED) { munmap(slot_page, 4096); return -5; }
    // 3) 哨兵函数：入口 16B = nop×4（可换址重放段；补丁态下前三条被
    //    12B entry patch 覆盖，第四条原位留存——蹦床重放 16B + 跳回
    //    jit+16 = 原函数语义，与生产补丁态同构）。+16 起续段 eor 折叠
    //    x1-x4 进 x0 后 ret。
    static const uint32_t cont[] = {
        0xCA010000u, 0xCA020000u, 0xCA030000u, 0xCA040000u, 0xD65F03C0u,
    };
    static const uint32_t orig[4] = {0xD503201Fu, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu};
    pthread_jit_write_protect_np(0);
    memcpy(jit, orig, 16);
    memcpy(jit + 16, cont, sizeof(cont));
    sys_icache_invalidate(jit, 16 + sizeof(cont));
    pthread_jit_write_protect_np(1);
    typedef long (*sentinel_t)(long, void *, long, long, long);
    sentinel_t fn = (sentinel_t)(void *)jit;
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));   // buf[0]=0：短串门关断（确定性，同透传缝）
    long v0 = 0x1100000000000001L, v2 = 0x3300000000000003L,
         v3 = 0x4400000000000004L, v4 = 0x5500000000000005L;
    long expect = v0 ^ (long)(intptr_t)buf ^ v2 ^ v3 ^ v4;
    if (fn(v0, buf, v2, v3, v4) != expect) {   // 未挂钩自检（续段执行位）
        munmap(jit, 4096); munmap(slot_page, 4096); return -3;
    }
    // 4) 生产链路架设：蹦床（原 16B 原像 + 跳回 jit+16）+ 发布序（与
    //    install_hook 同构）+ entry patch 落页（编码/解码往返互证先行）。
    hook_trampoline_t tr;
    uint8_t prologue[16];
    memcpy(prologue, orig, 16);
    if (prepare_trampoline((uintptr_t)jit, prologue, 16, 1, &tr) != 0) {
        munmap(jit, 4096); munmap(slot_page, 4096); return -1;
    }
    g_hook.msg_arg = 1;            // args[1]=buf：诊断面/串门全程界内
    g_hook.xml_sso_off = 0;
    g_sso_layout_arm64 = 1;
    memcpy(g_hook.saved, prologue, 16);
    g_hook.trampoline = tr.mem;
    g_real_wrapper = (void *(*)(void *, void *, void *, void *, void *, void *))tr.mem;
    __atomic_store_n(&g_hook.target, (uintptr_t)jit, __ATOMIC_RELEASE);
    int64_t pages = ((int64_t)(slot & ~(uint64_t)0xFFF)
                     - (int64_t)((uint64_t)(uintptr_t)jit & ~(uint64_t)0xFFF)) >> 12;
    uint32_t imm = (uint32_t)(pages & 0x1FFFFF);   // 21 位：decode 侧符号扩展
    uint32_t w[3] = {
        0x90000000u | ((imm & 0x3u) << 29) | ((imm >> 2) << 5) | 16u,
        0xF9400000u | ((uint32_t)((slot & 0xFFF) >> 3) << 10) | (16u << 5) | 16u,
        0xD61F0200u,   // br x16
    };
    if (slotfill_decode(w, (uintptr_t)jit) != slot) {
        g_hook.trampoline = NULL; g_real_wrapper = NULL;
        __atomic_store_n(&g_hook.target, 0, __ATOMIC_RELEASE);
        munmap(tr.mem, 4096); munmap(jit, 4096); munmap(slot_page, 4096);
        return -6;
    }
    pthread_jit_write_protect_np(0);
    memcpy(jit, w, 12);
    sys_icache_invalidate(jit, 12);
    pthread_jit_write_protect_np(1);
    // 5) 生产武装 + 实弹：try_slot_fill 生产实参（slot_arm_target——与
    //    安装路共用一源，实参漂移双侧同红）。
    int rc = try_slot_fill((uintptr_t)jit, slot_arm_target());
    long calls_before = g_hook_calls;
    long r = (rc == 0) ? fn(v0, buf, v2, v3, v4) : -100;
    // 6) 清理：还原入口 + 复位武装态（与 install 失败清理同序），页全归还。
    pthread_jit_write_protect_np(0);
    memcpy(jit, orig, 16);
    sys_icache_invalidate(jit, 16);
    pthread_jit_write_protect_np(1);
    g_hook.trampoline = NULL;
    g_real_wrapper = NULL;
    __atomic_store_n(&g_hook.target, 0, __ATOMIC_RELEASE);
    munmap(tr.mem, 4096); munmap(jit, 4096); munmap(slot_page, 4096);
    if (rc != 0) return -1;
    if (g_hook_calls != calls_before + 1) return -4;   // 96 故障形态：绕过逻辑
    return (r == expect) ? 1 : 0;
}
#else
long wxkeep_runtime_test_hook_transparency(void) { return -2; }   // 非 arm64 宿主
long wxkeep_runtime_test_slot_chain(void) { return -2; }         // 同上（SLOT 链缝）
#endif

int wxkeep_runtime_test_quiesce_count(void) { return g_quiesce_threads; }
long wxkeep_runtime_test_transparency_diff(void) { return g_wxkeep_transparency_diff; }
long wxkeep_runtime_test_transparency_got(void) { return g_wxkeep_transparency_got; }
// 槽位：0..7=x0..x7，8=[sp] 栈参，9=d0，10=d1，11=x30，12=sp
long wxkeep_runtime_test_transparency_slot(int idx, int hooked) {
    if (idx < 0 || idx > 12) return 0;
    uint64_t v = (hooked ? g_wxkeep_transparency_hooked_dump[idx]
                         : g_wxkeep_transparency_base_dump[idx]);
    return (long)v;
}

/// 当前生效文案的字节长度（load_config_file 缝的 tip 断言用）。
int wxkeep_runtime_test_tip_len(void) {
    return (int)tip_len_active();
}

/// 自发撤回判别缝（77 续㉘）：1=改写/清零门放行（非自发 XML），0=自发
/// （「你撤回」needle 命中，原生行为）。锁死 F1 修复的判别器本体。
int wxkeep_runtime_test_keep_gate(const unsigned char *xml, unsigned long len) {
    return find_bytes((uint8_t *)xml, len, kSelfNeedle, sizeof(kSelfNeedle) - 1) ? 0 : 1;
}

/// 热重载缝（77 续㉘）：按生产 maybe_reload_config 的应用面（仅策略键）
/// 装载指定路径配置。返回 0=应用且 hooks 表未动；1=hooks 表被意外触碰
/// （契约破坏）；-1=文件不可解析。
int wxkeep_runtime_test_reload_config(const char *path) {
    if (!path) return -1;
    @autoreleasepool {
        NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:
                                       [NSString stringWithUTF8String:path]];
        if (![cfg isKindOfClass:[NSDictionary class]]) return -1;
        int before = g_ext_hook_count;
        apply_policy_dict(cfg);
        return (g_ext_hook_count == before) ? 0 : 1;
    }
}

/// 当前外部 hooks 表行数（热重载契约断言用）。
int wxkeep_runtime_test_ext_hooks_count(void) { return g_ext_hook_count; }

/// marker 候选目录回落策略缝（77 续）：按序尝试两目录，返回首个「建目录
/// +写 marker」成功的序号（0/1），全败 -1。锁死「Group 写被拒时不回落
/// legacy」缺陷复发（沙盒微信 marker 永久盲区，台账 T4）。
int wxkeep_runtime_test_marker_dirs(const char *d1, const char *d2) {
    if (!d1 || !d2) return -1;
    NSString *dirs[2];
    dirs[0] = [NSString stringWithUTF8String:d1];
    dirs[1] = [NSString stringWithUTF8String:d2];
    return write_marker_first_writable(dirs, 2, @"wxkeep-marker-fallback-probe");
}

long wxkeep_runtime_test_rewrite(unsigned char *data, unsigned long data_len,
                                 const char *tip, unsigned long tip_len) {
    uint8_t sso[24];
    memset(sso, 0, sizeof(sso));
    uint64_t size = data_len;
    uint8_t *ptr = data;
    if (g_sso_layout_arm64) {
        // arm64 变体布局头：{data@0, size@8, cap|flag@0x10（MSB=长）}
        memcpy(sso, &ptr, 8);
        memcpy(sso + 8, &size, 8);
        uint64_t cap = 0x8000000000000000UL;
        memcpy(sso + 16, &cap, 8);
    } else {
        // x64 标准布局头：{tag@0=1, size@8, ptr@0x10}
        sso[0] = 1;
        memcpy(sso + 8, &size, 8);
        memcpy(sso + 16, &ptr, 8);
    }
    char saved_buf[128];
    size_t saved_len = tip_len_active();
    memcpy(saved_buf, tip_text_active(), sizeof(saved_buf));
    if (tip_len >= 128) return -1;
    tip_store_write(tip, tip_len);
    int r = rewrite_replacemsg_inner(sso);
    tip_store_write(saved_buf, saved_len);
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
