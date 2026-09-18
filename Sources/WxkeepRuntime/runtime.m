#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <sys/mman.h>
#import <string.h>
#import <stdlib.h>
#import <os/log.h>

#include "wxkeep_runtime.h"

// wxkeep 运行时组件（可选功能）。
// M-R1：加载证明 + 标记文件。
// M-R2：撤回提示文本替换——hook 撤回解析汇点 wrapper，在其入口把
//       sysmsg XML 中 <replacemsg> 的内文等长改写为 runtime.json 文案，
//       下游（解析结果/入库/会话预览/渲染/历史重扫）全部拿到自定义文本。
//
// hook 点位（drive22 全链实证，docs/ROADMAP ⑦ 终验定案）：
//  - isRevokemsg 全程只收 "revokemsg" 类型串（40+ 次实测无一例外）——
//    「hook isRevokemsg 改写内容 SSO」前提证伪，isRevokemsg 是纯类型谓词。
//  - wrapper [0x537d910..0x537db40)@270099 是 A 到达解析 / B 二次解析 /
//    D 历史批扫三条路径的唯一公共汇点（每个 parse 命中的调用者都是
//    wrapper 内 0x537dad3 的 call）。
//  - wrapper(rdi=信息对象, rsi=消息结构)：撤回 sysmsg XML 的 SSO 嵌在
//    rsi+0x130（tag@+0x130 / size@+0x138 / ptr@+0x140）。wrapper 先把它
//    拷入 rdi+0x1d0（SSO copy），再调 parse(rdi, rsi+0x130, &ok)——入口处
//    改写 XML 即让全链一致（连 DB 持久化都是自定义文本）。
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
// 地址表（每构建一行；expected = 目标函数入口前 12 字节，防漂移门）
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t hook_off;          // hook 目标（wrapper）在 wechat.dylib 内的 VM 偏移
    uint64_t msg_arg;           // 消息结构在第几个整型参数（1=rsi）
    uint64_t xml_sso_off;       // 撤回 XML SSO 字段在消息结构内的偏移
    uint8_t expected[12];       // 入口 12 字节原像（须为纯栈操作序言）
} hook_target_t;

// 270099 x64 — 撤回解析汇点 wrapper（0x537d910，与 parse 0x537db40 同簇）。
// 序言 12B = push rbp; mov rbp,rsp; push r15/r14/r13/r12 —— 无 rip 相对，
// 蹦床换址执行安全（pristine 与已打补丁的安装二进制实测一致）。
static const hook_target_t kTarget270099 = {
    0x537d910,
    1,
    0x130,
    {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54},
};

typedef struct {
    const char *build;
    const char *uuid;
    const hook_target_t *target;
} build_entry_t;

static const build_entry_t kBuilds[] = {
    { "270099", "97e21436-abda-3b79-bec0-ef2653c6b423", &kTarget270099 },
};
static const size_t kBuildCount = sizeof(kBuilds) / sizeof(kBuilds[0]);

// ---------------------------------------------------------------------------
// 配置（Application Support/wxkeep/runtime.json）
// ---------------------------------------------------------------------------

static char g_tip_text[128];       // 固定文案（NUL 结尾，UTF-8）
static size_t g_tip_len;
static int g_hook_installed;
// 诊断（marker 回写）：0=未尝试 1=UUID 不匹配 2=序言不匹配
// 3=mmap/mprotect 失败 4=已武装；bit8=回调已触发
static int g_hook_status;
enum { kStIdle = 0, kStUuidMismatch = 1, kStPrologueMismatch = 2,
       kStInstallFail = 3, kStArmed = 4, kStCallbackBit = 8,
       kStScanMissed = 16 };
static char g_probe_name[96];   // 构造器期匹配到的镜像名样本（诊断）

void write_marker(void);   // 容器路径回写（armed 后状态翻转）
static volatile int32_t g_arm_done;   // 整个进程只装一次（多触发源竞态防御）
static const char kTarget270099_uuid[] = "97e21436-abda-3b79-bec0-ef2653c6b423";
static int uuid_matches(const struct mach_header_64 *hdr, const char *want);
static char g_last_uuid[40];     // 回调收到的最后一个镜像 UUID
static int g_cb_count;           // 回调触发计数
static int g_scan_missed;

static NSString *runtimeConfigPath(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, YES);
    if (dirs.count == 0) return nil;
    return [[dirs[0] stringByAppendingPathComponent:@"wxkeep"]
        stringByAppendingPathComponent:@"runtime.json"];
}

static void load_config(void) {
    NSString *path = runtimeConfigPath();
    if (!path) return;
    NSDictionary *cfg = [NSDictionary dictionaryWithContentsOfFile:path];
    if (![cfg isKindOfClass:[NSDictionary class]]) return;
    NSString *text = cfg[@"tip_text"];
    if (![text isKindOfClass:[NSString class]] || text.length == 0) return;
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    if (data.length == 0 || data.length >= sizeof(g_tip_text)) return;
    // 文案最终嵌入 <replacemsg> 内文（XML 文本节点）：剥掉会破坏标签/实体的
    // < > & 三种字符（长度随之收缩），其余（含 emoji/引号）原样保留。
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

/// 提示内文等长改写（M-R2 核心，drive25 实弹定案语义）：
///  - 只动 SSO 指向的数据缓冲内部，SSO 结构/分配器零接触；
///  - 内文须含「撤回」needle（类型门：非撤回消息绝不动）；
///  - 依次尝试 <content>（270099 实测线上形态）与 <replacemsg>（静态备选），
///    内文可选 <![CDATA[ 包裹（跳过前缀、闭合标签定界）；
///  - 文案长于内文 → 放弃（保原文）；短于内文 → 空格填充到等长。
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
    if (inner_len < kNeedleLen || g_tip_len > inner_len) return 0;
    if (!find_bytes(inner, inner_len, kRevokeNeedle, kNeedleLen)) return 0;
    memcpy(inner, g_tip_text, g_tip_len);
    memset(inner + g_tip_len, ' ', inner_len - g_tip_len);
    return 1;
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
// inline hook（x86_64：入口 12B → movabs rax, hook; jmp rax）
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t saved[12];        // 原入口字节（已重定位的运行时原像）
    void *trampoline;         // RWX 蹦床：saved 12B + jmp target+12
    uintptr_t target;
    uint64_t msg_arg;
    uint64_t xml_sso_off;
} hook_ctx_t;

static hook_ctx_t g_hook;

// SysV：前 6 个整型参数 = rdi,rsi,rdx,rcx,r8,r9。wrapper 实测 rdi=信息对象、
// rsi=消息结构（XML SSO 嵌 +0x130），以 6×void* 透传还原现场。
static void *(*g_real_wrapper)(void *, void *, void *, void *, void *, void *);

static void *revoke_wrapper_hook(void *a0, void *a1, void *a2,
                                 void *a3, void *a4, void *a5) {
    if (g_hook.target && g_tip_len) {
        void *args[6] = {a0, a1, a2, a3, a4, a5};
        uint8_t *msg = (uint8_t *)args[g_hook.msg_arg];
        if (msg > (uint8_t *)0x10000) {
            rewrite_replacemsg_inner(msg + g_hook.xml_sso_off);
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
    uint8_t prologue[12];
    memcpy(prologue, (void *)target, 12);
    if (memcmp(prologue, t->expected, 12) != 0) {
        os_log(OS_LOG_DEFAULT, "[wxkeep-runtime] prologue mismatch — hook skipped");
        g_hook_status |= kStPrologueMismatch;
        return -1;
    }
    // 蹦床：RWX 页内 = 原入口 12B 指令 + movabs r11,target+12 + jmp r11。
    // 目标入口由地址表保证是纯栈操作序言（无 rip 相对），换址执行安全。
    uint8_t *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) { g_hook_status |= kStInstallFail; return -1; }
    memcpy(mem, prologue, 12);
    uint64_t back = target + 12;
    memcpy(mem + 12, "\x49\xbb", 2);            // movabs r11, imm64
    memcpy(mem + 14, &back, 8);
    memcpy(mem + 22, "\x41\xff\xe3", 3);        // jmp r11

    g_hook.target = target;
    g_hook.msg_arg = t->msg_arg;
    g_hook.xml_sso_off = t->xml_sso_off;
    memcpy(g_hook.saved, prologue, 12);
    g_hook.trampoline = mem;
    g_real_wrapper = (void *(*)(void *, void *, void *, void *, void *, void *))mem;

    uintptr_t page = target & ~(uintptr_t)0xfff;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        g_hook_status |= kStInstallFail;
        return -1;
    }
    uint8_t stub[12];
    uint64_t hook = (uint64_t)&revoke_wrapper_hook;
    memcpy(stub, "\x48\xb8", 2);                // movabs rax, imm64
    memcpy(stub + 2, &hook, 8);
    memcpy(stub + 10, "\xff\xe0", 2);           // jmp rax
    memcpy((void *)target, stub, 12);
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
    while (p < end) {
        uint32_t cmd, size;
        memcpy(&cmd, p, 4); memcpy(&size, p + 4, 4);
        if (cmd == LC_UUID && size >= 24) {
            memcpy(uuid, p + 8, 16);
            found = 1;
            break;
        }
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
    for (size_t i = 0; i < kBuildCount; i++) {
        if (uuid_matches(hdr, kBuilds[i].uuid)) {
            if (install_hook(kBuilds[i].target, (uintptr_t)hdr) == 0) {
                g_hook_installed = 1;
                g_hook_status = kStArmed;
                os_log(OS_LOG_DEFAULT,
                       "[wxkeep-runtime] M-R2 hook armed build=%{public}@",
                       @(kBuilds[i].build));
                // marker 不在这里回写：本函数可能在 add_image 回调（dyld 持锁）
                // 上下文执行，Foundation 磁盘 I/O 不该发生在那里；armed 态的
                // marker 由构造器尾部 / arm_late / 定时器在安全上下文回写。
            }
            return;
        }
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
        while (p < end) {
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

void write_marker(void) {
    @autoreleasepool {
        NSString *dir = @"~/Library/Application Support/wxkeep";
        dir = [dir stringByExpandingTildeInPath];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *marker = [dir stringByAppendingPathComponent:@"runtime.marker"];
        NSString *now = [NSString stringWithFormat:
            @"loaded ts=%f mr2=%@ status=%d probe=%@\n",
            [NSDate date].timeIntervalSince1970,
            g_hook_installed ? @"hook-armed" : @"marker-only", g_hook_status,
            [NSString stringWithFormat:@"cb=%d last=%@ scanmiss=%d probe=%@",
                g_cb_count,
                g_last_uuid[0] ? @(g_last_uuid) : @"<none>",
                g_scan_missed,
                g_probe_name[0] ? @(g_probe_name) : @"<none>"]];
        [now writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[wxkeep-runtime] loaded, marker at %@, mr2=%d", marker, g_hook_installed);
    }
}

// ---- 迟到装载兜底 ----
// 实证（2026-09-18，macOS 15 dyld4）：wechat.dylib 由壳程序延迟装载且
// **不经过 add_image 通知**（回调 1000+ 次无它，但它确在 dyld 镜像表中，
// index 209 >> 本 dylib 的 2）。因此除回调外增加两个兜底触发源：
//   a) NSApplicationDidFinishLaunchingNotification —— UI 就绪即 wechat.dylib
//      已完全初始化，此时刻挂 inline hook 是各注入框架的标准时机；
//   b) 有界轮询（30 次 × 500ms，全局队列）—— 非 UI 辅助进程兜底。
// g_arm_done CAS 保证只装一次；扫到即装，无 tap 亦无害。
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
        // 必须检查**当前** protection 而非仅 max_protection：PROT_NONE 的
        // 保留区（共享缓存孔洞等）max_protection 可含 X，解引用即 SIGSEGV
        // （0x7ff800000000 实测）。可读才允许触碰 header。
        if ((bi.protection & VM_PROT_READ)
            && (bi.max_protection & VM_PROT_EXECUTE) && size >= 0x4000000
            && (addr & 0xfff) == 0) {
            const struct mach_header_64 *hdr = (const struct mach_header_64 *)addr;
            if (hdr->magic == MH_MAGIC_64
                && uuid_matches(hdr, kTarget270099_uuid)) {
                return (uintptr_t)hdr;
            }
        }
        addr += size;
        if (addr < size) break;    // 回绕保护
    }
    return 0;
}

static void scan_and_arm(void) {
    if (g_hook_installed) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (uuid_matches((const struct mach_header_64 *)mh, kTarget270099_uuid)) {
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
    dispatch_source_set_event_handler(timer, ^{
        scan_and_arm();
        if (g_hook_installed || ++ticks >= 30) {
            if (g_hook_installed) write_marker();
            dispatch_source_cancel(timer);
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
    // 既有镜像线性扫描（wechat.dylib 可能早于本 dylib 加载）——按 UUID 直查
    {
        uint32_t n = _dyld_image_count();
        int found = 0;
        for (uint32_t i = 0; i < n; i++) {
            const struct mach_header *mh = _dyld_get_image_header(i);
            if (uuid_matches((const struct mach_header_64 *)mh, kTarget270099_uuid)) {
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
