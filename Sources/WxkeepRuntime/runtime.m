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
    // V3-M2 克隆第二挂点（可选；105 轮缝位定案 seam B）——撤回写点（消息
    // 对象原地改写执行体）的入口三件。行不带 = 单点武装（向后兼容）；
    // 带则 arm 期与主 hook 并行填第二 SLOT（槽位 1），指针指向克隆 thunk。
    uint64_t clone_hook_off;
    uint8_t clone_expected[16]; // 写点入口原像（恰 16B：12B 补丁门 + 蹦床
                                // 重放源；108 轮 P0 修——12B 行=重放 4B 零=UDF）
    uint8_t has_clone;
    uint32_t clone_func_size;   // 写点函数级身份门（可选）
    uint8_t has_clone_func_size;
    // R6 证据步（110 轮）：consumer 成员服务对象（this+0xb78 pointee）的
    // vtable 切片偏移——RE 定案 0x9deeb48（setter 0x3199f78 内联构造的双
    // vtable 多继承对象，0x9dee000 页 +0xb48）。带此字段的行，克隆 hook 体
    // 内核读 [x19+0xb78]→[svc+0] 与 base+off 比对：命中计数 clsvc= 是
    // 「x19=consumer this 运行时假设」的真机证据位（零宿主调用，纯读）。
    uint32_t clone_svc_vtable;
    uint8_t has_clone_svc_vtable;
    // R6 读路径直调表（111 轮，docs/RUNTIME-DESIGN 111 节合同）：异步工作
    // 函数按 msgid 重查消息对象的宿主函数组。九字段**成组出现**（任一在
    // 场则全组必须完整，否则整行拒绝——clone_hook_off 成对门同哲学）。
    // 安装期对 clone_rd_lookup 过函数身份门（FUNCTION_STARTS 距离 + 入口
    // 16B 锚 memcmp），失配 → 直调表不武装（worker 惰性，clmiss 语义不变）。
    uint32_t clone_rd_lookup_off;      // svrid 查找 0x32edaec（sret 五参）
    uint32_t clone_rd_lookup_fs;       // lookup 的函数距离（身份门①）
    uint8_t clone_rd_lookup_head[16];  // lookup 入口 16B 原像（身份门②）
    uint32_t clone_rd_wrap_off;        // wrap 0x309ac50（拷贝+dynamic_cast）
    uint32_t clone_rd_getter_off;      // getter 0x102b740（sret {obj,ctl}）
    uint32_t clone_rd_x2single_off;    // 全局单例 get 0x571ce74（out ctl, &slot）
    uint32_t clone_rd_x2desc_off;      // 单例描述符槽 0xa3de0a70（切片偏移）
    uint32_t clone_rd_x2ctx_off;       // ctx 获取 0x5720308（&p, NULL）
    uint32_t clone_rd_key_slot;        // consumer_main 帧内 key 串对象的 sp 偏移（0x3a0）
    // R11 parse 锚定加订（可选三件套；在场必须 rd 组完整——keyctor 是
    // rd 直调族成员，单独在场的行=笔误整行拒绝）：key 构造 0x4a2b524
    //（sret 24B 串对象, x0=parse msg 对象）+ fs/head 双身份门。
    uint32_t clone_rd_keyctor_off;
    uint32_t clone_rd_keyctor_fs;
    uint8_t clone_rd_keyctor_head[16];
    uint8_t has_clone_rd;
    // M4 插入直调表（113 轮 R8 RE 定案，docs/RUNTIME-DESIGN R8 节）：
    // ctor 0x34597c8（x0=源消息对象, x1=容器, w2=0xa 文本分支, sret 32B
    // {vtable@+0=clone_ins_msg_vt, 自引用槽@+8, ctl@+0x18}）与
    // AddMessageResource 0x33fd190（x0=publisher, x1=&16B pair{obj,ctl},
    // x2=&24B 零置 outvec；体内=32B 任务包装 vtable 0x9df7c38 → 写枢纽
    // post——纯异步，任意线程同步调用安全）。七字段成组；pub_vt 可选
    //（publisher 认证门=[[读svc+8]] 的 vtable——R8 定案 publisher=订阅期
    // 绑定、静态对象图不可达，270135 不带 = 探针-only，插入调用恒惰性）。
    uint32_t clone_ins_ctor_off;
    uint32_t clone_ins_ctor_fs;     // ctor 身份门①（FUNCTION_STARTS 距离）
    uint8_t clone_ins_ctor_head[16];// ctor 身份门②（入口 16B 原像）
    uint32_t clone_ins_amr_off;
    uint32_t clone_ins_amr_fs;      // amr 身份门①
    uint8_t clone_ins_amr_head[16]; // amr 身份门②
    uint32_t clone_ins_msg_vt;      // msg 类 vtable（0x9f24930）
    uint32_t clone_ins_pub_vt;      // 可选：publisher 认证 vtable
    uint8_t has_clone_ins_pub_vt;
    uint8_t has_clone_ins;
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
/// 一致快照（108 轮修）：text/len 分两次读 g_tip_which，热重载翻转的瞬间
/// 会拼出新槽长度 + 旧槽缓冲。读一次索引派生两者，撕裂窗归零（单次改写
/// 不再可能带进前一文案的残余字节）。
static const char *tip_active_snapshot(size_t *len) {
    int w = g_tip_which;
    *len = g_tip_store_len[w];
    return g_tip_store[w];
}
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

// R5 配对槽前置声明（定义在 R4 写点捕获节；tentative 合并）——
// clone_capture 暂存侧在本节，先声明后用。
static uint64_t g_clone_pending_msgid;
static uint64_t g_clone_pending_ts;
static char g_clone_pending_fromusr[64];
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

// ---------------------------------------------------------------------------
// V3-M2 克隆原型缝（R1 骨架起建，R4/R5 增写点捕获与配对，2026-11-01，
// docs/V3-CHARTER.md M2）：
// 实验键 clone_message（默认关）。hook 体在非自发分支、**先于 keep_message
// 清零**（清零会改写我们捕获的数字）只读提取撤回 XML 的 <newmsgid>/
// <fromusr>，深拷贝成堆事件后派发到私有串行队列——hook 线程零宿主调用、
// 零 DB 触碰（风险#2 线程亲和的时序解耦，charter §1）。工作函数的宿主
// 直调表有意未接：消息表读/插入族是 M2-R2 的 RE 目标（charter §1 只对位
// 了读路径锚点，插入族从未定位）。无方法 → 计 g_clone_nomethods 丢弃：
// 机制链（配置→hook→捕获→队列→工作→marker）全程被真实驱动且可证惰性，
// 数据行入库即活。
// 自发撤回不克隆——selfskip 门先于克隆判定（M3「自撤不克隆」提前钉入）。
static int g_clone_message;        // 实验开关（runtime.json clone_message，默认关）
static volatile int g_clone_captures;    // 捕获派发计数
static volatile int g_clone_skips;       // 无 newmsgid（非撤回形态/短串）跳过计数
static volatile int g_clone_nomethods;   // 工作函数无宿主方法表丢弃计数（R2 接表后归零语义）
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

/// NSString → C 串的 nil 安全版（110 轮修）：未配对代理等畸形内容会让
/// UTF8String 返回 nil，直传下游 = NULL 解引用（构造器 SIGSEGV）。runtime.json
/// 在微信自己的 App Group 容器（腾讯可写，威胁模型在案）——「任何字段坏 →
/// 整行丢弃」的哲学必须在字符串→C 串这一步也成立。空串自然过不了后续
/// 形制门（长度/hex 解析），与 nil 同路收敛。
static const char *ns_u8(NSString *s) {
    const char *p = s.UTF8String;
    return p ? p : "";
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
        if ((w & 0xBF000000u) == 0x18000000u) return 0;   // LDR literal（32/64）
        // 108 轮补门：旧 mask 漏 LDRSW-literal(0x98)/PRFM-literal(0xD8) 与
        // b.cond(0x54)——全是 PC 相对编码，换址重放即跳错目标。反证：全部
        // 现役行（F85FBCA9… 家族 / FFC302D1…+F85F07A9 / 零填充测试向量）
        // 4B 对齐均不含三族首字——零误拒。
        if ((w & 0xFF000000u) == 0x54000000u) return 0;   // b.cond（imm19 PC 相对）
        if ((w & 0xFF000000u) == 0x98000000u) return 0;   // LDRSW literal
        if ((w & 0xFF000000u) == 0xD8000000u) return 0;   // PRFM literal
        // 111 轮补门（审计 P1）：寄存器间接跳转族（BR/BLR/RET 及 PAC 变体
        // 全在 0xD6 首字节）与陷阱/系统空间（0xD4=HLT/BRK/DCPS、
        // 0xD5=MSR/SYS/AT/TLBI——hint/NOP 误拒按「宁拒不挂」接受）。
        // 动机：补丁态的蹦床重放源 100% 来自行字节（磁盘原 12B 已被入口
        // 补丁覆盖，运行时无第二信源可比对）——PC 相对门只封了显式转移，
        // `br x0` 一条即任意控制流。现役行首字节 FF/F8/F6/F4/FD 全不含
        // 0xD4-D6，零误拒。
        if ((w >> 24) == 0xD4 || (w >> 24) == 0xD5 || (w >> 24) == 0xD6) return 0;
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
    if (!uuid_str_valid(ns_u8(uuid))) return 0;
    // hook_off/clone_hook_off 用严格 hex 解析（110 轮修）：strtoull 静默吞
    // 尾部垃圾（"0x537db4ZZZ" → 0x537db4）——位置字段的笔误会以静默错址
    // 落地，只剩序言门兜底。与 anchor_va 的 parse_hex_u32 同规（宽严一致）。
    {
        uint32_t v = 0;
        if (!parse_hex_u32(ns_u8(off), &v) || v == 0) return 0;
        out->hook_off = v;
    }
    out->msg_arg = marg ? marg.unsignedLongValue : 1;
    // xml_sso_off 必须显式给出：它决定 hook 从哪个地址读 SSO 头，缺省值
    // （旧 wrapper 模型的 0x130）在 parse 直挂语义下是错误偏移——缺字段
    // 的行按「宁可不挂也不挂错」整行拒绝，而不是静默读错位置。
    if (!soff) return 0;
    out->xml_sso_off = soff.unsignedLongValue;
    if (out->msg_arg > 5 || out->xml_sso_off > 0x1000) return 0;
    out->is_arm64 = [arch isEqualToString:@"arm64"];
    out->expected_len = out->is_arm64 ? 16 : 12;
    if (parse_hex(ns_u8(exp), out->expected, sizeof(out->expected)) != out->expected_len) {
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
        if (!parse_hex_u32(ns_u8(ava), &out->anchor_va)) return 0;
        size_t n = parse_hex(ns_u8(aby), out->anchor, sizeof(out->anchor));
        if (n == 0) return 0;
        out->anchor_len = (uint8_t)n;
    }
    // V3-M2 克隆第二挂点（可选）：clone_hook_off + clone_expected 成对出现；
    // 单边 = 行作者笔误，整行拒绝（宁可不挂也不挂错）。arm64 行专属——
    // x64 行带此字段按坏行处理（克隆缝仅 arm64 布局派生）。
    //
    // 克隆套件顶层门（113 轮体检 P2 修）：svc_vtable/rd 组/ins 组/func_size
    // 的解析全嵌套在「克隆对在场」块内——孤儿字段（带任一套件键而无
    // clone_hook_off+clone_expected，含键名笔误与 x64 行误带）此前被静默
    // 丢弃：行照常接受、字段永不武装、零 bootlog/marker 信号（探针惰性
    // 无从排障）。武装点要求 has_clone（arm_clone_site 只在 t->has_clone
    // 进入），孤儿字段在现行代码不存在合法场景——任一套件键在场而无对
    // （或非 arm64）即整行拒绝（rd 组 111 轮以来同构洞一并收口）。
    NSString *coff = [row[@"clone_hook_off"] isKindOfClass:[NSString class]] ? row[@"clone_hook_off"] : nil;
    NSString *cexp = [row[@"clone_expected"] isKindOfClass:[NSString class]] ? row[@"clone_expected"] : nil;
    static NSString *const kCloneSuiteKeys[] = {
        @"clone_func_size", @"clone_svc_vtable",
        @"clone_rd_lookup", @"clone_rd_lookup_fs", @"clone_rd_lookup_head",
        @"clone_rd_wrap", @"clone_rd_getter", @"clone_rd_x2single",
        @"clone_rd_x2desc", @"clone_rd_x2ctx", @"clone_rd_key_slot",
        @"clone_rd_keyctor", @"clone_rd_keyctor_fs", @"clone_rd_keyctor_head",
        @"clone_ins_ctor", @"clone_ins_ctor_fs", @"clone_ins_ctor_head",
        @"clone_ins_amr", @"clone_ins_amr_fs", @"clone_ins_amr_head",
        @"clone_ins_msg_vt", @"clone_ins_pub_vt",
    };
    BOOL csAny = (coff || cexp);
    if (!csAny) {
        for (size_t i = 0; i < sizeof(kCloneSuiteKeys) / sizeof(kCloneSuiteKeys[0]); i++) {
            if (row[kCloneSuiteKeys[i]] != nil) { csAny = YES; break; }
        }
    }
    if (csAny) {
        if (!(coff && cexp)) return 0;
        if (!out->is_arm64) return 0;
        uint32_t cv = 0;
        if (!parse_hex_u32(ns_u8(coff), &cv) || cv == 0) return 0;
        out->clone_hook_off = cv;
        // clone_expected 必须恰 16B（108 轮 P0 修）：蹦床重放源是本字段的
        // 完整 16B，而入口补丁只盖 12B——行带 12B 时补丁态分支 memcpy 16B
        // 会把 [12..16) 的 memset 零当第 4 指令重放 = UDF #0 = 首次撤回
        // 写点调用即 SIGILL（与 clone_message 开关无关——thunk 透传也尾跳
        // 蹦床）。主 hook 的 expected 同款精确长度纪律（!= 16 拒）。
        if (parse_hex(ns_u8(cexp), out->clone_expected, sizeof(out->clone_expected)) != 16) return 0;
        if (!arm64_prologue_relocatable(out->clone_expected, 16)) return 0;
        out->has_clone = 1;
        NSNumber *cfsz = [row[@"clone_func_size"] isKindOfClass:[NSNumber class]] ? row[@"clone_func_size"] : nil;
        if (cfsz) {
            unsigned long v = cfsz.unsignedLongValue;
            if (v == 0 || v > (1UL << 21)) return 0;
            out->clone_func_size = (uint32_t)v;
            out->has_clone_func_size = 1;
        }
        // R6 证据步（110 轮）：可选 clone_svc_vtable（hex，切片偏移）。
        // 坏值整行拒绝——它是对内核读结果的比对基准，假门比没门糟。
        NSString *csvt = [row[@"clone_svc_vtable"] isKindOfClass:[NSString class]] ? row[@"clone_svc_vtable"] : nil;
        if (csvt) {
            uint32_t v = 0;
            if (!parse_hex_u32(ns_u8(csvt), &v) || v == 0) return 0;
            out->clone_svc_vtable = v;
            out->has_clone_svc_vtable = 1;
        }
        // R6 读路径直调表（111 轮）：九字段成组——任一在场则全组必须完整
        //（缺任一 = 行作者笔误，整行拒绝）。全部严格 hex（hook_off 同规：
        // strtoull 吞尾部垃圾 = 错址直调，身份门锚字节同拒绝半合法值）。
        // lookup 头锚恰 16B（蹦床重放源同款精确长度纪律）。
        NSString *rdl = [row[@"clone_rd_lookup"] isKindOfClass:[NSString class]] ? row[@"clone_rd_lookup"] : nil;
        NSString *rdf = [row[@"clone_rd_lookup_fs"] isKindOfClass:[NSString class]] ? row[@"clone_rd_lookup_fs"] : nil;
        NSNumber *rdfn = [row[@"clone_rd_lookup_fs"] isKindOfClass:[NSNumber class]] ? row[@"clone_rd_lookup_fs"] : nil;
        NSString *rdh = [row[@"clone_rd_lookup_head"] isKindOfClass:[NSString class]] ? row[@"clone_rd_lookup_head"] : nil;
        NSString *rdw = [row[@"clone_rd_wrap"] isKindOfClass:[NSString class]] ? row[@"clone_rd_wrap"] : nil;
        NSString *rdg = [row[@"clone_rd_getter"] isKindOfClass:[NSString class]] ? row[@"clone_rd_getter"] : nil;
        NSString *rds = [row[@"clone_rd_x2single"] isKindOfClass:[NSString class]] ? row[@"clone_rd_x2single"] : nil;
        NSString *rdd = [row[@"clone_rd_x2desc"] isKindOfClass:[NSString class]] ? row[@"clone_rd_x2desc"] : nil;
        NSString *rdc = [row[@"clone_rd_x2ctx"] isKindOfClass:[NSString class]] ? row[@"clone_rd_x2ctx"] : nil;
        NSString *rdk = [row[@"clone_rd_key_slot"] isKindOfClass:[NSString class]] ? row[@"clone_rd_key_slot"] : nil;
        if (rdl || rdh || rdw || rdg || rds || rdd || rdc || rdk || rdf || rdfn) {
            if (!(rdl && rdh && rdw && rdg && rds && rdd && rdc && rdk)) return 0;
            uint32_t v;
            if (!parse_hex_u32(ns_u8(rdl), &v) || v == 0) return 0;
            out->clone_rd_lookup_off = v;
            if (!parse_hex_u32(ns_u8(rdw), &v) || v == 0) return 0;
            out->clone_rd_wrap_off = v;
            if (!parse_hex_u32(ns_u8(rdg), &v) || v == 0) return 0;
            out->clone_rd_getter_off = v;
            if (!parse_hex_u32(ns_u8(rds), &v) || v == 0) return 0;
            out->clone_rd_x2single_off = v;
            if (!parse_hex_u32(ns_u8(rdd), &v) || v == 0) return 0;
            out->clone_rd_x2desc_off = v;
            if (!parse_hex_u32(ns_u8(rdc), &v) || v == 0) return 0;
            out->clone_rd_x2ctx_off = v;
            if (!parse_hex_u32(ns_u8(rdk), &v)) return 0;   // 帧偏移可为小值（0x3a0）
            out->clone_rd_key_slot = v;
            // lookup 身份门字段（组内必选，非可选——直调是最重放宽面，身份
            // 缺失 = 无门直调，比不直调更糟）：fs 为十进制/整数字段，head 恰 16B。
            unsigned long fs = 0;
            if (rdfn) {
                fs = rdfn.unsignedLongValue;
            } else if (rdf) {
                uint32_t fv = 0;
                if (!parse_hex_u32(ns_u8(rdf), &fv)) return 0;
                fs = fv;
            } else {
                return 0;
            }
            if (fs == 0 || fs > (1UL << 21)) return 0;
            out->clone_rd_lookup_fs = (uint32_t)fs;
            if (parse_hex(ns_u8(rdh), out->clone_rd_lookup_head,
                          sizeof(out->clone_rd_lookup_head)) != 16) return 0;
            out->has_clone_rd = 1;
        }
        // R11 parse 锚定加订（可选三件套，rd 组块外独立判定）：任一在场
        // 则必须 rd 组完整（keyctor 是 rd 直调族成员，脱离主组 = 笔误）
        // 且全三完整合法（fs 双形态同 rd 组；head 恰 16B）。
        NSString *kc = [row[@"clone_rd_keyctor"] isKindOfClass:[NSString class]] ? row[@"clone_rd_keyctor"] : nil;
        NSString *kcfs = [row[@"clone_rd_keyctor_fs"] isKindOfClass:[NSString class]] ? row[@"clone_rd_keyctor_fs"] : nil;
        NSNumber *kcfsn = [row[@"clone_rd_keyctor_fs"] isKindOfClass:[NSNumber class]] ? row[@"clone_rd_keyctor_fs"] : nil;
        NSString *kch = [row[@"clone_rd_keyctor_head"] isKindOfClass:[NSString class]] ? row[@"clone_rd_keyctor_head"] : nil;
        if (kc || kcfs || kcfsn || kch) {
            if (!out->has_clone_rd) return 0;
            if (!(kc && kch && (kcfs || kcfsn))) return 0;
            uint32_t kv = 0;
            if (!parse_hex_u32(ns_u8(kc), &kv) || kv == 0) return 0;
            out->clone_rd_keyctor_off = kv;
            unsigned long kfs = 0;
            if (kcfsn) kfs = kcfsn.unsignedLongValue;
            else { uint32_t fv = 0; if (!parse_hex_u32(ns_u8(kcfs), &fv)) return 0; kfs = fv; }
            if (kfs == 0 || kfs > (1UL << 21)) return 0;
            out->clone_rd_keyctor_fs = (uint32_t)kfs;
            if (parse_hex(ns_u8(kch), out->clone_rd_keyctor_head,
                          sizeof(out->clone_rd_keyctor_head)) != 16) return 0;
        }
        // M4 插入直调表（113 轮 R8）：七字段成组（ctor/amr 各带 fs+head 双
        // 身份门 + msg_vt——直调是最重放宽面，两个入口都要门），pub_vt 可选
        //（认证门——不带 = 探针-only 模式）。任一非 pub 字段在场则全组必须
        // 完整，缺任一 = 行作者笔误，整行拒绝（rd 组同哲学）。
        NSString *ictor = [row[@"clone_ins_ctor"] isKindOfClass:[NSString class]] ? row[@"clone_ins_ctor"] : nil;
        NSString *ictfS = [row[@"clone_ins_ctor_fs"] isKindOfClass:[NSString class]] ? row[@"clone_ins_ctor_fs"] : nil;
        NSNumber *ictfN = [row[@"clone_ins_ctor_fs"] isKindOfClass:[NSNumber class]] ? row[@"clone_ins_ctor_fs"] : nil;
        NSString *icth = [row[@"clone_ins_ctor_head"] isKindOfClass:[NSString class]] ? row[@"clone_ins_ctor_head"] : nil;
        NSString *iamr = [row[@"clone_ins_amr"] isKindOfClass:[NSString class]] ? row[@"clone_ins_amr"] : nil;
        NSString *iamfS = [row[@"clone_ins_amr_fs"] isKindOfClass:[NSString class]] ? row[@"clone_ins_amr_fs"] : nil;
        NSNumber *iamfN = [row[@"clone_ins_amr_fs"] isKindOfClass:[NSNumber class]] ? row[@"clone_ins_amr_fs"] : nil;
        NSString *iamh = [row[@"clone_ins_amr_head"] isKindOfClass:[NSString class]] ? row[@"clone_ins_amr_head"] : nil;
        NSString *imvt = [row[@"clone_ins_msg_vt"] isKindOfClass:[NSString class]] ? row[@"clone_ins_msg_vt"] : nil;
        NSString *ipvt = [row[@"clone_ins_pub_vt"] isKindOfClass:[NSString class]] ? row[@"clone_ins_pub_vt"] : nil;
        if (ictor || icth || iamr || iamh || imvt || ictfS || ictfN || iamfS || iamfN || ipvt) {
            if (!(ictor && icth && iamr && iamh && imvt)) return 0;
            uint32_t v;
            if (!parse_hex_u32(ns_u8(ictor), &v) || v == 0) return 0;
            out->clone_ins_ctor_off = v;
            if (!parse_hex_u32(ns_u8(iamr), &v) || v == 0) return 0;
            out->clone_ins_amr_off = v;
            if (!parse_hex_u32(ns_u8(imvt), &v) || v == 0) return 0;
            out->clone_ins_msg_vt = v;
            unsigned long cfs = 0;
            if (ictfN) cfs = ictfN.unsignedLongValue;
            else if (ictfS) { uint32_t fv = 0; if (!parse_hex_u32(ns_u8(ictfS), &fv)) return 0; cfs = fv; }
            else return 0;
            if (cfs == 0 || cfs > (1UL << 21)) return 0;
            out->clone_ins_ctor_fs = (uint32_t)cfs;
            unsigned long afs = 0;
            if (iamfN) afs = iamfN.unsignedLongValue;
            else if (iamfS) { uint32_t fv = 0; if (!parse_hex_u32(ns_u8(iamfS), &fv)) return 0; afs = fv; }
            else return 0;
            if (afs == 0 || afs > (1UL << 21)) return 0;
            out->clone_ins_amr_fs = (uint32_t)afs;
            if (parse_hex(ns_u8(icth), out->clone_ins_ctor_head,
                          sizeof(out->clone_ins_ctor_head)) != 16) return 0;
            if (parse_hex(ns_u8(iamh), out->clone_ins_amr_head,
                          sizeof(out->clone_ins_amr_head)) != 16) return 0;
            out->has_clone_ins = 1;
            if (ipvt) {
                uint32_t pv = 0;
                if (!parse_hex_u32(ns_u8(ipvt), &pv) || pv == 0) return 0;
                out->clone_ins_pub_vt = pv;
                out->has_clone_ins_pub_vt = 1;
            }
        }
    }
    strlcpy(out->uuid, ns_u8(uuid), sizeof(out->uuid));
    NSString *build = [row[@"build"] isKindOfClass:[NSString class]] ? row[@"build"] : @"?";
    strlcpy(out->build, ns_u8(build), sizeof(out->build));
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
    // clone_message：V3-M2 克隆原型缝（默认关；M2-R5=XML 捕获+写点捕获+
    // msgid↔content 配对+证据，插入调用在认证值+容器合同落地前恒惰性——clmiss= 是
    // 「机制在跑且惰性」
    // 的证据位，非故障）
    id cm = cfg[@"clone_message"];
    g_clone_message = (cm == nil) ? 0 : [cm boolValue];
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
    // {from} 展开（仅当文案里真的写了占位符）；文案/长度取一致快照
    char eff[128 + 64];
    size_t eff_len;
    size_t tip_now_len = 0;
    const char *tip_now = tip_active_snapshot(&tip_now_len);
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
// V3-M2 克隆捕获（只读面）：zero_tag_digits 的提取孪生 + 文本标签提取。
// 与 zero 的区别：不改写缓冲（hook 体在清零**前**调用，顺序即语义）。
// ---------------------------------------------------------------------------

/// <tag> 的数字提取（等长清零的只读孪生）。返回 1 = 提到非零值；0 = 无
/// 该 tag / 全零 / 非数字形态。
static int extract_tag_u64(const uint8_t *buf, uint64_t size, const char *tag,
                           uint64_t taglen, uint64_t *out) {
    const uint8_t *p = find_bytes((uint8_t *)buf, size, tag, taglen);
    if (!p) return 0;
    uint64_t i = (uint64_t)(p - buf) + taglen;
    uint64_t v = 0;
    int digits = 0;
    while (i < size && buf[i] != '<') {
        if (buf[i] >= '0' && buf[i] <= '9') {
            if (digits < 19) v = v * 10 + (uint64_t)(buf[i] - '0');
            digits++;
        } else break;   // 非数字即停（与 zero 的形态门一致）
        i++;
    }
    if (digits == 0 || v == 0) return 0;
    *out = v;
    return 1;
}

/// <tag> 文本内容提取（截断安全：恒 NUL 尾）。返回 1 = 提到非空内容。
static int extract_tag_text(const uint8_t *buf, uint64_t size, const char *tag,
                            uint64_t taglen, char *out, uint64_t cap) {
    if (cap == 0) return 0;
    out[0] = 0;
    const uint8_t *p = find_bytes((uint8_t *)buf, size, tag, taglen);
    if (!p) return 0;
    uint64_t i = (uint64_t)(p - buf) + taglen;
    uint64_t o = 0;
    while (i < size && buf[i] != '<') {
        if (o < cap - 1) out[o++] = (char)buf[i];
        i++;
    }
    out[o] = 0;
    return o > 0;
}

/// 克隆事件（深拷贝——hook 线程只做提取，队列 worker 只持堆拷贝；
/// 事件不得引用 XML 缓冲，parse 返回后缓冲生命周期不归我们）。
/// R11：consumer_cand/obj = parse 入口 args[0]/args[1] 快照（worker 异步
/// 验证；obj 存活竞态在 worker 侧如实暴露）。
typedef struct {
    uint64_t newmsgid;
    char fromusr[64];
    uint64_t consumer_cand;
    uint64_t obj;
} clone_evt_t;

/// 最近一次捕获的快照（测试缝/诊断读回；与派发事件同内容）。
static clone_evt_t g_clone_last;
static volatile int g_clone_last_valid;

// —— R11 parse 锚定前置区（原 R6 节定义上提到此：clone_work 消费 rd 表
//    全族；枚举/typedef 全仓单点，全局变量为 tentative 合并，仓库先例）——
enum { kCloneMaxLookups = 32 };
enum { kRdHit = 1, kRdGet = 2, kRdInner = 4 };
typedef struct {
    uint32_t lookup_off, wrap_off, getter_off, x2single_off, x2desc_off, x2ctx_off;
    uint32_t keyctor_off;       // R11：key 构造 0x4a2b524（sret 24B 串对象）
} clone_rd_table_t;
typedef struct {
    void *lookup, *wrap, *getter, *x2single, *x2ctx;
    const void *x2desc;
} clone_rd_fns_t;
static uintptr_t g_image_base;               // install_hook 记录（slide 后基址）
static uint32_t g_clone_svc_vt_off;          // 行携带（0x9deeb48）
static clone_rd_table_t g_clone_rd;          // 安装期填充（base 相对偏移）
static volatile int g_clone_rd_valid;        // 身份门全过才置位（RELEASE 发布）
static volatile int g_clone_rd_lookups;      // 进程级调用上界护栏（实验封顶）
static volatile int g_clone_rd_keyctor_valid; // R11：keyctor 三字段行在位且 rd 门过
static int g_clone_rd_misses;                // lookup miss / 中途守卫退出（clmissq=）
static int g_clone_key_caps;                 // key 采集成功数（clkey=）
static uint64_t g_clone_parse_consumer;      // parse 入口 args[0] 快照（hook 体写）
static uint64_t g_clone_parse_obj;           // parse 入口 args[1] 快照（hook 体写）
static volatile int g_clone_svc2_hits;       // clsvc2=（parse 锚定 svc 身份门命中）
static int sso_key_snapshot(const uint8_t head24[24], uint8_t *out, size_t cap);
static int kread_buf(uint64_t addr, void *out, size_t n);
static int kread64(uint64_t addr, uint64_t *out);
static int clone_rd_run_core(uint64_t svc, const uint8_t *keyobj24,
                             const clone_rd_fns_t *fns, uint64_t base,
                             uint32_t svc_vt_off, uint64_t *svc_out,
                             uint64_t *msg_out);
static void clone_ins_probe(uint64_t svc, uint64_t msg_obj);
static uint64_t rd_abs(uint64_t base, uint32_t off);   // 定义在 R6 节
static void bootlog_line(const char *msg);             // 定义在武装节

static void clone_work(void *ctx);

/// 队列惰性单例（hook 多线程首触竞态由 dispatch_once 收敛）。
static dispatch_queue_t clone_queue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("wxkeep.clone", DISPATCH_QUEUE_SERIAL);
    });
    return q;
}

/// hook 体捕获入口：提取 → 深拷贝 → 异步派发。返回本次捕获结果
/// （1=已派发，0=无 newmsgid 跳过——**不是**持久快照位，连续两次调用
/// 的结果互不污染）。任何失败路径都不阻断 hook 主体（放行原生
/// parse——克隆是加法实验，绝不放大为消息链故障）。
static int clone_capture(const uint8_t *ptr, uint64_t size) {
    clone_evt_t evt;
    memset(&evt, 0, sizeof(evt));
    if (!extract_tag_u64(ptr, size, "<newmsgid>", sizeof("<newmsgid>") - 1,
                         &evt.newmsgid)) {
        g_clone_skips++;
        return 0;
    }
    extract_tag_text(ptr, size, "<fromusr>", sizeof("<fromusr>") - 1,
                     evt.fromusr, sizeof(evt.fromusr));
    g_clone_last = evt;
    g_clone_last_valid = 1;
    // R5 配对：暂存 msgid 供写点捕获消费（撤回流 parse 先于写点）。
    // 写序（108 轮）：fromusr 先落、msgid 最后 release 发布——acquire 侧
    // 见 msgid 即见同事件 fromusr。
    strlcpy(g_clone_pending_fromusr, evt.fromusr, sizeof(g_clone_pending_fromusr));
    __atomic_store_n(&g_clone_pending_msgid, evt.newmsgid, __ATOMIC_RELEASE);
    __atomic_store_n(&g_clone_pending_ts, (uint64_t)time(NULL), __ATOMIC_RELAXED);
    clone_evt_t *heap = malloc(sizeof(*heap));
    if (!heap) return 1;   // OOM：无派发，但捕获/提取语义已完成
    *heap = evt;
    heap->consumer_cand = g_clone_parse_consumer;
    heap->obj = g_clone_parse_obj;
    dispatch_queue_t q = clone_queue();
    if (q) {
        g_clone_captures++;
        dispatch_async_f(q, heap, clone_work);
    } else {
        free(heap);
    }
    return 1;
}

/// 队列 worker：R1 无宿主方法表——计数后丢弃。M2-R2 在这里接直调表
/// （svrid 读 → 内容捕获 → 消息行插入），数据行走 runtime.json hooks 行
/// 扩展字段（同 hook_off 机制，derive_runtime_hooks.py 产出）。
/// parse 锚定主体（R11；clone_work 消费；测试缝直驱同一条代码）。返回
/// 位掩码 kRdHit|kRdGet|kRdInner；svc/obj/key 任一验证失败返回 0。
/// 宿主调用合法面（异步串行队列）：
///   ①svc 验证：[cand+0xb78]→[svc]==base+clone_svc_vtable（cand=
///     parse 入口 args[0]；验证否 = px0 行，候选身份裁决）
///   ②obj 验证：[obj] 非零可读（parse 的 msg 结构在 worker 时点的
///     存活竞态如实暴露——死即守卫退出，绝不带病直调）
///   ③key 构造：keyctor(sret=keyout24, x0=obj)——宿主直调（行身份
///     门武装后）；24B key 串对象直送 lookup，sso 快照进 px0 行
///    （「键=svrid 十进制还是会话串」最终定案面）
///   ④读路径 tail = 写点版同一条 clone_rd_run_core
static int clone_parse_run(uint64_t cand, uint64_t obj) {
    uint64_t svc = 0, vt = 0;
    int svc_ok = 0;
    if (cand > 0x10000
        && kread64(cand + 0xb78, &svc) && svc > 0x10000
        && kread64(svc, &vt) && vt == rd_abs(g_image_base, g_clone_svc_vt_off)) {
        svc_ok = 1;
        g_clone_svc2_hits++;              // clsvc2=
    }
    uint8_t keyobj[24];
    memset(keyobj, 0, sizeof(keyobj));
    int key_ok = 0;
    uint32_t key_len = 0;
    if (svc_ok && obj > 0x10000) {
        typedef void (*keyctor_t)(void *, void *);
        uint64_t obj_head = 0;
        if (kread64(obj, &obj_head) && obj_head != 0) {
            ((keyctor_t)rd_abs(g_image_base, g_clone_rd.keyctor_off))(
                (void *)keyobj, (void *)obj);
            uint8_t flag = keyobj[0x17];   // 串对象头合法性（短 len<<1/长 MSB）
            if (flag != 0) {
                uint8_t kb[64];
                key_len = (uint32_t)sso_key_snapshot(keyobj, kb, sizeof(kb));
                if (key_len > 0) {
                    key_ok = 1;
                    g_clone_key_caps++;   // clkey=（parse 锚定 key 采集）
                    char kx[25];
                    for (int i = 0; i < 12 && i < (int)key_len; i++)
                        snprintf(kx + i * 2, 3, "%02x", kb[i]);
                    char b[160];
                    snprintf(b, sizeof(b),
                             "px0: cand=0x%llx svcvt_off=0x%llx keylen=%u key=%s",
                             (unsigned long long)cand,
                             (unsigned long long)g_clone_svc_vt_off,
                             key_len, kx);
                    bootlog_line(b);
                }
            }
        }
    }
    int r = 0;
    if (key_ok) {
        clone_rd_fns_t fns = {
            .lookup = (void *)rd_abs(g_image_base, g_clone_rd.lookup_off),
            .wrap = (void *)rd_abs(g_image_base, g_clone_rd.wrap_off),
            .getter = (void *)rd_abs(g_image_base, g_clone_rd.getter_off),
            .x2single = (void *)rd_abs(g_image_base, g_clone_rd.x2single_off),
            .x2ctx = (void *)rd_abs(g_image_base, g_clone_rd.x2ctx_off),
            .x2desc = (const void *)rd_abs(g_image_base, g_clone_rd.x2desc_off),
        };
        uint64_t probe_svc = svc, probe_msg = 0;
        r = clone_rd_run_core(svc, keyobj, &fns, g_image_base,
                              g_clone_svc_vt_off, &probe_svc, &probe_msg);
        if ((r & kRdGet) && probe_svc > 0x10000 && probe_msg > 0x10000) {
            clone_ins_probe(probe_svc, probe_msg);   // M4 探针（R8/R9 面）
        }
    }
    if (!svc_ok) {
        char b[128];
        snprintf(b, sizeof(b),
                 "px0: cand=0x%llx svc=<vtable-miss> obj=0x%llx",
                 (unsigned long long)cand, (unsigned long long)obj);
        bootlog_line(b);
    }
    return r;
}

static void clone_work(void *ctx) {
    clone_evt_t *evt = ctx;
    // R11 parse 锚定：nomethods 桩退役（实弹判决写点缝零触发，clrow=0）；
    // 门与护栏语义与写点版一致，主体见 clone_parse_run。
    if (!__atomic_load_n(&g_clone_rd_valid, __ATOMIC_ACQUIRE)
        || !g_clone_rd_keyctor_valid
        || __atomic_load_n(&g_clone_rd_lookups, __ATOMIC_RELAXED) >= kCloneMaxLookups
        || g_image_base == 0) {
        g_clone_nomethods++;
        free(evt);
        return;
    }
    __atomic_fetch_add(&g_clone_rd_lookups, 1, __ATOMIC_RELAXED);
    int r = clone_parse_run(evt->consumer_cand, evt->obj);
    if (!(r & kRdHit)) g_clone_rd_misses++;   // clmissq=
    free(evt);
}

// ---------------------------------------------------------------------------
// V3-M2-R4 写点捕获（seam B，105 轮定案；109 轮合同修正）：clone_hook_off
// 第二挂点武装后的 hook 体。写点签名 = (msg_obj, &shared_ptr{inner,ctl},
// wrap)——109 轮以 disasm+decomp+调用点三方互证定案（caller=consumer_main
// 体内 0x31aa680）：args[1] 解一次引用 = 行集合持有者 inner，行枚举须经
// inner 的 vtable[0x10] 调用（hook 体零宿主调用红线，禁）；原文 content
// 在**行对象** +0x7e（M2-R2 的「消息对象 @+0x7e」归因勘误），且撤回时被
// config+0x20 覆写。故本缝的诚实能力 = 事件 + msgid 配对；content 采集
// 移交 R6 工作函数（异步侧宿主调用合法）按 msgid 重查。
// **全部解引用走内核级读**（mach_vm_read_overwrite）：用户态裸读垃圾
// 指针 = 进程崩溃，内核读只返错——实验缝绝不放大为消息链故障。
static int g_clone_rows;      // 写点事件数（挂点命中即计）
static int g_clone_obj_caps;  // content 捕获数（109 轮起恒 0——content 源待 R6）
static volatile int g_clone_last_len;   // 最近一次捕获的 content 字节数（同上，恒 0）
static int g_sso_layout_arm64;   // 前向声明（定义在 SSO 布局节；tentative 合并）

// ---------------------------------------------------------------------------
// R6 证据步（110 轮，静态链 RE 收口的运行时验证面）：
//   x19 = consumer this 在写点调用处存活（270135 实证：consumer_main 序言
//   mov x19,x0；0x31aa5dc `ldr x0,[x19,#0xb78]`→bl 0x32edaec 直证服务
//   句柄来源；至写点调用 0x31aa680 无 x19 复写）。+0xb78 = consumer 的
//   成员 shared_ptr（setter 0x3199f78 内联构造的 0x90B 双 vtable 对象，
//   vtable 主项 0x9deeb48）——**服务获取问题就此消解：拿到 consumer this
//   即拿到读路径全部输入**。本步只做证据采集（thunk 把 x19 存进全局，
//   body 内核读 [x19+0xb78]→[svc+0] 与 base+clone_svc_vtable 比对），
//   零宿主调用；命中计数 clsvc= 是 R6 接线（异步按 msgid 重查）的真机
//   前提证明。x19 是被调用者保存寄存器——写点自递归（0x4cd60c0）路径下
//   它被写点函数原样保全，语义不变。
// ---------------------------------------------------------------------------
static uint64_t g_clone_caller_x19;          // thunk 快照（每次写点事件刷新）
static uint64_t g_clone_caller_sp;           // thunk 快照（caller 帧；111 轮 R6）
static uintptr_t g_image_base;               // install_hook 记录（slide 后基址）
static uint32_t g_clone_svc_vt_off;          // 行携带（0x9deeb48）
static uint8_t g_clone_svc_vt_valid;
static int g_clone_svc_hits;                 // vtable 身份门命中计数（marker clsvc=）

// ---------------------------------------------------------------------------
// R6 读路径直调表（111 轮接线，docs/RUNTIME-DESIGN 111 节合同）：
// 异步工作函数按 msgid 重查消息对象。九个偏移全部来自行数据（成组门 +
// 安装期 lookup 身份门通过才置 valid）；任何一道门失配 → 表不武装，
// worker 惰性（clmiss 语义不变——「机制在跑且惰性」的证据面诚实保留）。
//
// ABI 合同（270135 arm64 定点反汇编三方核对的直译）：
//   lookup  big3 sret(x8), x0=svc, x1=&key串, x2=ctx, w3=0   （0x32edaec）
//           —— C 侧以 >16B struct 返回值强制 sret（真实函数是
//              non-trivial C++ 类的内存返回；16B C struct 会被 clang 排
//              进 x0/x1 寄存器返回，与宿主 ABI 错位——big3_t 是刻意的）
//   wrap    x0=wrapout(≥0x300B), x1=&lookup_out → 返回 wrap   （0x309ac50）
//   getter  big3 sret(x8)={obj,ctl}, x0=wrap                  （0x102b740）
//   x2 链   p = x2single(&ctl_out, base+desc)（全局单例）；ctx = x2ctx(&p, NULL)
//   哨兵    未命中/空 shared_ptr 的预置毒值 0xAAAAAAAAAAAAAAAA（-0x5555..）
//   命中位  wrap_out + 0x278 bit0；msg_obj +0x6b0/{+0x6b8} = 行集合 inner/ctl
//
// 生命周期诚实边界：getter 返回的 pair 已 bump strong count，worker 结束
// 不做配对 release（错放比泄漏危险）——每事件泄漏一个 strong ref，由
// kCloneMaxLookups 进程级上界封顶（32 次）；插入接线轮引入 0x129f68 族
// 配对 release 后收口。consumer 在配对与执行间被销毁的残余竞态在册
//（charter 风险 #1 同族，毫秒窗 + vtable 复验缓解）。
// ---------------------------------------------------------------------------
// kCloneMaxLookups / clone_rd_table_t 已上提到 R11 parse 锚定前置区
//（clone_work 在本节之前消费 rd 表全族）。
static int kread_buf(uint64_t addr, void *out, size_t n);   // 定义在 R4 节（前向声明）
static int kread64(uint64_t addr, uint64_t *out);           // 同上
static clone_rd_table_t g_clone_rd;         // 安装期填充（base 相对偏移；typedef 见前置区）
static uint32_t g_clone_rd_key_slot_off;    // 帧内 key 串偏移（与表同批生效）
static volatile int g_clone_rd_key_slot_live; // 配对捕获侧的启用位（与 valid 同发布序）
static volatile int g_clone_rd_valid;       // 身份门全过才置位（RELEASE 发布）
static volatile int g_clone_rd_lookups;     // 进程级调用上界护栏（实验封顶）
static int g_clone_rd_hits;                 // lookup+wrap 命中（marker clhit=）
static int g_clone_rd_misses;               // lookup miss / 中途守卫退出（clmissq=）
static int g_clone_rd_gets;                 // getter 非 null（clget=）
static int g_clone_rd_inner;                // msg_obj+0x6b0 inner 在位（clinner=）
static int g_clone_key_caps;                // 帧内 key 串快照成功数（clkey=）
static int g_clone_last_key_len;            // 最近一次快照的 key 字节数
static char g_clone_last_key[64];           // 最近一次快照（bootlog 诊断面，不入 marker）
/// 24B 串对象头（arm64 变体布局，77 续⑧）→ 字节快照。返回长度（0=放弃）。
static int sso_key_snapshot(const uint8_t head24[24], uint8_t *out, size_t cap) {
    if ((int8_t)head24[0x17] < 0) {   // 长串：ptr@0 size@8
        uint64_t ptr = 0, size = 0;
        memcpy(&ptr, head24, 8);
        memcpy(&size, head24 + 8, 8);
        if (ptr <= 0x10000 || size == 0 || size > (1 << 16)) return 0;
        size_t n = size < cap ? (size_t)size : cap;
        if (!kread_buf(ptr, out, n > 64 ? 64 : n)) return 0;
        return (int)(n > 64 ? 64 : n);
    }
    // 短串：数据内联 @0，长度 = flag 字节 >>1（libc++ LE 编码；lookup 侧
    // csel 同读法实证——非零判空一致）
    size_t n = (size_t)(head24[0x17] >> 1);
    if (n == 0 || n > 22) return 0;
    memcpy(out, head24, n);
    return (int)n;
}

// ---------------------------------------------------------------------------
// R5 配对槽：XML 捕获（parse 入口，有 newmsgid）暂存 → 写点捕获（有
// content）读取并消费。撤回流内 parse 先于写点（同流毫秒级）；陈旧槽
// （>30s）不配对（防跨撤回串绑）。CAS 清零消费——多对象写点只配首捕。
// __atomic 内建要求非 _Atomic 限定指针——裸 uint64 + 内建序语义（配对槽
// 单写多读、CAS 消费，无 _Atomic 类型需求）。
static uint64_t g_clone_pending_msgid;           // 0 = 无待配对
static uint64_t g_clone_pending_ts;              // 暂存时刻（epoch 秒）
// 暂存 fromusr 快照（108 轮）：与 msgid 同事件的会话键——配对记录原先读
// g_clone_last.fromusr（最新捕获），并发捕获下可能把 msgid 与后一事件的
// fromusr 错配。写序 = 先写 fromusr 再 release 发布 msgid（acquire 侧必见
// 同事件值）；消费侧在 CAS 清槽**前**快照。残余窗口（多写者并发覆盖，读
// 侧 NUL@63 恒有界——strlcpy 消费永不越界）记录在案：msgid 配对本身精确，
// fromusr 极端竞态下可陈旧一拍（元数据面，R6 接线前无消费者）。
static char g_clone_pending_fromusr[64];
static int g_clone_pairs;                        // 配对完整记录数

static void bootlog_line(const char *msg);   // 定义在武装节（前向声明）
/// 完整克隆记录（msgid+content 配对产物）：R6 插入直调表的消费单元。
/// 111 轮扩展：svc/consumer（配对时刻 vtable 门验证过的读路径钥匙）+
/// key 快照（consumer_main 帧内串对象 → 字节级深拷贝——异步侧免复刻
/// 键构造 ABI）。
typedef struct {
    uint64_t msgid;
    uint64_t svc;           // [consumer+0xb78] pointee（vtable 门过才非 0）
    uint64_t consumer;      // x19 快照（svc 复验用）
    char fromusr[64];
    uint32_t key_len;       // 0 = 帧内 key 快照不可得（worker 惰性走 clmissq）
    char key[64];           // 重查键字节（十进制 svrid 或会话串——真机定案）
    uint32_t len;
    uint8_t content[];      // 深拷贝（≤255B 快照，同 R4 证据口径）
} clone_full_t;
static void clone_work_full(void *ctx);

/// 配对记录派发（捕获侧调用）：堆拷贝进串行队列。分配失败静默（证据
/// 计数不虚报）。
static void clone_dispatch_full(uint64_t msgid, uint64_t svc, uint64_t consumer,
                                const char *fromusr, const char *key, uint32_t key_len,
                                const uint8_t *content, uint32_t len) {
    clone_full_t *rec = malloc(sizeof(clone_full_t) + len);
    if (!rec) return;
    memset(rec, 0, sizeof(*rec));
    rec->msgid = msgid;
    rec->svc = svc;
    rec->consumer = consumer;
    if (fromusr) strlcpy(rec->fromusr, fromusr, sizeof(rec->fromusr));
    rec->key_len = key_len;
    if (key && key_len > 0) memcpy(rec->key, key, key_len > 64 ? 64 : key_len);
    rec->len = len;
    if (content && len > 0) memcpy(rec->content, content, len);   // len=0 事件合法（109 轮：content 待 R6）
    dispatch_queue_t q = clone_queue();
    if (q) {
        dispatch_async_f(q, rec, clone_work_full);
    } else {
        free(rec);
    }
}

// ---------------------------------------------------------------------------
// R6 worker：读路径直译（111 轮）。fns = **已解析的绝对地址**函数组（生产
// 路径由 g_clone_rd + g_image_base 解析；测试缝注入 JIT 桩直驱同一条生产
// 代码）。返回位掩码：1=clhit 2=clget 4=clinner（测试断言面）；任何中途
// 守卫退出只计 clmissq，绝不放大为动作。
// ---------------------------------------------------------------------------
// kRdHit/kRdGet/kRdInner 与 clone_rd_fns_t 已上提到 R11 parse 锚定前置区。
/// 溢出安全换算：切片偏移 → 绝对 VA（base 已知合法）。
static uint64_t rd_abs(uint64_t base, uint32_t off) { return base + off; }

/// R11 拆分壳（写点配对字节路径）：svc 重建与复验 + key 字节重建 → core。
/// （配对与执行之间 consumer 可能销毁——vtable 门重走；失配/不可读 →
/// 守卫退出，绝不用未验句柄调宿主。）
static int clone_rd_run(const clone_full_t *rec, const clone_rd_fns_t *fns,
                        uint64_t base, uint32_t svc_vt_off,
                        uint64_t *svc_out, uint64_t *msg_out) {
    uint64_t svc = rec->svc;
    if (svc > 0x10000) {
        uint64_t vt = 0;
        if (!kread64(svc, &vt) || vt != rd_abs(base, svc_vt_off)) svc = 0;
    }
    if (svc <= 0x10000 && rec->consumer > 0x10000) {
        uint64_t s = 0, vt = 0;
        if (kread64(rec->consumer + 0xb78, &s) && s > 0x10000
            && kread64(s, &vt) && vt == rd_abs(base, svc_vt_off)) {
            svc = s;
        }
    }
    if (svc <= 0x10000) return 0;
    if (rec->key_len == 0 || rec->key_len > 63) return 0;   // 键缺失/超快照界——不调
    // key 串对象重建（短串内联 flag=len<<1；长串 = 进程内静态缓冲 +
    // MSB 长 flag——只读消费方仅读 ptr/size/长位，cap 数值不入语义）
    uint8_t keybuf[64];
    uint8_t keyobj[24];
    memset(keyobj, 0, sizeof(keyobj));
    if (rec->key_len <= 22) {
        memcpy(keyobj, rec->key, rec->key_len);
        keyobj[0x17] = (uint8_t)(rec->key_len << 1);
    } else {
        memcpy(keybuf, rec->key, rec->key_len);
        uint64_t ptr = (uint64_t)(uintptr_t)keybuf;
        uint64_t size = rec->key_len;
        uint64_t capflag = 0x8000000000000000ULL;
        memcpy(keyobj, &ptr, 8);
        memcpy(keyobj + 8, &size, 8);
        memcpy(keyobj + 16, &capflag, 8);
    }
    return clone_rd_run_core(svc, keyobj, fns, base, svc_vt_off, svc_out, msg_out);
}

/// R11 拆分 core（读路径 tail；parse 锚定与字节路径共用单一代码路径）。
/// keyobj24 = **就绪的 24B key 串对象**（字节路径由壳重建；parse 路径由
/// 宿主 keyctor 产出直送）。返回位掩码 kRdHit|kRdGet|kRdInner。
static int clone_rd_run_core(uint64_t svc, const uint8_t *keyobj24,
                             const clone_rd_fns_t *fns, uint64_t base,
                             uint32_t svc_vt_off, uint64_t *svc_out,
                             uint64_t *msg_out) {
    // svc 复验（写点路径配对与执行之间 consumer 可能销毁；parse 路径刚
    // 验过——双验一次内核读成本，换取单一代码路径）。
    {
        uint64_t vt = 0;
        if (svc <= 0x10000 || !kread64(svc, &vt) || vt != rd_abs(base, svc_vt_off))
            return 0;
    }
    if (svc_out) *svc_out = svc;   // M4 探针输入（读服务在手）
    const uint8_t *keyobj = keyobj24;
    // 3) x2 上下文（全局单例两跳——生命周期与进程等价，异步可复现）
    typedef void *(*x2single_t)(void *, const void *);
    typedef void *(*x2ctx_t)(void *, void *);
    uint64_t ctl_out = 0;
    void *p = ((x2single_t)fns->x2single)(&ctl_out, fns->x2desc);
    if (!p) return 0;
    uint64_t pslot = (uint64_t)(uintptr_t)p;
    void *x2 = ((x2ctx_t)fns->x2ctx)(&pslot, NULL);
    if (!x2) return 0;
    // 4) lookup（sret 五参直译；出参预置毒值哨兵——consumer_main 同款）
    typedef struct { uint64_t a, b, c; } big3_t;   // >16B → clang 强制 x8 sret
    typedef big3_t (*lookup_t)(const void *, const void *, void *, int);
    typedef void *(*wrap_t)(void *, const void *);
    typedef big3_t (*getter_t)(const void *);
    const uint64_t poison = 0xAAAAAAAAAAAAAAAAULL;
    big3_t out = { poison, poison, poison };
    out = ((lookup_t)fns->lookup)((const void *)svc, (const void *)keyobj, x2, 0);
    // 5) wrap + 命中位（wrap 出参 ≥0x280B——0x300 清零缓冲，越界面归零）
    uint8_t wrapbuf[0x300];
    memset(wrapbuf, 0, sizeof(wrapbuf));
    void *w = ((wrap_t)fns->wrap)(wrapbuf, &out);
    if (!w) return 0;
    uint8_t hit = 0;
    if (!kread_buf((uint64_t)w + 0x278, &hit, 1)) return 0;
    if (!(hit & 1)) return 0;
    g_clone_rd_hits++;                     // clhit=
    // 6) getter（sret {obj,ctl}——strong count 由宿主 bump；见节注释的
    //    生命周期诚实边界：本 worker 不做配对 release）
    big3_t got = { poison, poison, poison };
    got = ((getter_t)fns->getter)(w);
    if (got.a <= 0x10000) return kRdHit;
    g_clone_rd_gets++;                     // clget=
    if (msg_out) *msg_out = got.a;         // M4 探针/插入输入（消息对象在手）
    // 7) 行集合持有者证据（+0x6b0 inner——R6 后续行枚举的入口在位性）
    uint64_t inner = 0;
    if (kread64(got.a + 0x6b0, &inner) && inner > 0x10000) {
        g_clone_rd_inner++;                // clinner=
        return kRdHit | kRdGet | kRdInner;
    }
    return kRdHit | kRdGet;
}

/// 完整记录 worker（生产路径）：直调表未武装/护栏到顶 → clmiss 惰性
///（109/110 轮语义不变）；表在位 → 读路径重查，证据入 marker。
static void clone_ins_probe(uint64_t svc, uint64_t msg_obj);   // M4 节（后置定义）
static int g_clone_cnt_caps;   // 同上（tentative 合并；R9 节零初始化）
static volatile int g_clone_ins_valid;   // 同上（tentative 合并；M4 节零初始化）
static void clone_work_full(void *ctx) {
    clone_full_t *rec = ctx;
    if (!__atomic_load_n(&g_clone_rd_valid, __ATOMIC_ACQUIRE)
        || __atomic_load_n(&g_clone_rd_lookups, __ATOMIC_RELAXED) >= kCloneMaxLookups
        || g_image_base == 0) {
        g_clone_nomethods++;
        free(rec);
        return;
    }
    __atomic_fetch_add(&g_clone_rd_lookups, 1, __ATOMIC_RELAXED);
    clone_rd_fns_t fns = {
        .lookup = (void *)rd_abs(g_image_base, g_clone_rd.lookup_off),
        .wrap = (void *)rd_abs(g_image_base, g_clone_rd.wrap_off),
        .getter = (void *)rd_abs(g_image_base, g_clone_rd.getter_off),
        .x2single = (void *)rd_abs(g_image_base, g_clone_rd.x2single_off),
        .x2ctx = (void *)rd_abs(g_image_base, g_clone_rd.x2ctx_off),
        .x2desc = (const void *)rd_abs(g_image_base, g_clone_rd.x2desc_off),
    };
    uint64_t svc = 0, msg_obj = 0;
    int r = clone_rd_run(rec, &fns, g_image_base, g_clone_svc_vt_off, &svc, &msg_obj);
    if (!(r & kRdHit)) g_clone_rd_misses++;   // clmissq=（lookup miss / 守卫退出）
    {   // bootlog 证据行（key 前缀 12B——「键=svrid 十进制还是会话串」的
        // 真机定案面；marker 只带长度，内容不进低敏感通道）
        char kx[25];
        for (int i = 0; i < 12 && i < (int)rec->key_len; i++)
            snprintf(kx + i * 2, 3, "%02x", (uint8_t)rec->key[i]);
        char b[176];
        snprintf(b, sizeof(b), "r6: msgid=%llu keylen=%u key=%s r=%d hits=%d gets=%d inner=%d",
                 (unsigned long long)rec->msgid, rec->key_len, kx, r,
                 g_clone_rd_hits, g_clone_rd_gets, g_clone_rd_inner);
        bootlog_line(b);
    }
    // M4 证据步（R8）：消息对象在手（clget）→ publisher/msg 形态探针。
    // 纯内核读，零宿主调用——clpub= 与 bootlog r8pub 行是 R9 派生面
    //（publisher 认证值 + 容器合同）的唯一真机输入。表未武装不计证据
    //（机制驱动且可证惰性的口径与 rd 表一致）。
    if ((r & kRdGet) && __atomic_load_n(&g_clone_ins_valid, __ATOMIC_ACQUIRE)
        && svc > 0x10000 && msg_obj > 0x10000) {
        clone_ins_probe(svc, msg_obj);
    }
    free(rec);
}

// ---------------------------------------------------------------------------
// M4 插入链（113 轮 R8 接线，docs/RUNTIME-DESIGN R8 节合同）：
//   ctor 0x34597c8(x0=源消息对象, x1=容器, w2=0xa, sret=x8→32B)
//     ——sret {vtable@+0（=行 clone_ins_msg_vt）, 自引用槽@+8, ctl@+0x18}；
//       宿主 execute 体（0x34579d0）对 sret+0x18 做非空判别后才继续——
//       本侧同款门（毒值哨兵 + 双读门）。
//   AMR 0x33fd190(x0=publisher, x1=&16B pair{obj,ctl}, x2=&24B 零置 outvec)
//     ——体内 new(0x20) 任务{vtable 0x9df7c38, svc, &pair, &outvec} →
//       写枢纽 0x3aeddb4 post（纯异步投递）。pair 的 strong count 由 AMR
//       自行 bump（0x33fd190 体内 ldadd）；本侧不做配对 release（R6 同款
//       诚实泄漏政策，由 kCloneMaxInserts 进程级封顶）。
//   publisher 协议（写枢纽 0x3aeddb4 直译）：x0 需 [x0+8] = 订阅者持有者
//     对象（[[x0+8]] = 其 vtable，vtable[0x10] 槽被虚调）。认证门 =
//     [[svc+8]] 与行 clone_ins_pub_vt 比对——R8 定案 publisher=订阅期
//     绑定（0x3416724 订阅派发器，对象图静态不可达），270135 行不带
//     pub_vt = 探针-only：插入调用恒惰性，clpub= 是认证值的派生输入。
//   容器（ctor x1）：宿主流 = [[[观察者任务+0x20]]]（订阅侧 pair 的首成
//     员再解引）——合同未定案（RUNTIME-DESIGN R8 诚实边界），生产侧
//     在 pub 认证与容器合同双落地前不进入插入调用。
// ---------------------------------------------------------------------------
enum { kCloneMaxInserts = 8, kInsCtorOk = 1, kInsAmr = 2 };
typedef struct { uint32_t ctor_off, amr_off, msg_vt_off, pub_vt_off; } clone_ins_table_t;
static clone_ins_table_t g_clone_ins;         // 安装期填充（base 相对偏移）
static volatile int g_clone_ins_valid;        // ctor/amr 双身份门过才置位
static uint8_t g_clone_ins_pub_gated;         // pub_vt 行在位（认证门启用）
static volatile int g_clone_ins_inserts;      // 进程级插入调用上界护栏（实验封顶）
static int g_clone_pub_probes;                // clpub=（探针成功：读服务+8 链两跳可读）
static int g_clone_pub_matches;               // 认证门命中计数（pub_gated 时）
static int g_clone_cnt_caps;                  // R9 容器候选链三跳全读计数（r9pub 行）
static int g_clone_ins_calls;                 // clins=（AMR 实际调用）

/// M4 探针（纯内核读）：①publisher 形态证据——[svc+8]（写枢纽协议位）→
/// [[svc+8]] vtable 切片偏移（bootlog r8pub 行；pub_vt 认证值 + 与 AMR
/// 同对象的判别面）；②msg 对象形态证据——vtable 偏移（0x9f24930 类主张
/// 的真机核对面）与 +0x10 形态字。认证门在位且命中 → g_clone_pub_matches+
///（clpub 计数独立——证据与判定分开报）。插入调用不在本函数：见节注释
/// 的「pub 认证与容器合同双落地」前提。
///
/// R9/R10 探针-2（114/115 轮）：订阅句柄对全量取证（bootlog r9pub 行，
/// 独立成行——r8pub 行不动，按前缀分账）。R10 数据流定案（execute
/// 0x345818c-0x345820c 三方互证）：AMR 的 pair = {[subThis+0x78],
/// [subThis+0x80]}（订阅对象自身句柄对 A/B，B 引用计数 bump——非
/// 0x40B 捕获对象，那在此被 release）；container（ctor x1）= [A]；
/// publisher = [subThis+0x38]。写回调用方栈槽（0x34581a8）= 同步内联
/// 派发实锤（异步下为内存破坏）。sub（=[svc+8]）若与订阅对象同类，
/// 则 AMR 调用全参数从本链一步可得：pub38=候选 publisher、c78/b80=
/// 候选 pair、cnt=[c78]=container、cnt20=[container+0x20]；全链可读才
/// 计 g_clone_cnt_caps（测试断言面）。msg20=[msg_obj+0x20]=原消息上下
/// 文现值——与 cnt20 对比=源变异风险锚（相等则 ctor 的覆写无实际效果）。
/// 链断 = cnt 记 chain-broken（其余字段照实带值/0），caps 不计——证据面不虚报。
static void clone_ins_probe(uint64_t svc, uint64_t msg_obj) {
    uint64_t sub = 0, sub_vt = 0;
    if (!kread64(svc + 8, &sub) || sub <= 0x10000) return;
    if (!kread64(sub, &sub_vt) || sub_vt <= 0x10000) return;
    g_clone_pub_probes++;                     // clpub=
    uint64_t mvt = 0, m10 = 0;
    kread64(msg_obj, &mvt);
    kread64(msg_obj + 0x10, &m10);
    int match = 0;
    if (g_clone_ins_pub_gated && g_image_base
        && sub_vt == rd_abs(g_image_base, g_clone_ins.pub_vt_off)) {
        g_clone_pub_matches++;
        match = 1;
    }
    char b[160];
    snprintf(b, sizeof(b),
             "r8pub: subvt_off=0x%llx msgvt_off=0x%llx msg10=0x%llx match=%d",
             (unsigned long long)(sub_vt > g_image_base ? sub_vt - g_image_base : 0),
             (unsigned long long)(mvt > g_image_base ? mvt - g_image_base : 0),
             (unsigned long long)m10, match);
    bootlog_line(b);
    // 探针-2：订阅句柄对全量 + 原消息 +0x20（r9pub 行）。pub38/b80 恒采
    //（publisher/pair 候选），cnt 三跳全读才计 caps。
    uint64_t msg20 = 0;
    kread64(msg_obj + 0x20, &msg20);
    uint64_t pub38 = 0, b80 = 0;
    kread64(sub + 0x38, &pub38);
    kread64(sub + 0x80, &b80);
    uint64_t c78 = 0, cnt = 0, cnt20 = 0;
    if (kread64(sub + 0x78, &c78) && c78 > 0x10000
        && kread64(c78, &cnt) && cnt > 0x10000
        && kread64(cnt + 0x20, &cnt20)) {
        g_clone_cnt_caps++;
        char b2[224];
        snprintf(b2, sizeof(b2),
                 "r9pub: pub38=0x%llx c78=0x%llx b80=0x%llx cnt=0x%llx "
                 "cnt20=0x%llx msg20=0x%llx",
                 (unsigned long long)pub38, (unsigned long long)c78,
                 (unsigned long long)b80, (unsigned long long)cnt,
                 (unsigned long long)cnt20, (unsigned long long)msg20);
        bootlog_line(b2);
    } else {
        char b2[160];
        snprintf(b2, sizeof(b2),
                 "r9pub: pub38=0x%llx c78=0x%llx b80=0x%llx cnt=<chain-broken> "
                 "msg20=0x%llx",
                 (unsigned long long)pub38, (unsigned long long)c78,
                 (unsigned long long)b80, (unsigned long long)msg20);
        bootlog_line(b2);
    }
}

/// M4 插入 ABI 直译（生产路径由 g_clone_ins + g_image_base 解析；测试缝
/// 注入 JIT 桩直驱同一条生产代码）。前置：publisher 已过认证门、容器合同
/// 已定案（生产侧调用点的责任，本函数不重验——直调表的武装即身份门）。
/// 返回位掩码：1=ctor sret 双读门过 2=AMR 已调。中途守卫退出绝不放大为
/// 动作（AMR 未调 = 零副作用）。
static int clone_ins_run(uint64_t publisher, uint64_t container, uint64_t source,
                         uint64_t pair_obj, const void *ctor_fn, const void *amr_fn,
                         uint64_t base, uint32_t msg_vt_off) {
    if (publisher <= 0x10000 || container <= 0x10000 || source <= 0x10000) return 0;
    if (pair_obj <= 0x10000) return 0;   // AMR 体首读 [pair.obj]/[+0x10]——零句柄绝不进
    // 护栏（113 轮体检 P3 修）：fetch_add 原子取号判界——check-then-add 在
    // 并发调用下可越 kCloneMaxInserts 帽（当前生产零调用点+串行队列无实际
    // 竞态，但这是泄漏封顶的进程级上界，接线轮调用点换队列即破帽）。计数
    // 含被拒尝试（只增不减，marker 语义=attempts 总数）。
    if (__atomic_fetch_add(&g_clone_ins_inserts, 1, __ATOMIC_RELAXED)
        >= kCloneMaxInserts) return 0;
    // ctor：big4_t（32B）强制 clang x8 sret——与宿主 0x34597c8 的
    // sret 协议对齐（big3_t 同理的刻意布局）
    typedef struct { uint64_t a, b, c, d; } big4_t;
    typedef big4_t (*ctor_t)(void *, void *, uint32_t);
    const uint64_t poison = 0xAAAAAAAAAAAAAAAAULL;
    big4_t out = { poison, poison, poison, poison };
    out = ((ctor_t)ctor_fn)((void *)source, (void *)container, 0xa);
    // sret 双读门：vtable 身份（msg 类）+ ctl@+0x18 非空（宿主 execute
    // 体 0x3457aec 同款判别位）
    if (out.a != rd_abs(base, msg_vt_off)) return 0;
    if (out.d <= 0x10000 || out.d == poison) return 0;
    // AMR：pair 16B{obj,ctl} + 24B 零置 outvec（宿主 0x34581d8-0x345820c 直译）。
    // pair_obj=显式入参：宿主流的 pair 来自订阅侧 wrapper（0x3456d00 处理链
    // 产物，RUNTIME-DESIGN R8 诚实边界③未定案）——ctl 用 ctor sret 的
    // （产物生命周期与其控制块同源），obj 不猜、由生产调用点按定案供给。
    //
    // 缓冲区**堆化**（113 轮体检 P2 修）：AMR 体内把 &pair/&outvec 原样存进
    // 异步任务（0x33fd258 stp）——宿主自己的调用点传栈缓冲是它的时序赌注，
    // 本侧不复制该赌注：堆分配 + 不释放（R6 getter 同款「错放比泄漏危险」
    // 政策，kCloneMaxInserts 封顶泄漏量：≤8×40B/进程）。分配失败=放弃该次
    // 插入（计数不虚报——g_clone_ins_calls 只在 AMR 实调后 +1）。
    uint64_t *pair = malloc(sizeof(uint64_t) * 2);
    uint64_t *outvec = malloc(sizeof(uint64_t) * 3);
    if (!pair || !outvec) { free(pair); free(outvec); return 0; }
    pair[0] = pair_obj;
    pair[1] = out.d;
    outvec[0] = outvec[1] = outvec[2] = 0;
    typedef void *(*amr_t)(const void *, void *, void *);
    ((amr_t)amr_fn)((const void *)publisher, (void *)pair, (void *)outvec);
    g_clone_ins_calls++;                      // clins=
    return kInsCtorOk | kInsAmr;
}

/// 内核级 8B 读。1=成功 0=目标页不可读（垃圾指针/越界）。
static int kread64(uint64_t addr, uint64_t *out) {
    if (addr <= 0x10000) return 0;
    uint64_t v = 0;
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr, 8,
                               (mach_vm_address_t)(unsigned long)&v, &got) != KERN_SUCCESS
        || got != 8) return 0;
    *out = v;
    return 1;
}

/// 内核级块读（≤64B）。1=成功。
static int kread_buf(uint64_t addr, void *out, size_t n) {
    if (addr <= 0x10000 || n > 64) return 0;
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)addr, n,
                               (mach_vm_address_t)(unsigned long)out, &got) != KERN_SUCCESS
        || got != n) return 0;
    return 1;
}

/// 从本地缓冲套用 per-arch SSO 布局（sso_head 的内核读版——原函数裸解引用，
/// 只可用于自身缓冲）。buf = 对象头 24B 快照。1=长串且 (size,off) 已填
/// （off 相对对象基址的 content 起始——长串数据指针在头内）。
static int sso_head_buf(const uint8_t *head24, uint64_t *size) {
    if (g_sso_layout_arm64) {
        if ((int8_t)head24[0x17] >= 0) return 0;
        memcpy(size, head24 + 8, 8);
    } else {
        if (!(head24[0] & 1)) return 0;
        memcpy(size, head24 + 8, 8);
    }
    return 1;
}

/// 克隆 hook 体（109 轮合同修正版）：args = 写点整型参镜像（x0/x1/x2……）。
/// 只读 args[1]（&shared_ptr{inner,ctl}，解一次引用得行集合持有者）；
/// 事件 + msgid 配对走内核读 + 异步派发（队列复用 R1 的 wxkeep.clone
/// 串行队列）。content 采集不在本缝（见节注释——行枚举需宿主调用）。
__attribute__((used)) static void clone_hook_body(void *const *args) {
    if (!g_clone_message) return;   // 实验开关关 = 纯透传（挂点命中也不动）
    g_clone_rows++;
    // R6 证据步：内核读 [x19+0xb78] → 成员服务对象 → [svc] vtable 与
    // base+行偏移比对。x19 来自 thunk 快照（可能是垃圾寄存器值——比如
    // 写点被非 consumer_main 路径调用），全部走内核读：错值只让比对不中，
    // 绝不放大为崩溃。
    if (g_clone_svc_vt_valid && g_image_base) {
        uint64_t x19v = __atomic_load_n(&g_clone_caller_x19, __ATOMIC_ACQUIRE);
        uint64_t svc = 0, vt = 0;
        if (x19v > 0x10000
            && kread64(x19v + 0xb78, &svc) && svc > 0x10000
            && kread64(svc, &vt)
            && vt == (uint64_t)g_image_base + g_clone_svc_vt_off) {
            g_clone_svc_hits++;
        }
    }
    uint64_t v = (uint64_t)(uintptr_t)args[1];
    if (v <= 0x10000) { g_clone_skips++; return; }
    uint64_t inner = 0;
    if (!kread64(v, &inner) || inner <= 0x10000) { g_clone_skips++; return; }
    // inner 在手（R6 工作函数的枚举入口，指针权威=caller 已 bump 引用计
    // 数的 shared_ptr 拷贝；异步侧使用前须重建生命周期——R6 合同面）。
    // 本缝不触碰行集合（枚举需 vtable 调用=hook 体红线）；content 证据位
    // （g_clone_obj_caps/g_clone_last_len）109 轮起恒 0，待 R6 接上真源。
    // R5 配对（不变）：消费暂存 msgid（CAS 清零——多写点事件只配首捕；
    // 陈旧槽 >30s 不配对，防跨撤回串绑）。配对成功=克隆事件入队（R6 直
    // 调表消费单元；content 由 R6 按 msgid 重查）。fromusr 快照先于 CAS
    // 拷贝（同事件值；残余并发窗口见 g_clone_pending_fromusr 注释——
    // NUL@63 有界，消费 strlcpy 恒安全）。
    uint64_t pid = __atomic_load_n(&g_clone_pending_msgid, __ATOMIC_ACQUIRE);
    uint64_t pts = __atomic_load_n(&g_clone_pending_ts, __ATOMIC_RELAXED);
    uint64_t now = (uint64_t)time(NULL);
    if (pid != 0 && pts != 0 && now >= pts && now - pts <= 30) {
        char fromusr_local[64];
        memcpy(fromusr_local, (const void *)g_clone_pending_fromusr, sizeof(fromusr_local));
        fromusr_local[63] = 0;   // 写侧 strlcpy 覆盖窗可瞬态无 NUL——强制尾零（消费侧有界）
        uint64_t expect = pid;
        if (__atomic_compare_exchange_n(&g_clone_pending_msgid, &expect, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            g_clone_pairs++;
            // R6 接线（111 轮）：配对成功 = 重查钥匙采集窗（同步、帧活）。
            // ① key 快照：consumer_main 帧 sp+key_slot 的串对象（thunk 已
            // 快照 caller sp）——内核读 24B 头 + SSO 解码 → 字节级深拷贝。
            // ② svc：x19+0xb78 经 vtable 身份门——过门才入记录（worker
            // 调宿主前复验）。两者任一失败只影响该事件的重查能力（clmissq
            // 证据面），不阻断配对本身。
            uint32_t key_len = 0;
            char key_local[64];
            uint64_t caller_sp = __atomic_load_n(&g_clone_caller_sp, __ATOMIC_ACQUIRE);
            if (g_clone_rd_key_slot_live && caller_sp > 0x10000) {
                uint8_t head24[24];
                if (kread_buf(caller_sp + 0xE0 + g_clone_rd_key_slot_off,
                              head24, sizeof(head24))) {
                    key_len = (uint32_t)sso_key_snapshot(head24,
                                                         (uint8_t *)key_local, sizeof(key_local));
                }
            }
            if (key_len > 0) {
                g_clone_key_caps++;
                g_clone_last_key_len = (int)key_len;
                memcpy(g_clone_last_key, key_local, key_len);
                g_clone_last_key[key_len] = 0;
            }
            uint64_t svc = 0, x19v = __atomic_load_n(&g_clone_caller_x19, __ATOMIC_ACQUIRE);
            if (g_clone_svc_vt_valid && g_image_base && x19v > 0x10000) {
                uint64_t s = 0, vt = 0;
                if (kread64(x19v + 0xb78, &s) && s > 0x10000
                    && kread64(s, &vt)
                    && vt == (uint64_t)g_image_base + g_clone_svc_vt_off) {
                    svc = s;
                }
            }
            clone_dispatch_full(pid, svc, x19v, fromusr_local,
                                key_len ? key_local : NULL, key_len, NULL, 0);
        }
    }
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
static void *(*volatile g_real_wrapper)(void *, void *, void *, void *, void *, void *);

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
    // R11 parse 锚定（116 轮）：实弹判决写点缝死（clrow=0 两次撤回零事件）
    // 后，consumer 候选改从 parse 入口 args[0] 采集——纯寄存器快照（一次
    // 存储，零宿主调用/零内核读，主热路径零负担）；[x0+0xb78] 的验证在
    // worker 异步侧做。clone_capture 同步读走该全局（同调用即配对）。
    g_clone_parse_consumer = (uint64_t)(uintptr_t)args[0];
    g_clone_parse_obj = (uint64_t)(uintptr_t)args[1];
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
        && (tip_len_active() > 0 || g_keep_message || g_clone_message)) {
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
                        // V3-M2 克隆捕获必须先于 keep_message 清零（清零会把
                        // 我们要捕获的 newmsgid 数字改写成 0）。自发分支已在
                        // 上方放行——自撤不克隆的语义由门序天然成立。
                        if (g_clone_message) clone_capture(ptr, size);
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
        // 尾跳读 g_real_wrapper 用 ldar（110 轮修）：与安装侧的 RELEASE 存储
        // （install_hook/prepare 路径）配对——「他核见 SLOT/thunk 已生效而读到
        // 陈旧 wrapper=NULL → 跳 0」的弱序窗口在 wrapper 边上闭合（SLOT 桩的
        // 12B 磁盘编码装不进 ldar 序列，该边维持 stlr+普通 ldr 的最终一致残余，
        // 108 轮注释在案）。x17=IP2 草稿位，非参数面。
        "adrp x16, _g_real_wrapper@PAGE\n"
        "add x16, x16, _g_real_wrapper@PAGEOFF\n"
        "ldar x17, [x16]\n"
        "br x17\n");
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
// V3-M2-R4 克隆写点 thunk（seam B 第二挂点）：结构 = revoke_wrapper_hook
// 全参透传同款（写点签名未知——透传是结构前提），SLOT 2 指向它；尾跳
// g_clone_real_wrapper = 写点蹦床（arm 期自 clone_expected 重建，重放原始
// 16B 跳回 target+16）。
static void *(*volatile g_clone_real_wrapper)(void *, void *, void *, void *, void *, void *);
static volatile uint64_t g_clone_hook_target;   // 非零=克隆挂点已武装

#if defined(__arm64__) || defined(__aarch64__)
__attribute__((naked)) static void *revoke_clone_hook(void *a0, void *a1, void *a2,
                                                      void *a3, void *a4, void *a5) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-0xe0]!\n"
        "stp x0, x1, [sp, #0x10]\n"
        "stp x2, x3, [sp, #0x20]\n"
        "stp x4, x5, [sp, #0x30]\n"
        "stp x6, x7, [sp, #0x40]\n"
        "str x8,      [sp, #0x50]\n"
        "stp q0, q1, [sp, #0x60]\n"
        "stp q2, q3, [sp, #0x80]\n"
        "stp q4, q5, [sp, #0xa0]\n"
        "stp q6, q7, [sp, #0xc0]\n"
        // R6 证据步：x19 = consumer this（写点调用处存活，见 clone_hook_body
        // 上方块注释）——快照进全局供 body 内核读取证。x16 是 IP 草稿寄存器
        // （非参数位），bl 前 populate 无透传面影响；帧布局零改动。
        "adrp x16, _g_clone_caller_x19@PAGE\n"
        "str x19, [x16, _g_clone_caller_x19@PAGEOFF]\n"
        // R6 接线（111 轮）：同时快照 sp。此刻 sp = 写点入口 sp = 调用者
        //（consumer_main）在 bl 处的 sp——其帧内的 key 串对象（clone_rd_
        // key_slot 偏移）在 body 同步窗口内仍存活，内核读快照即得重查键，
        // 异步侧无需复刻键构造。body 侧换算：caller_sp = 快照 + 0xE0（本
        // thunk 帧深）。sp 不能作 str 源操作数——经 x17（IP2 草稿位，尾部
        // ldar 前无占用）中转。
        "adrp x16, _g_clone_caller_sp@PAGE\n"
        "mov x17, sp\n"
        "str x17, [x16, _g_clone_caller_sp@PAGEOFF]\n"
        "add x0, sp, #0x10\n"
        "bl _clone_hook_body\n"
        "ldp x0, x1, [sp, #0x10]\n"
        "ldp x2, x3, [sp, #0x20]\n"
        "ldp x4, x5, [sp, #0x30]\n"
        "ldp x6, x7, [sp, #0x40]\n"
        "ldr x8,      [sp, #0x50]\n"
        "ldp q0, q1, [sp, #0x60]\n"
        "ldp q2, q3, [sp, #0x80]\n"
        "ldp q4, q5, [sp, #0xa0]\n"
        "ldp q6, q7, [sp, #0xc0]\n"
        "ldp x29, x30, [sp], #0xe0\n"
        // 尾跳读 g_clone_real_wrapper 用 ldar（110 轮修，与安装侧 RELEASE 存储
        // 配对——发布序两端闭合，不再依赖 SLOT 读侧语义兜底；x17=IP2 草稿位）
        "adrp x16, _g_clone_real_wrapper@PAGE\n"
        "add x16, x16, _g_clone_real_wrapper@PAGEOFF\n"
        "ldar x17, [x16]\n"
        "br x17\n");
}
#else
static void *revoke_clone_hook(void *a0, void *a1, void *a2,
                               void *a3, void *a4, void *a5) {
    void *args[6] = {a0, a1, a2, a3, a4, a5};
    clone_hook_body(args);
    return g_clone_real_wrapper(a0, a1, a2, a3, a4, a5);
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
            if (shift >= 64) break;       // 病态续位流：shift≥64 的左移是 UB——当表尽处理（110 轮修）
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
                    if (sh2 >= 64) break;   // 病态续位流同上（110 轮修）
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

// T6 诊断：武装决策点留痕（进程可能死于任何一步——逐点记录才能远程定位）。
//
// 110 轮修（P2）：原实现做 Foundation 全文件读+重写，而武装路径会在
// add_image 回调（dyld 持锁）上下文到达（on_image_add → try_hook_image →
// install_hook → try_slot_fill/arm_clone_site）——违反自家「回调内不做
// 磁盘 I/O」红线（marker 为同理由移出武装路径，注释在案）。改为进程内
// 环形缓冲（snprintf+fetch_add 分槽，无锁无分配；极端并发下单行可读性
// 损失是诊断面可接受代价），安全上下文（构造器尾/arm_late/30s 定时器）
// 统一落盘；文件超 4MB 截断重开（长会话下 O(n²) 读写与无界增长一并消除）。
enum { kBootRingLines = 64, kBootLineLen = 176 };
static char g_boot_ring[kBootRingLines][kBootLineLen];
static volatile int g_boot_ring_head;
static int g_boot_ring_flushed;
static void bootlog_line(const char *msg) {
    int slot = __atomic_fetch_add(&g_boot_ring_head, 1, __ATOMIC_RELAXED);
    char *dst = g_boot_ring[slot % kBootRingLines];
    snprintf(dst, kBootLineLen, "%lld %s", (long long)time(NULL), msg);
    dst[kBootLineLen - 1] = 0;
}
/// NSString 形态的行（cfgdiag/done/late20s 等富文本诊断行）。
static void bootlog_line_ns(NSString *s) { bootlog_line([s UTF8String] ?: ""); }
/// 把环形缓冲里未落盘的行写进 boot log（只在安全上下文调用）。
static void bootlog_flush(void) {
    @autoreleasepool {
        // 111 轮审计 P3：flush 的读-改-写在多安全上下文（构造器尾/arm_late/
        // 20s/30s 定时器）并发时互相覆盖丢行——CAS 抢占式互斥，抢不到就
        // 跳过本轮（行留在环形缓冲，下个 tick 落盘；诊断面可接受）。
        static volatile int flushing;
        int expected = 0;
        if (!__atomic_compare_exchange_n(&flushing, &expected, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
        int head = __atomic_load_n(&g_boot_ring_head, __ATOMIC_RELAXED);
        if (g_boot_ring_flushed >= head) {
            __atomic_store_n(&flushing, 0, __ATOMIC_RELEASE);
            return;
        }
        NSString *boot = [NSString stringWithFormat:@"%@/tmp/wxkeep-boot.log",
                          NSHomeDirectory()];
        long long sz = [[[NSFileManager defaultManager]
            attributesOfItemAtPath:boot error:nil] fileSize];
        NSMutableString *acc = (sz > 4 * 1024 * 1024)
            ? [NSMutableString stringWithFormat:@"-- truncated (was %lldB) --\n", sz]
            : ([NSMutableString stringWithContentsOfFile:boot
                encoding:NSUTF8StringEncoding error:nil] ?: [NSMutableString new]);
        for (int i = g_boot_ring_flushed; i < head; i++) {
            NSString *l = @(g_boot_ring[i % kBootRingLines]);
            if (l.length) [acc appendFormat:@"%@\n", l];
        }
        g_boot_ring_flushed = head;
        [acc writeToFile:boot atomically:YES encoding:NSUTF8StringEncoding error:nil];
        __atomic_store_n(&flushing, 0, __ATOMIC_RELEASE);
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

/// 补丁态 + 尾 4B 校验（111 轮审计 P1 修）：补丁态下蹦床重放源 100% 来自
/// 行字节——磁盘前 12B 已被入口补丁覆盖（原指令只在行里），但 [12..16)
/// （第 4 条指令）**未被补丁触碰、仍在磁盘上**，是与行 expected 比对的
/// 唯一在盘信源。失配 = 同 UUID 内容漂移（10-03 事件形态）或行被篡改
/// ——两种都不得武装。返回 1 = 补丁形态在场且尾 4B 与 expected 一致。
static int entry_patch_matches(uintptr_t target, const uint8_t expected[16]) {
    uint32_t w[4] = {0, 0, 0, 0};
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)target, 16,
                               (mach_vm_address_t)(unsigned long)w, &got) != KERN_SUCCESS
        || got != 16) return 0;
    if (slotfill_decode(w, target) == 0) return 0;
    return memcmp(((const uint8_t *)w) + 12, expected + 12, 4) == 0;
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
    // 入口 12B 读走内核读（与 entry_patch_present 同规——目标页访问 doctrine
    // 统一；直 memcpy 读在 97-98 实机虽未出事，但与「目标页一律内核读」的
    // 注释声明相矛盾，且内核读对 JIT/文件页语义等价零成本）。
    if (!kread_buf(target, w, 12)) {
        bootlog_line("slotfill: 入口 12B 内核读失败");
        return EIO;
    }
    uint64_t slot = slotfill_decode(w, target);
    if (slot == 0) {
        bootlog_line("slotfill: 入口非补丁形态（decode 失败）");
        return ENOENT;
    }
    // P0 落点双门（110 轮修）：CLI 侧的孪生识别（EntrySlot.detectPatched）带
    // 「SLOT 落 __DATA 段尾填充区 + 当前内容真零」两道门，运行时侧此前只验
    // 指令形态——同 UUID 内容漂移（10-03 自更新事件实证的形态）下，入口 12B
    // 可能恰是 __objc_stubs 原生三连（adrp x16/ldr x16/br x16 在 arm64 大库
    // 里极常见），序言门在补丁态分支又被整体跳过、身份字段可选——解码出的
    // slot 指向任意常量/GOT 槽。无门直写 = 对只读页 store（SIGSEGV，启动即
    // 死）或野写 8B 指针（静默劫持）。门 1：内核读必须成功且当前值为零
    // （合法装机件上 CLI 已验磁盘真零、运行时无人写它；objc_stub 引用槽恒
    // 非零——一并挡掉）。门 2：mach_vm_region 报告该页可写（__DATA RW；对
    // __DATA_CONST/GOT 只读页拒装）。
    uint64_t cur = 0;
    if (!kread64(slot, &cur) || cur != 0) {
        bootlog_line("slotfill: SLOT 非零或不可读——拒装（真零门，P0）");
        return EIO;
    }
    {
        mach_vm_address_t rgn = slot & ~(mach_vm_address_t)0xFFF;
        mach_vm_size_t rsz = 0;
        struct vm_region_basic_info_64 bi;
        mach_msg_type_number_t rcnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t robj = MACH_PORT_NULL;
        kern_return_t krr = mach_vm_region(mach_task_self(), &rgn, &rsz,
                                           VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&bi, &rcnt, &robj);
        if (robj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), robj);
        if (krr != KERN_SUCCESS || !(bi.protection & VM_PROT_WRITE)) {
            bootlog_line("slotfill: SLOT 页不可写——拒装（落区门，P0）");
            return EIO;
        }
    }
    // 双写一致性读回 + release 发布序（108 轮修）：SLOT 写必须是 release 存
    // 储——蹦床/wrapper 指针（此前同线程的普通 store）经它对全核可见。
    // volatile+同核读回不提供任何跨核序（旧注释声明不成立）；构造器扫描路
    // 径下 parse 并发命中纳秒窗即「见 SLOT 非零、读陈旧 wrapper=NULL → 跳
    // 0」——与 72·L3① stub 写同构的弱序窗口，这里以 stlr（RELEASE）封死。
    __atomic_store_n((volatile uint64_t *)slot, (uint64_t)(uintptr_t)trampoline,
                     __ATOMIC_RELEASE);
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
    // （111 轮审计 P3 修：读回失配此前仍返回 0——「armed 但 fires=0」的
    // 96 轮故障形态被静默放行；与 COW 分支的返回语义对齐）
    const uint8_t *now = (const uint8_t *)target;
    g_stub_alive = (memcmp(now, stub, stub_len) == 0) ? 1 : 0;
    return g_stub_alive == 1 ? 0 : -1;
}

/// V3-M2-R4：克隆写点第二 SLOT 武装（主 hook slot-fill 成功后并行执行）。
/// 独立失败面：任何一步失败只置 kStCloneFail 位 + bootlog，**不拆主 hook**
/// （两个挂点互不承载——克隆是加法实验）。
enum { kStCloneFail = 128 };
static void arm_clone_site(const hook_target_t *t, uintptr_t base) {
    uintptr_t ctarget = base + t->clone_hook_off;
    uint8_t cprologue[16];
    int cpatched = entry_patch_present(ctarget);
    if (cpatched && !entry_patch_matches(ctarget, t->clone_expected)) {
        // 111 轮审计 P1 修：与主 hook 同门——补丁态尾 4B 必须与行一致。
        g_hook_status |= kStCloneFail;
        bootlog_line("clone-arm: 补丁态尾 4B 失配（漂移/篡改？）——拒装；"
                     "盘上克隆入口补丁在场而 SLOT 未填，写点调用将崩溃；"
                     "收口：wxkeep runtime remove 或重装");
        return;
    }
    if (cpatched) {
        memcpy(cprologue, t->clone_expected, 16);
    } else {
        if (!kread_buf(ctarget, cprologue, 16)) {
            g_hook_status |= kStCloneFail;
            bootlog_line("clone-arm: 入口不可读（行偏移漂移？）");
            return;
        }
    }
    if (memcmp(cprologue, t->clone_expected, 16) != 0) {
        g_hook_status |= kStCloneFail;
        bootlog_line("clone-arm: 序言门失配——拒装");
        return;
    }
    if (!cpatched && !arm64_prologue_relocatable(cprologue, 16)) {
        g_hook_status |= kStCloneFail;
        bootlog_line("clone-arm: 序言含 PC 相对编码——拒装");
        return;
    }
    if (t->has_clone_func_size) {
        image_layout_t im;
        if (!image_layout((const struct mach_header_64 *)base, (size_t)-1, &im)
            || func_size_matches(&im, t->clone_hook_off, t->clone_func_size) != 1) {
            g_hook_status |= kStCloneFail;
            bootlog_line("clone-arm: 函数身份门失配——拒装");
            image_layout_free(&im);
            return;
        }
        image_layout_free(&im);
    }
    hook_trampoline_t ctr;
    if (prepare_trampoline(ctarget, cprologue, 16, 1, &ctr) != 0) {
        g_hook_status |= kStCloneFail;
        bootlog_line("clone-arm: 蹦床构造失败");
        return;
    }
    // RELEASE 存储（110 轮修）：与克隆 thunk 尾跳的 ldar 配对（主 wrapper 同款）。
    __atomic_store_n(&g_clone_real_wrapper,
                     (void *(*)(void *, void *, void *, void *, void *, void *))ctr.mem,
                     __ATOMIC_RELEASE);
    // R6 证据步：行带 clone_svc_vtable 时启用 [x19+0xb78] vtable 身份门。
    // （111 轮序修：svc 字段先于 wrapper 的 RELEASE 写——110 序在其后，
    // thunk 的 ldar 只与 wrapper 边配对，覆盖不了其后写入；首个写点事件
    // 弱序下可读到陈旧 0 → clsvc 漏计。现字段全部在两条 release 边之前。）
    if (t->has_clone_svc_vtable) {
        g_clone_svc_vt_off = t->clone_svc_vtable;
        g_clone_svc_vt_valid = 1;
    }
    // R6 读路径直调表（111 轮）：lookup 过双身份门（FUNCTION_STARTS 距离
    // + 入口 16B 锚）才武装——直调面比挂点更不可逆，门与主 hook 同强度。
    // 任一门失配 → 表不置 valid（worker 惰性），不置失败位（克隆挂点
    // 本身不受影响——rd 表是加法实验的加法）。
    if (t->has_clone_rd) {
        image_layout_t im;
        int bad = !image_layout((const struct mach_header_64 *)base, (size_t)-1, &im);
        if (!bad && func_size_matches(&im, t->clone_rd_lookup_off,
                                      t->clone_rd_lookup_fs) != 1) bad = 1;
        image_layout_free(&im);
        uint8_t head16[16];
        if (!bad && (!kread_buf(base + t->clone_rd_lookup_off, head16, 16)
                     || memcmp(head16, t->clone_rd_lookup_head, 16) != 0)) bad = 1;
        if (bad) {
            bootlog_line("clone-rd: lookup 身份门失配——直调表不武装（worker 惰性）");
        } else {
            g_clone_rd.lookup_off = t->clone_rd_lookup_off;
            g_clone_rd.wrap_off = t->clone_rd_wrap_off;
            g_clone_rd.getter_off = t->clone_rd_getter_off;
            g_clone_rd.x2single_off = t->clone_rd_x2single_off;
            g_clone_rd.x2desc_off = t->clone_rd_x2desc_off;
            g_clone_rd.x2ctx_off = t->clone_rd_x2ctx_off;
            g_clone_rd_key_slot_off = t->clone_rd_key_slot;
            __atomic_store_n(&g_clone_rd_key_slot_live, 1, __ATOMIC_RELEASE);
            __atomic_store_n(&g_clone_rd_valid, 1, __ATOMIC_RELEASE);
            bootlog_line("clone-rd: 直调表已武装（R6 读路径接线，上限 32 次/进程）");
            // R11 parse 锚定：keyctor 三件套在场则过双身份门（fs+head）后
            // 才置 valid——直调族的第三个入口，门强与 lookup 同级。失配
            // 只惰性 keyctor（px0/读链整体不武装），不回退 rd 门结果。
            if (t->clone_rd_keyctor_off != 0 && t->clone_rd_keyctor_fs != 0) {
                image_layout_t im2;
                int kbad = !image_layout((const struct mach_header_64 *)base,
                                         (size_t)-1, &im2);
                if (!kbad && func_size_matches(&im2, t->clone_rd_keyctor_off,
                                               t->clone_rd_keyctor_fs) != 1) kbad = 1;
                image_layout_free(&im2);
                uint8_t kh[16];
                if (!kbad && (!kread_buf(base + t->clone_rd_keyctor_off, kh, 16)
                              || memcmp(kh, t->clone_rd_keyctor_head, 16) != 0)) kbad = 1;
                if (kbad) {
                    bootlog_line("clone-rd: keyctor 身份门失配——parse 锚定链不武装");
                } else {
                    g_clone_rd.keyctor_off = t->clone_rd_keyctor_off;
                    __atomic_store_n(&g_clone_rd_keyctor_valid, 1, __ATOMIC_RELEASE);
                    bootlog_line("clone-rd: keyctor 已武装（R11 parse 锚定链启用）");
                }
            }
        }
    }
    // M4 插入直调表（113 轮 R8）：ctor/amr 双身份门（rd 表同强度——直调面
    // 两个入口都要门）。任一失配 → 表不置 valid（探针惰性），不置失败位
    //（克隆挂点与 rd 表不受影响——ins 表是加法实验的再加法）。pub_vt 行
    // 在位才启用认证门；270135 不带 = 探针-only（clpub 证据位）。
    if (t->has_clone_ins) {
        image_layout_t im;
        int bad = !image_layout((const struct mach_header_64 *)base, (size_t)-1, &im);
        if (!bad && func_size_matches(&im, t->clone_ins_ctor_off,
                                      t->clone_ins_ctor_fs) != 1) bad = 1;
        if (!bad && func_size_matches(&im, t->clone_ins_amr_off,
                                      t->clone_ins_amr_fs) != 1) bad = 1;
        image_layout_free(&im);
        uint8_t h1[16], h2[16];
        if (!bad && (!kread_buf(base + t->clone_ins_ctor_off, h1, 16)
                     || memcmp(h1, t->clone_ins_ctor_head, 16) != 0)) bad = 1;
        if (!bad && (!kread_buf(base + t->clone_ins_amr_off, h2, 16)
                     || memcmp(h2, t->clone_ins_amr_head, 16) != 0)) bad = 1;
        if (bad) {
            bootlog_line("clone-ins: ctor/amr 身份门失配——插入表不武装（探针惰性）；"
                         "地址行漂移：按当前构建重派生 hooks 数据行"
                         "（tools/derive_runtime_hooks.py）后重跑 wxkeep runtime hooks");
        } else {
            g_clone_ins.ctor_off = t->clone_ins_ctor_off;
            g_clone_ins.amr_off = t->clone_ins_amr_off;
            g_clone_ins.msg_vt_off = t->clone_ins_msg_vt;
            g_clone_ins.pub_vt_off = t->has_clone_ins_pub_vt ? t->clone_ins_pub_vt : 0;
            g_clone_ins_pub_gated = t->has_clone_ins_pub_vt;
            __atomic_store_n(&g_clone_ins_valid, 1, __ATOMIC_RELEASE);
            bootlog_line(g_clone_ins_pub_gated
                ? "clone-ins: 插入表已武装（R8，认证门在位，上限 8 次/进程；容器合同接线前 clins= 恒 0）"
                : "clone-ins: 插入表已武装（R8 探针模式——pub 认证值待 clpub 证据派生，插入调用惰性）");
        }
    }
    __atomic_store_n(&g_clone_hook_target, ctarget, __ATOMIC_RELEASE);
    int rc = try_slot_fill(ctarget, (void *)&revoke_clone_hook);
    if (rc != 0) {
        __atomic_store_n(&g_clone_hook_target, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_clone_real_wrapper, NULL, __ATOMIC_RELEASE);
        munmap(ctr.mem, 4096);   // 110 轮修：失败路径蹦床页归还（不再泄漏）
        if (rc == ENOENT && !cpatched) {
            // 111 轮审计 P3 修：入口本就无补丁（数据先行行/旧版 CLI 装机）——
            // 原函数字节原封未动，实验未武装 = 安全态，非故障。不置
            // kStCloneFail（此前与危险态混报「将崩溃」+ 污染状态位）。
            bootlog_line("clone-arm: 克隆入口未补丁——实验未武装（安全；"
                         "重跑 wxkeep runtime install 可补装双点）");
        } else {
            g_hook_status |= kStCloneFail;
            // 诚实边界：CLI 已在盘上写入克隆入口补丁而 SLOT 恒 0——首次撤回写点
            // 调用 br x16 → 跳 0 即崩。运行时无 TEXT 写权（W^X），无法中和；唯一
            // 收口 = `wxkeep runtime remove`（还原入口字节）或重装。bootlog 留痕。
            bootlog_line("clone-arm: slot-fill 失败（rc≠0）——盘上入口补丁在场而 SLOT 未填，"
                         "撤回写点调用将崩溃；收口：wxkeep runtime remove 或重装");
        }
    } else {
        bootlog_line("clone-arm: OK（写点第二 SLOT 已填）");
    }
}

static int install_hook(const hook_target_t *t, uintptr_t base) {
    int32_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_arm_done, &expected, 1, 0,
                                     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return -2;   // 别的触发源已装
    }
    g_image_base = base;   // R6 证据步：行偏移→绝对 VA 的换算基（slide 后）
    uintptr_t target = base + t->hook_off;
    size_t len = t->expected_len;               // x64 12 / arm64 16
    uint8_t prologue[16];
    memset(prologue, 0, sizeof(prologue));   // x64 只填 12B——late20s 的 16B
                                             // 转储不再带 4B 栈垃圾（审计 P3）
    // T6（95 轮）：arm64 先做内核级补丁态识别。补丁态 = 入口已是我们的
    // 跳板——prologue 用行 expected（蹦床重放原始 16B、跳回 target+len，
    // 与未补丁语义一致），并跳过对目标页的一切用户态触碰（用户态
    // memcpy 读/写已改写签名页 = SIGKILL CS 击杀，95 轮副本实测）。
    int entry_patched = 0;
    if (t->is_arm64 && entry_patch_present(target)) {
        if (!entry_patch_matches(target, t->expected)) {
            // 111 轮审计 P1 修：补丁在场而尾 4B ≠ 行 expected——同 UUID 内容
            // 漂移（10-03 形态）或行篡改。拒装（不再盲信行字节重放）；
            // 矛盾态如实留痕（W^X 下无中和手段，收口=remove/重装）。
            bootlog_line("arm: 补丁态尾 4B 失配（内容漂移/行篡改？）——拒装；"
                         "盘上入口补丁在场而 SLOT 未填，parse 调用将崩溃；"
                         "收口：wxkeep runtime remove 或重装");
            g_hook_status |= kStPrologueMismatch;
            return -1;
        }
        entry_patched = 1;
    }
    if (entry_patched) {
        memcpy(prologue, t->expected, len);
    } else {
        // 未补丁态的入口读走内核读（110 轮修）：语义与用户态读等价（映射页
        // 必成功），但「行偏移指向未映射区」（坏行/极端漂移）从构造器
        // SIGSEGV 降级为干净拒装——与 try_slot_fill 的入口读同 doctrine。
        if (!kread_buf(target, prologue, len)) {
            g_hook_status |= kStInstallFail;
            g_install_step = 2;
            g_install_errno = EIO;
            bootlog_line("arm: 入口内核读失败（页不可读）——拒装");
            return -1;
        }
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
    // RELEASE 存储（110 轮修）：与 thunk 尾跳的 ldar 配对——wrapper 指针与
    // 此前全部依赖字段（蹦床内容/上下文）经同一边对全核可见，不再依赖
    // SLOT 读侧语义间接建立同步。
    __atomic_store_n(&g_real_wrapper,
                     (void *(*)(void *, void *, void *, void *, void *, void *))tr.mem,
                     __ATOMIC_RELEASE);
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
        // V3-M2-R4：克隆写点第二 SLOT 并行武装（独立失败面——不拆主 hook）
        if (t->is_arm64 && t->has_clone) arm_clone_site(t, base);
        return 0;
    }
    if (t->is_arm64) {
        g_hook_status |= kStInstallFail;
        if (slot_rc != ENOENT) {
            // 111 轮审计 P3 修：EIO 族 = 盘上入口补丁在场而双门拒填 SLOT——
            // 首次 parse 调用 br x16 → 跳非零垃圾即崩。主 hook 此前没有
            // clone 同款的矛盾态留痕（排障面不对称）。
            bootlog_line("arm: slot-fill 被门拒（rc≠ENOENT）——盘上入口补丁在场"
                         "而 SLOT 未填，parse 调用将崩溃；收口：wxkeep runtime"
                         " remove 或重装");
        }
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
            // |= 而非覆盖赋值（108 轮修）：主 hook 武装成功后 arm_clone_site
            // 可能已置 kStCloneFail（128）——覆盖式 `= kStArmed` 会抹掉它，
            // marker 的 clone-fail 判读（CLI runtimeStatusFlags）结构性不可达。
            g_hook_status |= kStArmed;
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
            // 与 uuid_matches 同界的 LC_UUID 载荷检查（111 轮审计 P3：
            // 此循环缺 (end-p)>=size——纯硬化一致性）
            if (cmd == LC_UUID && size >= 24 && (size_t)(end - p) >= size) {
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
        @"loaded ts=%f mr2=%@ status=%d enc=2 istep=%d ierr=%d fires=%d hits=%d zero=%d selfskip=%d clone=%d clmiss=%d clrow=%d cllastlen=%d clpair=%d clsvc=%d clkey=%d clkeylen=%d clhit=%d clmissq=%d clget=%d clinner=%d clpub=%d clpubm=%d clins=%d clsvc2=%d cfg=%.0f cfgh=%016llx last=%@ inner=%@ probe=%@\n",
        [NSDate date].timeIntervalSince1970,
        g_hook_installed ? @"hook-armed" : @"marker-only", g_hook_status,
        g_install_step, g_install_errno,
        g_rewrite_fires, g_rewrite_hits, g_zero_fires,
        g_self_skips, g_clone_captures, g_clone_nomethods,
        g_clone_rows, g_clone_last_len, g_clone_pairs, g_clone_svc_hits,
        g_clone_key_caps, g_clone_last_key_len,
        g_clone_rd_hits, g_clone_rd_misses, g_clone_rd_gets, g_clone_rd_inner,
        g_clone_pub_probes, g_clone_pub_matches, g_clone_ins_calls,
        g_clone_svc2_hits,
        g_cfg_stamp, g_cfg_hash,
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
        // 改走 boot log 通道（构造器诊断同款，沙盒 tmp 必可达）。定时器线程
        // 是安全上下文——这里顺带承担武装路径环形缓冲的统一落盘（110 轮）。
        @autoreleasepool {
            if (g_hook_installed && g_hook.trampoline) {
                // 入口在位判定双形态（108 轮修）：旧 inline stub（ldr x17,#8;
                // br x16）与 T6 入口补丁（adrp x16,SLOT; ldr; br）——slot 武装
                // 机器上旧单形态判定恒 0，boot log tick 行曾被误写 alive=0
                //（误导排障）。读走内核读（目标页访问 doctrine）。
                uint8_t head12[12];
                if (kread_buf((uintptr_t)g_hook.target, head12, 12)) {
                    uint32_t w[3];
                    memcpy(w, head12, 12);
                    g_stub_alive = (memcmp(head12, "\x51\x00\x00\x58\x20\x02\x1f\xd6", 8) == 0
                                    || slotfill_decode(w, (uintptr_t)g_hook.target) != 0) ? 1 : 0;
                } else {
                    g_stub_alive = 0;
                }
            }
            char tick[176];
            snprintf(tick, sizeof(tick),
                "tick installed=%d status=%d alive=%d calls=%d fires=%d hits=%d zero=%d selfskip=%d qz=%d arg1=%s",
                g_hook_installed, g_hook_status, g_stub_alive, g_hook_calls,
                g_rewrite_fires, g_rewrite_hits, g_zero_fires, g_self_skips,
                g_quiesce_threads, g_arg1_valid ? "" : "<none>");
            bootlog_line(tick);
            // arg1 十六进制样本（含 NUL 尾）与 last/inner 内文样本走同一条
            // 环形缓冲行有长度限制——拼进独立行（受 176B 截断，诊断面够用）。
            if (g_arg1_valid) {
                char hex[72];
                for (int k = 0; k < 24 && k * 2 + 1 < (int)sizeof(hex); k++) {
                    snprintf(hex + k * 2, 3, "%02x", g_arg1_head[k]);
                }
                char l2[192];
                snprintf(l2, sizeof(l2), "arg1=%s last=%s inner=%s", hex,
                         g_last_fired[0] ? (const char *)cstr_sample(g_last_fired).UTF8String : "<none>",
                         g_last_inner[0] ? (const char *)cstr_sample(g_last_inner).UTF8String : "<none>");
                bootlog_line(l2);
            }
            bootlog_flush();
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
static int probe_match_target(uintptr_t addr, uint32_t *cmds_len);

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
            && probe_match_target((uintptr_t)addr, NULL)) {
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
// cmds_len（可选出参）：回传 sizeofcmds——调用方不再对 base 做用户态
// 裸读（110 轮收紧：该读是扫描路径上唯一的直解引用点，虽与探针同页
// 理论无险，统一走探针结果零成本）。
static int probe_match_target(uintptr_t addr, uint32_t *cmds_len) {
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
    if (hit && cmds_len) *cmds_len = h->sizeofcmds;
    return hit;
}

static void scan_and_arm(void) {
    if (g_hook_installed) return;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;   // 111 轮审计 P2：count 快照后镜像收缩 → 越界返
                             // NULL——直读 sizeofcmds 即 NULL 解引用（500ms
                             // 兜底定时器恰跑在壳程序动态装卸活跃期）
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
        // sizeofcmds 由探针回传（110 轮收紧：不在 base 上做用户态裸读——
        // probe_match_target 已 mach-读验证 32+sizeofcmds 全量可读，同界复用）
        uint32_t cmds = 0;
        probe_match_target(base, &cmds);
        try_hook_image((const struct mach_header_64 *)base, 0, 32 + cmds);
    }
}

static void arm_late(void) {
    scan_and_arm();
    bootlog_flush();   // 武装路径环形缓冲在此（全局队列=安全上下文）落盘
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
            if (!mh) continue;   // 与 scan_and_arm 同款 NULL 门（111 轮审计 P2）
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
    bootlog_flush();   // 构造器尾：武装路径环形缓冲首次落盘（安全上下文）
    // 诊断通道（T4 排障）：构造器走完的尾部标记（经环形缓冲——110 轮统一通道）
    @autoreleasepool {
        NSString *cfgPath = nil;
        NSDictionary *cfgDiag = read_runtime_config_at(&cfgPath);
        NSString *tipDiag = [cfgDiag objectForKey:@"tip_text"];
        bootlog_line_ns([NSString stringWithFormat:@"cfgdiag path=%@ tip=%@ rows=%@",
            cfgPath ?: @"<nil>",
            [tipDiag isKindOfClass:[NSString class]] && tipDiag.length > 0 ? @"set" : @"<empty>",
            cfgDiag[@"hooks"] ? @([(NSArray *)cfgDiag[@"hooks"] count]) : @"0"]);
        bootlog_line_ns([NSString stringWithFormat:
            @"done config=%@ installed=%d status=%d scanmiss=%d cb=%d last_uuid=%s armed=%d",
            cfgDiag ? @"yes" : @"no", g_hook_installed, g_hook_status,
            g_scan_missed, g_cb_count,
            g_last_uuid[0] ? g_last_uuid : "<none>", g_hook_installed]);
        bootlog_flush();
    }
    // 诊断通道（T4 排障）：延迟采样——wechat.dylib 由 libwxld 在 main 内
    // dlopen，构造器期快照看不到它；20s 后回调证据已齐（全局队列=安全
    // 上下文，经环形缓冲统一落盘——110 轮）。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            NSMutableString *line = [NSMutableString stringWithFormat:
                @"late20s installed=%d status=%d cb=%d last_uuid=%s scanmiss=%d istep=%d errno=%d slot=%d prologue=",
                g_hook_installed, g_hook_status, g_cb_count,
                g_last_uuid[0] ? g_last_uuid : "<none>", g_scan_missed,
                g_install_step, g_install_errno, g_arm_via_slot];
            if (g_saved_prologue_valid) {
                for (int k = 0; k < 16; k++) [line appendFormat:@"%02x", g_saved_prologue[k]];
            } else {
                [line appendString:@"<not-captured>"];
            }
            bootlog_line_ns(line);
            bootlog_flush();
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

/// V3-M2 克隆缝：newmsgid 提取（只读孪生的直接驱动）。返回 1/0，out 填值。
int wxkeep_runtime_test_extract_newmsgid(const unsigned char *data, unsigned long len,
                                         unsigned long long *out) {
    uint64_t v = 0;
    if (!extract_tag_u64(data, (uint64_t)len, "<newmsgid>", sizeof("<newmsgid>") - 1, &v))
        return 0;
    if (out) *out = v;
    return 1;
}

/// V3-M2 克隆缝：捕获入口直接驱动（含派发）。返回本次捕获结果（1/0，
/// 与生产 clone_capture 同源）；msgid/from 回传最近快照（仅成功时语义
/// 成立）。队列异步——快照在派发前写入，本函数返回即可读（不需要等
/// worker）。
int wxkeep_runtime_test_clone_capture(const unsigned char *data, unsigned long len,
                                      unsigned long long *msgid,
                                      char *from, unsigned long fromcap) {
    int captured = clone_capture(data, (uint64_t)len);
    if (!captured) return 0;
    if (msgid) *msgid = g_clone_last.newmsgid;
    if (from && fromcap > 0) {
        strncpy(from, g_clone_last.fromusr, fromcap - 1);
        from[fromcap - 1] = 0;
    }
    return 1;
}

/// V3-M2 克隆缝：证据计数读回（captures/skips/nomethods）。
void wxkeep_runtime_test_clone_counts(int *captures, int *skips, int *nomethods) {
    if (captures) *captures = g_clone_captures;
    if (skips) *skips = g_clone_skips;
    if (nomethods) *nomethods = g_clone_nomethods;
}

/// V3-M2-R5 配对缝：配对完整记录数读回；可选清槽（测试隔离）。
int wxkeep_runtime_test_clone_pair_count(int clear_pending) {
    if (clear_pending) {
        __atomic_store_n(&g_clone_pending_msgid, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_clone_pending_ts, 0, __ATOMIC_RELAXED);
        g_clone_pending_fromusr[0] = 0;
    }
    return g_clone_pairs;
}

/// V3-M2 写点捕获缝（109 轮合同修正版）：对合成 shared_ptr 对直接驱动
/// clone_hook_body。构造（全部真实堆分配，走同一条内核读路径）：
///   args[1] = &pair{inner, ctl}（写点真实形态——caller 的 shared_ptr 栈
///   拷贝）；content_bytes > 0 → inner 指向可读堆块（事件路径，返回 1）；
///   content_bytes == 0 → inner = 0（g_clone_skips 路径，返回 0）。
/// rows/skips/objcaps 回传证据计数。返回本次事件处理结果（1/0）。
int wxkeep_runtime_test_clone_rows(unsigned long long content_bytes,
                                   int *rows, int *skips, int *objcaps) {
    // 开关：body 在 g_clone_message 关时直接透传——测试内强制开
    int saved = g_clone_message;
    g_clone_message = 1;
    // 合成 pair：inner 可读堆块（16B，内容无关——本缝不读其字段）或 0
    uint64_t *inner_obj = NULL;
    uint64_t *pair = malloc(16);
    if (content_bytes > 0) {
        inner_obj = calloc(1, 16);
        inner_obj[0] = 0xA11CE;
        pair[0] = (uint64_t)(uintptr_t)inner_obj;
    } else {
        pair[0] = 0;
    }
    pair[1] = 0;   // ctl = NULL（内核读不触碰 ctl——本缝只解引用 args[1] 一次）
    void *args[6] = { (void *)0x1111, pair, (void *)0x2222, NULL, NULL, NULL };
    clone_hook_body(args);
    g_clone_message = saved;
    int r = (content_bytes > 0) ? 1 : 0;
    if (rows) *rows = g_clone_rows;
    if (skips) *skips = g_clone_skips;
    if (objcaps) *objcaps = g_clone_obj_caps;
    free(pair); free(inner_obj);
    return r;
}

/// R6 证据步缝（110 轮）：验证 clsvc 身份门的判定本体。构造合成 consumer
/// （+0xb78 → svc 对象，svc+0 = vt_word）；g_image_base=0x1000、行偏移
/// 0x9deeb48 固定——vt_word == 0x1000 + 0x9deeb48 时命中。vt_mismatch=
/// 1 时 vt_word 填错值（应不命中）。返回本次 clsvc 命中计数增量。
int wxkeep_runtime_test_clone_svc(int vt_mismatch, int *rows) {
    uint64_t expect = 0x1000 + 0x9deeb48ULL;
    uint64_t *svc = malloc(16);
    svc[0] = vt_mismatch ? (expect ^ 0x20) : expect;
    uint64_t *consumer = calloc(1, 0xb80 + 8);
    consumer[0xb78 / 8] = (uint64_t)(uintptr_t)svc;
    __atomic_store_n(&g_clone_caller_x19, (uint64_t)(uintptr_t)consumer,
                     __ATOMIC_RELEASE);
    g_image_base = 0x1000;
    g_clone_svc_vt_off = 0x9deeb48;
    g_clone_svc_vt_valid = 1;
    int before = g_clone_svc_hits;
    int saved = g_clone_message;
    g_clone_message = 1;
    uint64_t *pair = malloc(16);
    pair[0] = 0;   // inner=0：走 skips 早退——clsvc 检查在早退之前（rows++ 后）
    void *args[6] = { (void *)0x1111, pair, (void *)0x2222, NULL, NULL, NULL };
    clone_hook_body(args);
    g_clone_message = saved;
    int delta = g_clone_svc_hits - before;
    if (rows) *rows = g_clone_rows;
    free(pair); free(consumer); free(svc);
    return delta;
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
long wxkeep_runtime_test_slot_gate(int prefill) { return -2; }   // 同上（SLOT 门缝）
#endif

#if defined(__arm64__) || defined(__aarch64__)
/// SLOT 落点双门缝（110 轮 P0）：与 slot_chain 同款页建设，prefill 非 0 时
/// 预置 SLOT 内容为非零——生产 try_slot_fill 的真零门必须拒装（返回 1）；
/// prefill 为 0 时照常武装（返回 0，与 slot_chain 互证）。页全归还。
long wxkeep_runtime_test_slot_gate(int prefill) {
    uint8_t *slot_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
    if (slot_page == MAP_FAILED) return -5;
    uint64_t slot = (uint64_t)(uintptr_t)slot_page;
    *(volatile uint64_t *)slot = prefill ? 0x0000DEADBEEF0000ULL : 0;
    uint8_t *jit = mmap((void *)(uintptr_t)(slot + 0x400000), 4096,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
    if (jit == MAP_FAILED) { munmap(slot_page, 4096); return -5; }
    int64_t delta = (int64_t)(uint64_t)(uintptr_t)jit - (int64_t)slot;
    if (delta < -(int64_t)0xF0000000LL || delta > (int64_t)0xF0000000LL) {
        munmap(jit, 4096); munmap(slot_page, 4096); return -5;
    }
    static const uint32_t cont[] = {
        0xCA010000u, 0xCA020000u, 0xD65F03C0u,
    };
    static const uint32_t orig[4] = {0xD503201Fu, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu};
    pthread_jit_write_protect_np(0);
    memcpy(jit, orig, 16);
    memcpy(jit + 16, cont, sizeof(cont));
    int64_t pages = ((int64_t)(slot & ~(uint64_t)0xFFF)
                     - (int64_t)((uint64_t)(uintptr_t)jit & ~(uint64_t)0xFFF)) >> 12;
    uint32_t imm = (uint32_t)(pages & 0x1FFFFF);
    uint32_t w[3] = {
        0x90000000u | ((imm & 0x3u) << 29) | ((imm >> 2) << 5) | 16u,
        0xF9400000u | ((uint32_t)((slot & 0xFFF) >> 3) << 10) | (16u << 5) | 16u,
        0xD61F0200u,
    };
    memcpy(jit, w, 12);
    sys_icache_invalidate(jit, 16 + sizeof(cont));
    pthread_jit_write_protect_np(1);
    int rc = try_slot_fill((uintptr_t)jit, slot_arm_target());
    pthread_jit_write_protect_np(0);
    memcpy(jit, orig, 16);
    sys_icache_invalidate(jit, 16);
    pthread_jit_write_protect_np(1);
    munmap(jit, 4096);
    munmap(slot_page, 4096);
    if (rc != 0) return 1;   // 门拒（prefill 时预期）
    // 武装成功时 SLOT 已被填——归还页即可（匿名页，无残留语义）
    return 0;
}
#endif

int wxkeep_runtime_test_quiesce_count(void) { return g_quiesce_threads; }

// ---------------------------------------------------------------------------
// R6 接线缝（111 轮）
// ---------------------------------------------------------------------------

/// hooks 行 rd 组读取缝：第 idx 行的九字段（组不存在返回 -1——组在场时
/// 行解析已保证完整）。
int wxkeep_runtime_test_hook_row_rd(int idx, unsigned long *lookup_off,
                                    unsigned long *wrap_off, unsigned long *getter_off,
                                    unsigned long *x2single_off, unsigned long *x2desc_off,
                                    unsigned long *x2ctx_off, unsigned long *key_slot,
                                    unsigned long *lookup_fs) {
    if (idx < 0 || idx >= g_ext_hook_count) return -1;
    const hook_target_t *t = &g_ext_hooks[idx];
    if (!t->has_clone_rd) return -1;
    if (lookup_off) *lookup_off = (unsigned long)t->clone_rd_lookup_off;
    if (wrap_off) *wrap_off = (unsigned long)t->clone_rd_wrap_off;
    if (getter_off) *getter_off = (unsigned long)t->clone_rd_getter_off;
    if (x2single_off) *x2single_off = (unsigned long)t->clone_rd_x2single_off;
    if (x2desc_off) *x2desc_off = (unsigned long)t->clone_rd_x2desc_off;
    if (x2ctx_off) *x2ctx_off = (unsigned long)t->clone_rd_x2ctx_off;
    if (key_slot) *key_slot = (unsigned long)t->clone_rd_key_slot;
    if (lookup_fs) *lookup_fs = (unsigned long)t->clone_rd_lookup_fs;
    return 0;
}

/// M4 插入直调表行字段回读缝（ins 组组门测试面）：行不含 ins 组返回 -1。
int wxkeep_runtime_test_hook_row_ins(int idx, unsigned long *ctor_off,
                                     unsigned long *amr_off, unsigned long *msg_vt,
                                     unsigned long *pub_vt, unsigned long *ctor_fs,
                                     unsigned long *amr_fs, int *pub_gated) {
    if (idx < 0 || idx >= g_ext_hook_count) return -1;
    const hook_target_t *t = &g_ext_hooks[idx];
    if (!t->has_clone_ins) return -1;
    if (ctor_off) *ctor_off = (unsigned long)t->clone_ins_ctor_off;
    if (amr_off) *amr_off = (unsigned long)t->clone_ins_amr_off;
    if (msg_vt) *msg_vt = (unsigned long)t->clone_ins_msg_vt;
    if (pub_vt) *pub_vt = (unsigned long)t->clone_ins_pub_vt;
    if (ctor_fs) *ctor_fs = (unsigned long)t->clone_ins_ctor_fs;
    if (amr_fs) *amr_fs = (unsigned long)t->clone_ins_amr_fs;
    if (pub_gated) *pub_gated = t->has_clone_ins_pub_vt;
    return 0;
}

/// sso_key_snapshot 直驱缝：24B 串对象头 → 字节快照（返回长度）。
int wxkeep_runtime_test_sso_key_snapshot(const unsigned char *head24,
                                         char *out, int cap) {
    if (cap > 64) cap = 64;
    return sso_key_snapshot(head24, (uint8_t *)out, (size_t)cap);
}

/// 配对帧注入缝：设置 thunk 同款快照。sp 参数 = **thunk 存进全局的原始
/// sp**（= caller sp − 0xE0，body 侧 +0xE0 换算——与生产语义一致）；测试
/// 按「key 对象地址 − key_slot − 0xE0」反推传入。
void wxkeep_runtime_test_set_clone_frame(unsigned long long x19,
                                         unsigned long long thunk_sp,
                                         unsigned int key_slot_off, int enable) {
    __atomic_store_n(&g_clone_caller_x19, x19, __ATOMIC_RELEASE);
    __atomic_store_n(&g_clone_caller_sp, thunk_sp, __ATOMIC_RELEASE);
    g_clone_rd_key_slot_off = key_slot_off;
    __atomic_store_n(&g_clone_rd_key_slot_live, enable ? 1 : 0, __ATOMIC_RELEASE);
}

/// 最近一次 key 快照读回（返回长度，0=无）。
int wxkeep_runtime_test_last_key(char *out, int cap) {
    if (g_clone_last_key_len <= 0) return 0;
    int n = g_clone_last_key_len < cap ? g_clone_last_key_len : cap;
    memcpy(out, g_clone_last_key, n);
    if (n < cap) out[n] = 0;
    return g_clone_last_key_len;
}

/// R6 证据计数读回（clhit/clmissq/clget/clinner/clkey + 直调护栏余量）。
void wxkeep_runtime_test_clone_rd_counts(int *hits, int *misses, int *gets,
                                         int *inner, int *keys, int *lookups,
                                         int *svc2) {
    if (hits) *hits = g_clone_rd_hits;
    if (misses) *misses = g_clone_rd_misses;
    if (gets) *gets = g_clone_rd_gets;
    if (inner) *inner = g_clone_rd_inner;
    if (keys) *keys = g_clone_key_caps;
    if (lookups) *lookups = __atomic_load_n(&g_clone_rd_lookups, __ATOMIC_RELAXED);
    if (svc2) *svc2 = g_clone_svc2_hits;
}

/// R11 parse 锚定主体直驱缝（clone_parse_run 同一条代码）：注入式武装
///（g_image_base/g_clone_rd/g_clone_svc_vt_off 保存-改写-恢复，serialized
/// 套件纪律）；fns 全部为**绝对地址** JIT 桩，keyctor 桩 sret 写 24B 串
/// 对象头。cand 须过 [cand+0xb78]→[svc]==base+svc_vt_off 同门。返回位掩码。
int wxkeep_runtime_test_clone_parse_invoke(unsigned long long cand,
                                           unsigned long long obj,
                                           unsigned long keyctor_fn,
                                           unsigned long lookup_fn,
                                           unsigned long wrap_fn,
                                           unsigned long getter_fn,
                                           unsigned long x2single_fn,
                                           unsigned long x2ctx_fn,
                                           unsigned long base,
                                           unsigned long svc_vt_off) {
    uintptr_t savedBase = g_image_base;
    uint32_t savedVt = g_clone_svc_vt_off;
    clone_rd_table_t savedRd = g_clone_rd;
    g_image_base = (uintptr_t)base;
    g_clone_svc_vt_off = (uint32_t)svc_vt_off;
    g_clone_rd.keyctor_off = (uint32_t)(keyctor_fn - base);
    g_clone_rd.lookup_off = (uint32_t)(lookup_fn - base);
    g_clone_rd.wrap_off = (uint32_t)(wrap_fn - base);
    g_clone_rd.getter_off = (uint32_t)(getter_fn - base);
    g_clone_rd.x2single_off = (uint32_t)(x2single_fn - base);
    g_clone_rd.x2ctx_off = (uint32_t)(x2ctx_fn - base);
    int r = clone_parse_run((uint64_t)cand, (uint64_t)obj);
    g_image_base = savedBase;
    g_clone_svc_vt_off = savedVt;
    g_clone_rd = savedRd;
    return r;
}

/// worker 直驱缝（生产 clone_rd_run 同一条代码）：fn 全部为**绝对地址**
//（测试注入 JIT 桩）。svc/consumer/key 由调用方构造（svc 须满足
// [svc]==base+svc_vt_off 的 vtable 门——与生产同门）。返回 r 位掩码。
int wxkeep_runtime_test_clone_rd_invoke(unsigned long long svc,
                                        unsigned long long consumer,
                                        const char *key, int key_len,
                                        unsigned long lookup_fn, unsigned long wrap_fn,
                                        unsigned long getter_fn, unsigned long x2single_fn,
                                        unsigned long x2ctx_fn,
                                        unsigned long base, unsigned long svc_vt_off) {
    clone_full_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.svc = svc;
    rec.consumer = consumer;
    rec.key_len = (uint32_t)key_len;
    if (key && key_len > 0) memcpy(rec.key, key, key_len > 64 ? 64 : (size_t)key_len);
    clone_rd_fns_t fns = {
        .lookup = (void *)(uintptr_t)lookup_fn,
        .wrap = (void *)(uintptr_t)wrap_fn,
        .getter = (void *)(uintptr_t)getter_fn,
        .x2single = (void *)(uintptr_t)x2single_fn,
        .x2ctx = (void *)(uintptr_t)x2ctx_fn,
        .x2desc = (const void *)(uintptr_t)0x10000,   // 桩不消费
    };
    return clone_rd_run(&rec, &fns, base, (uint32_t)svc_vt_off, NULL, NULL);
}

/// M4 插入链证据计数读回（clpub/clins + 护栏余量 + 认证门命中）。
void wxkeep_runtime_test_clone_ins_counts(int *probes, int *matches,
                                          int *calls, int *inserts, int *cnt_caps) {
    if (probes) *probes = g_clone_pub_probes;
    if (matches) *matches = g_clone_pub_matches;
    if (calls) *calls = g_clone_ins_calls;
    if (inserts) *inserts = __atomic_load_n(&g_clone_ins_inserts, __ATOMIC_RELAXED);
    if (cnt_caps) *cnt_caps = g_clone_cnt_caps;
}

/// M4 探针直驱缝（生产 clone_ins_probe 同一条代码）：构造 svc/holder/
/// msg_obj 形态（svc+8→holder、holder+0→vtable、msg_obj+0/+0x10 证据字），
/// pub_gate_off 非 0 时按认证门走（与生产同门——需 g_image_base 一致性，
/// 测试传 base=0 时 match 恒 0 是诚实结果）。
void wxkeep_runtime_test_clone_ins_probe(unsigned long long svc,
                                         unsigned long long msg_obj,
                                         unsigned long base,
                                         unsigned long pub_vt_off) {
    // 测试缝私有形态注入（不污染生产全局）：直接以调用方给的字段地址布局
    uint64_t savedBase = g_image_base;
    uint8_t savedGate = g_clone_ins_pub_gated;
    uint32_t savedVt = g_clone_ins.pub_vt_off;
    if (base) {
        g_image_base = base;
        g_clone_ins_pub_gated = pub_vt_off != 0;
        g_clone_ins.pub_vt_off = (uint32_t)pub_vt_off;
    }
    clone_ins_probe(svc, msg_obj);
    if (base) {
        g_image_base = savedBase;
        g_clone_ins_pub_gated = savedGate;
        g_clone_ins.pub_vt_off = savedVt;
    }
}

/// M4 插入 ABI 直驱缝（生产 clone_ins_run 同一条代码）：ctor/amr 为
/// **绝对地址** JIT 桩；publisher/container/source/pair_obj 由调用方构造
///（pair_obj=AMR pair 的对象位——生产语义待 R9 容器合同定案）。返回
/// 位掩码（1=ctor 门过 2=AMR 已调）。
int wxkeep_runtime_test_clone_ins_invoke(unsigned long long publisher,
                                         unsigned long long container,
                                         unsigned long long source,
                                         unsigned long long pair_obj,
                                         unsigned long ctor_fn, unsigned long amr_fn,
                                         unsigned long base, unsigned long msg_vt_off) {
    return clone_ins_run(publisher, container, source, pair_obj,
                         (const void *)(uintptr_t)ctor_fn, (const void *)(uintptr_t)amr_fn,
                         base, (uint32_t)msg_vt_off);
}
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
