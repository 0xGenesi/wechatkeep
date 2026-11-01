#ifndef WXKEEP_RUNTIME_H
#define WXKEEP_RUNTIME_H

// ---- 测试缝（仅单测使用；运行时走 runtime.json 配置）----
// 把 data 构造成长串 SSO（内容须为含 <replacemsg>…</replacemsg> 的 XML），
// 执行一次 hook 改写逻辑并把结果留在 data 内，返回内文长度；-1 = 未命中/放弃。
// tip 内可含 {from} 占位符（以原内文首对引号内的昵称展开）。
long wxkeep_runtime_test_rewrite(unsigned char *data, unsigned long data_len,
                                 const char *tip, unsigned long tip_len);
// 对伪 mach_header_64（32B 头 + LC_UUID）执行 270099 身份判定；1 = 匹配。
// len = hdr 起可读字节数——命令区游走以 min(32+sizeofcmds, len) 为界
// （模糊测试实证：只信 sizeofcmds 的裸缓冲契约会冲出未映射页）。
int wxkeep_runtime_test_uuid_match(const void *hdr, unsigned long len);
// 切换自发撤回门（“你撤回…”内文是否也改写；默认 0=不改）。
void wxkeep_runtime_test_set_policy(int rewrite_self);
// 解析 runtime.json 形态的 JSON 字节装载外部 hooks 表（重置旧态），
// 返回被接受的行数（0 = 外部表不启用）；JSON 不可解析返回 -1。
int wxkeep_runtime_test_parse_hooks(const char *json, unsigned long json_len);
// 读取第 idx 行外部表条目的核心字段；越界返回 -1。
int wxkeep_runtime_test_hook_row(int idx, unsigned long *hook_off,
                                 unsigned long *msg_arg, unsigned long *xml_sso_off,
                                 int *is_arm64, int *expected_len);
// 函数级身份门核对缝（77 续）：对伪镜像缓冲（段表 + LC_FUNCTION_STARTS）
// 执行与 install_hook 同一的核对。1=匹配 0=失配 -1=元数据缺失。
// func_size 语义 = 函数起点到下一函数起点的距离（与 machutil 派生同源）。
int wxkeep_runtime_test_func_size_verify(const void *hdr, unsigned long avail,
                                         unsigned long hook_off,
                                         unsigned long func_size);
// 同上：anchor 门核对（anchor_va 为切片内 VM 偏移；bytes ≤64B）。
int wxkeep_runtime_test_anchor_verify(const void *hdr, unsigned long avail,
                                      unsigned long anchor_va,
                                      const unsigned char *bytes, unsigned long len);
// 通用 keeptip 缝：对 XML 缓冲执行 <newmsgid> 数字清零，返回清零个数。
int wxkeep_runtime_test_zero(unsigned char *data, unsigned long len);
// T4 实验缝：对 XML 缓冲执行 <msgid> 数字清零（等长），返回清零个数。
int wxkeep_runtime_test_zero_msgid(unsigned char *data, unsigned long len);
// 按 plist 语义从任意路径加载配置并应用（生产同路径），返回接受的 hooks
// 行数（-1 = 文件不可解析）；应用前重置 tip/策略/hooks。
int wxkeep_runtime_test_load_config_file(const char *path);
// 当前生效文案的字节长度。
int wxkeep_runtime_test_tip_len(void);
// marker 候选目录回落策略缝（77 续）：按序尝试两目录写 runtime.marker，
// 返回首个成功序号（0/1），全败 -1。
int wxkeep_runtime_test_marker_dirs(const char *d1, const char *d2);
// per-arch 串对象头布局缝（77 续⑧）：1=arm64 变体布局（flag=[0x17] 符号
// /data@[0]/size@[8]），0=x64 标准布局（byte0 奇=长/size@[8]/ptr@[0x10]）。
void wxkeep_runtime_test_set_arm64_layout(int arm64);
// 透传契约端到端缝（77 续⑨，仅 arm64 宿主）：MAP_JIT 哨兵函数（8 整型
// 寄存器参 + 1 栈参 + 2 FP 参）经生产蹦床/stub 公共路径挂钩后调用，参数
// 逐位穿透返回 1；失配 0；装挂失败 -1；非 arm64 宿主 -2；哨兵自检失败
// -3；hook 链未到达 -4。锁死「hook 链清参数寄存器」（x6 草稿/FP 参被
// memcpy 清/sp 未复原）——T4 渲染破坏机制的回归防线。
long wxkeep_runtime_test_hook_transparency(void);
// 透传缝的排障出口：diff = 挂钩调用结果 ⊕ 期望的指纹（按位指认被破坏
// 的参数槽）；got = 挂钩调用原样返回值。
long wxkeep_runtime_test_transparency_diff(void);
long wxkeep_runtime_test_transparency_got(void);
// 转储哨兵逐槽出口（调试用）：idx 0..7=x0..x7，8=[sp] 栈参，9=d0，10=d1，
// 11=x30，12=sp；hooked=1 挂钩调用 / 0 基线调用。
long wxkeep_runtime_test_transparency_slot(int idx, int hooked);
// 线程静默写窗诊断（77 续⑩）：上次安装静默的线程数（-1 = task_threads
// 枚举失败，退化为无静默直写）。
int wxkeep_runtime_test_quiesce_count(void);
// SLOT 链回归缝（97 轮，仅 arm64 宿主）：把 T6 生产链路（entry patch
// 形态 + try_slot_fill 生产实参 + 发布序）原样架在哨兵函数上端到端走
// 一遍。返回 1=链路通（hook 逻辑到达且透传逐位）；0=返回值失配；
// -1=蹦床/武装失败；-2=非 arm64 宿主；-3=哨兵自检失败；-4=hook 逻辑
// 未到达（96 轮 fires=0 故障形态：SLOT 指了蹦床本体）；-5/-6=建设失败。
// 锁死「SLOT 语义 = naked thunk」——回退成蹦床即刻红。
long wxkeep_runtime_test_slot_chain(void);

#endif
// 自发撤回判别缝（77 续㉘）：1=keep/zero 门放行（非自发 XML）；0=自发
// （「你撤回」命中——原生删除+原生提示，零干预）。T5 F1 修复的判别器锁。
int wxkeep_runtime_test_keep_gate(const unsigned char *xml, unsigned long len);
// 热重载缝（77 续㉘）：按生产热重载应用面（仅策略键，hooks 不动）装载
// 指定路径配置。0=应用成功且 hooks 未动；1=hooks 被触碰（契约破坏）；
// -1=文件不可解析。
int wxkeep_runtime_test_reload_config(const char *path);
// 当前外部 hooks 表行数（热重载契约断言用）。
int wxkeep_runtime_test_ext_hooks_count(void);
// V3-M2 克隆缝：newmsgid 提取（只读孪生）。1=提取到非零值；0=无 tag/全零。
int wxkeep_runtime_test_extract_newmsgid(const unsigned char *data, unsigned long len,
                                         unsigned long long *out);
// V3-M2 克隆缝：捕获入口端到端驱动（提取→深拷贝→派发；快照派发前落盘，
// 返回即可读）。1=捕获成功；0=无 newmsgid（skips 计）。
int wxkeep_runtime_test_clone_capture(const unsigned char *data, unsigned long len,
                                      unsigned long long *msgid,
                                      char *from, unsigned long fromcap);
// V3-M2 克隆缝：证据计数读回（captures/skips/nomethods；任一出口可 NULL）。
void wxkeep_runtime_test_clone_counts(int *captures, int *skips, int *nomethods);
// V3-M2-R4 写点捕获缝：合成向量（候选 B 形态）直接驱动 clone_hook_body，
// 返回捕获对象数。content_bytes = 合成 content 字节数（≤1MB）。
int wxkeep_runtime_test_clone_rows(unsigned long long content_bytes,
                                   int *rows, int *skips, int *objcaps);
