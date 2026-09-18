#ifndef WXKEEP_RUNTIME_H
#define WXKEEP_RUNTIME_H

// ---- 测试缝（仅单测使用；运行时走 runtime.json 配置）----
// 把 data 构造成长串 SSO（内容须为含 <replacemsg>…</replacemsg> 的 XML），
// 执行一次 hook 改写逻辑并把结果留在 data 内，返回内文长度；-1 = 未命中/放弃。
// tip 内可含 {from} 占位符（以原内文首对引号内的昵称展开）。
long wxkeep_runtime_test_rewrite(unsigned char *data, unsigned long data_len,
                                 const char *tip, unsigned long tip_len);
// 对伪 mach_header_64（32B 头 + LC_UUID）执行 270099 身份判定；1 = 匹配。
int wxkeep_runtime_test_uuid_match(const void *hdr);
// 切换自发撤回门（“你撤回…”内文是否也改写；默认 0=不改写）。
void wxkeep_runtime_test_set_policy(int rewrite_self);
// 解析 runtime.json 形态的 JSON 字节装载外部 hooks 表（重置旧态），
// 返回被接受的行数（0 = 外部表不启用）；JSON 不可解析返回 -1。
int wxkeep_runtime_test_parse_hooks(const char *json, unsigned long json_len);
// 读取第 idx 行外部表条目的核心字段；越界返回 -1。
int wxkeep_runtime_test_hook_row(int idx, unsigned long *hook_off,
                                 unsigned long *msg_arg, unsigned long *xml_sso_off,
                                 int *is_arm64, int *expected_len);
#endif
// 按 plist 语义从任意路径加载配置并应用（生产同路径），返回接受的 hooks
// 行数（-1 = 文件不可解析）；应用前重置 tip/策略/hooks。
int wxkeep_runtime_test_load_config_file(const char *path);
// 当前生效文案的字节长度。
int wxkeep_runtime_test_tip_len(void);
