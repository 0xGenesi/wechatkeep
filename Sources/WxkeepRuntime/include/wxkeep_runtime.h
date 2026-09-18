#ifndef WXKEEP_RUNTIME_H
#define WXKEEP_RUNTIME_H
void wxkeep_runtime_marker(void);

// ---- 测试缝（仅单测使用；运行时走 runtime.json 配置）----
// 把 data 构造成长串 SSO（内容须为含 <replacemsg>…</replacemsg> 的 XML），
// 执行一次 hook 改写逻辑并把结果留在 data 内，返回内文长度；-1 = 未命中/放弃。
long wxkeep_runtime_test_rewrite(unsigned char *data, unsigned long data_len,
                                 const char *tip, unsigned long tip_len);
// 对伪 mach_header_64（32B 头 + LC_UUID）执行 270099 身份判定；1 = 匹配。
int wxkeep_runtime_test_uuid_match(const void *hdr);
#endif
