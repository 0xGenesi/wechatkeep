// runtime_fuzz.c — L3⑤ libFuzzer harness：包住 runtime.m 的全部测试缝，
// 把任意字节流分发到四个解析面（hooks JSON / XML 改写 / newmsgid 清零 /
// 伪 Mach-O UUID 头）。sanitizer=fuzzer 编译后由 LLVMFuzzerRunDriver 驱动。
//
// 语料复用：tools/fuzz/corpus/ 下的样本同时供确定性驱动与 fuzzer。
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wxkeep_runtime.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 面 1：整段输入当 hooks JSON（NUL 终结副本——parse_hooks 读 C 串）
    if (size < (1u << 20)) {
        char *s = malloc(size + 1);
        memcpy(s, data, size);
        s[size] = 0;
        (void)wxkeep_runtime_test_parse_hooks(s, (unsigned long)size);
        free(s);
    }
    // 面 2/3：整段输入当 XML 缓冲（改写 + 清零，两者都在副本上——
    // 改写会变更缓冲内容，先跑只读的清零再跑改写避免自我影响）
    if (size > 0) {
        uint8_t *buf = malloc(size);
        memcpy(buf, data, size);
        (void)wxkeep_runtime_test_zero(buf, (unsigned long)size);
        static const char tip[] = "\"{from}\" \xe6\x92\xa4\xe5\x9b\x9e";
        (void)wxkeep_runtime_test_rewrite(buf, (unsigned long)size,
                                          tip, sizeof(tip) - 1);
        free(buf);
    }
    // 面 4：前 64B 当伪 mach_header（uuid_matches 只读 sizeofcmds +
    // 加载命令区，越界由 p+8<=end 门挡——harness 目的就是验证这门）
    if (size >= 8) {
        (void)wxkeep_runtime_test_uuid_match(data, (unsigned long)size);
    }
    return 0;
}
