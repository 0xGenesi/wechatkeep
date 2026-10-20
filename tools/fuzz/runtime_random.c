// runtime_random.c — L3⑤ 随机模糊驱动（无 libFuzzer 环境的等价实现）。
// CLT 不带 libclang_rt.fuzzer_osx.a 且无 Xcode——coverage-guided 引擎不可
// 达，本驱动以 SplitMix64 确定性 PRNG + 变异策略（字节翻转/块拼接/截断/
// corpus 种子重组）复现同一 harness 面（hooks JSON / XML 改写 / newmsgid
// 清零 / 伪 Mach-O UUID 头），在 ASan+UBSan 下跑 N 次输入。种子固定 →
// 崩溃可复现；退出码非零 = sanitizer 报告（ASan 默认 abort）。
//
// 用法: ./runtime_random <corpus-dir> [iterations]
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "wxkeep_runtime.h"

static uint64_t g_state = 0x776B656570323036ULL;   // "wkeep2026"
static uint64_t rng(void) {
    g_state += 0x9E3779B97F4A7C15;
    uint64_t z = g_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

static uint8_t *g_seeds[256];
static size_t g_seed_lens[256];
static int g_seed_count;

static void load_corpus(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    char path[4096];
    while ((de = readdir(d)) != NULL && g_seed_count < 256) {
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (n < 0 || n > (1 << 20)) { fclose(f); continue; }
        uint8_t *buf = malloc((size_t)n + 1);
        if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); continue; }
        fclose(f);
        g_seeds[g_seed_count] = buf;
        g_seed_lens[g_seed_count] = (size_t)n;
        g_seed_count++;
    }
    closedir(d);
}

static uint8_t *gen_input(size_t *out_len) {
    size_t len;
    uint8_t *buf;
    if (g_seed_count > 0 && (rng() & 3) != 0) {
        // 3/4 概率：corpus 种子变异（翻 1-8 字节 + 偶发截断/扩展）
        int idx = (int)(rng() % (uint64_t)g_seed_count);
        len = g_seed_lens[idx];
        buf = malloc(len + 512 + 64);   // 截断/扩展/拼接三变异的上限
        memcpy(buf, g_seeds[idx], len);
        int flips = 1 + (int)(rng() % 8);
        for (int i = 0; i < flips && len > 0; i++) {
            buf[rng() % len] = (uint8_t)rng();
        }
        switch (rng() % 4) {
        case 0: if (len > 1) len = 1 + rng() % len; break;             // 截断
        case 1: for (size_t i = 0; i < 32; i++) buf[len + i] = (uint8_t)rng(); len += 32; break;
        case 2: if (g_seed_count > 1) {                                 // 拼接
                    int j = (int)(rng() % (uint64_t)g_seed_count);
                    size_t take = g_seed_lens[j] > 512 ? 512 : g_seed_lens[j];
                    memcpy(buf + len, g_seeds[j], take);
                    len += take;
                } break;
        default: break;
        }
    } else {
        // 1/4：纯随机（长度偏小——解析缺陷多在小输入）
        len = 1 + rng() % 4096;
        buf = malloc(len);
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rng();
        if ((rng() & 7) == 0) {   // 偶发植 magic
            memcpy(buf, "\xCF\xFA\xED\xFE", len >= 4 ? 4 : len);
        }
    }
    *out_len = len;
    return buf;
}

static uint64_t g_iters;

// 与 runtime_fuzz.c 的 LLVMFuzzerTestOneInput 同一面集
static void one_input(const uint8_t *data, size_t size) {
    g_iters++;
    if (size < (1u << 20)) {
        char *s = malloc(size + 1);
        memcpy(s, data, size);
        s[size] = 0;
        (void)wxkeep_runtime_test_parse_hooks(s, (unsigned long)size);
        free(s);
    }
    if (size > 0) {
        uint8_t *buf = malloc(size);
        memcpy(buf, data, size);
        (void)wxkeep_runtime_test_zero(buf, (unsigned long)size);
        static const char tip[] = "\"{from}\" \xe6\x92\xa4\xe5\x9b\x9e";
        (void)wxkeep_runtime_test_rewrite(buf, (unsigned long)size,
                                          tip, sizeof(tip) - 1);
        free(buf);
    }
    if (size >= 8) {
        (void)wxkeep_runtime_test_uuid_match(data, (unsigned long)size);
    }
}

int main(int argc, char **argv) {
    const char *corpus = argc > 1 ? argv[1] : "tools/fuzz/corpus";
    long target = argc > 2 ? atol(argv[2]) : 200000;
    load_corpus(corpus);
    fprintf(stderr, "corpus 种子 %d 个；目标 %ld 次输入（种子 %llx 可复现）\n",
            g_seed_count, target, (unsigned long long)0x776B656570323036ULL);
    for (long i = 0; i < target; i++) {
        size_t len;
        uint8_t *buf = gen_input(&len);
        one_input(buf, len);
        free(buf);
    }
    printf("runtime_random: %llu 次输入完成，无 sanitizer 报告\n",
           (unsigned long long)g_iters);
    return 0;
}
