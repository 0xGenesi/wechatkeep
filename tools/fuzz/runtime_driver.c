// runtime_driver.c — L3② 确定性驱动：以 ASan/UBSan 重编的 runtime.m 经
// 测试缝全量驱动（wxkeep_runtime_test_parse_hooks / load_config_file /
// rewrite / zero / uuid_match）。输入面 = 生产解析面的全部入口：
// runtime.json（plist）、hooks 行（JSON）、tip 文案、XML 缓冲、伪 Mach-O
// 头。合法 + 边界 + 畸形三类语料，每个缝都打到返回路径。
//
// 用法：./runtime_driver <corpus-dir>（corpus 内放 *.plist / *.json /
// *.xml / *.bin 样本；驱动逐个喂入）。无参数时跑内置语料。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "wxkeep_runtime.h"

static void feed_parse_hooks(const unsigned char *data, unsigned long len) {
    // parse_hooks 期望 NUL 结尾的 JSON 字节串
    char *s = malloc(len + 1);
    memcpy(s, data, len);
    s[len] = 0;
    int n = wxkeep_runtime_test_parse_hooks(s, len);
    (void)n;
    // 读回全部行（越界读缝也驱动一遍）
    unsigned long hook_off, marg, soff;
    int is_arm, elen;
    for (int i = 0; i < 160; i++) {
        if (wxkeep_runtime_test_hook_row(i, &hook_off, &marg, &soff,
                                         &is_arm, &elen) != 0) break;
    }
    free(s);
}

static void feed_zero(const unsigned char *data, unsigned long len) {
    unsigned char *buf = malloc(len ? len : 1);
    memcpy(buf, data, len ? len : 1);
    (void)wxkeep_runtime_test_zero(buf, len ? len : 1);
    free(buf);
}

static void feed_rewrite(const unsigned char *data, unsigned long len) {
    unsigned char *buf = malloc(len ? len : 1);
    memcpy(buf, data, len);
    static const char tips[] = "\"x\" 撤回了一条消息";
    (void)wxkeep_runtime_test_rewrite(buf, len, tips, sizeof(tips) - 1);
    // {from} 占位符形态
    static const char tips2[] = "\"{from}\" 撤回了一条消息";
    (void)wxkeep_runtime_test_rewrite(buf, len, tips2, sizeof(tips2) - 1);
    free(buf);
}

static void feed_uuid(const unsigned char *data, unsigned long len) {
    if (len < 4) return;
    // 伪 mach_header：把字节当 sizeofcmds/加载命令区直接喂
    (void)wxkeep_runtime_test_uuid_match(data, (unsigned long)len);
}

static void feed_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n > 0 ? (size_t)n : 1);
    size_t got = fread(buf, 1, n > 0 ? (size_t)n : 1, f);
    fclose(f);
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strstr(base, ".plist")) {
        (void)wxkeep_runtime_test_load_config_file(path);
        (void)wxkeep_runtime_test_tip_len();
    } else if (strstr(base, ".json")) {
        feed_parse_hooks(buf, (unsigned long)got);
    } else if (strstr(base, ".xml")) {
        feed_rewrite(buf, (unsigned long)got);
        feed_zero(buf, (unsigned long)got);
    } else {
        feed_uuid(buf, (unsigned long)got);
        feed_zero(buf, (unsigned long)got);
    }
    free(buf);
}

// 内置语料：生产形制的合法样本 + 畸形变体（坏 hex/截断 UUID/超界字段/
// 非 dict 顶层/深嵌套/空输入/超长行）。
static const char *kBuiltins[] = {
    "{}",
    "[]",
    "null",
    "{\"hooks\":[]}",
    "{\"hooks\":null}",
    "{\"hooks\":\"x\"}",
    "{\"hooks\":[{}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"arch\":\"x86_64\",\"hook_off\":\"0x537db40\",\"msg_arg\":1,"
    "\"xml_sso_off\":0,\"expected\":\"554889E54157415641554154\",\"build\":\"270099\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b42\","
    "\"hook_off\":\"0x1\",\"expected\":\"55\"}]}",
    "{\"hooks\":[{\"uuid\":\"97E21436-ABDA-3B79-BEC0-EF2653C6B423\","
    "\"hook_off\":\"0x1\",\"expected\":\"55\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0\",\"expected\":\"55\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0xfffffffff\",\"expected\":\"55\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0x100\",\"expected\":\"5548\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0x100\",\"expected\":\"55Z8\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0x100\",\"expected\":\"555\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"arch\":\"arm64\",\"hook_off\":\"0x100\",\"xml_sso_off\":0,"
    "\"expected\":\"9000005158000094F65701A9F44F02A9\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"arch\":\"arm64\",\"hook_off\":\"0x100\",\"xml_sso_off\":0,"
    "\"expected\":\"F85FBCA9F65701A9F44F02A9FD7B03A9\"}]}",
    "{\"hooks\":[{\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"arch\":\"arm64\",\"hook_off\":\"0x100\",\"xml_sso_off\":0x2000,"
    "\"expected\":\"F85FBCA9F65701A9F44F02A9FD7B03A9\"}]}",
    "{\"hooks\":[{\"uuid\":1,\"hook_off\":\"0x1\",\"expected\":\"55\"}]}",
    "{\"hooks\":[{\"msg_arg\":99,\"uuid\":\"97e21436-abda-3b79-bec0-ef2653c6b423\","
    "\"hook_off\":\"0x100\",\"xml_sso_off\":0,\"expected\":\"554889E54157415641554154\"}]}",
    "{\"hooks\":[",
    "{\"hooks\":[{\"uuid\":\"",
    "\xff\xfe{bogus",
};

static const unsigned char kXmlBuiltin[] =
    "<?xml version=\"1.0\"?><sysmsg>"
    "<content>\"Jennifer\" \xe6\x92\xa4\xe5\x9b\x9e\xe4\xba\x86\xe4\xb8\x80"
    "\xe6\x9d\xa1\xe6\xb6\x88\xe6\x81\xaf</content>"
    "<newmsgid>123456789</newmsgid></sysmsg>";
static const unsigned char kXmlCdata[] =
    "<r><![CDATA[\"x\" \xe6\x92\xa4\xe5\x9b\x9e]]></r><newmsgid>42</newmsgid>";
static const unsigned char kXmlTruncOpen[] = "<content>";
static const unsigned char kXmlTruncClose[] = "<content>abc</conte";
static const unsigned char kXmlNoClose[] = "<content>abc";
static const unsigned char kXmlNeedleNoClose[] =
    "<content>\xe6\x92\xa4\xe5\x9b\x9e";
static const unsigned char kXmlSelf[] =
    "<content>\xe4\xbd\xa0\xe6\x92\xa4\xe5\x9b\x9e\xe4\xba\x86\xe4\xb8\x80"
    "\xe6\x9d\xa1\xe6\xb6\x88\xe6\x81\xaf</content>";

// 伪 Mach-O 头 + LC_UUID（32B 头 + 24B 命令）：大小端字段按 LE 直填。
static unsigned char mk_uuid_blob(unsigned int sizeofcmds, unsigned char fill) {
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0xCF; buf[1] = 0xFA; buf[2] = 0xED; buf[3] = 0xFE;   // MH_MAGIC_64
    memcpy(buf + 16, &sizeofcmds, 4);
    memcpy(buf + 32, "\x1b\x00\x00\x00\x18\x00\x00\x00", 8);      // LC_UUID, 24
    memset(buf + 40, fill, 16);
    feed_uuid(buf, sizeof(buf));
    return buf[40];
}

int main(int argc, char **argv) {
    // 内置语料：JSON 文本面
    for (size_t i = 0; i < sizeof(kBuiltins) / sizeof(kBuiltins[0]); i++) {
        feed_parse_hooks((const unsigned char *)kBuiltins[i],
                         (unsigned long)strlen(kBuiltins[i]));
    }
    // XML 面（rewrite + zero）
    feed_rewrite(kXmlBuiltin, sizeof(kXmlBuiltin) - 1);
    feed_zero(kXmlBuiltin, sizeof(kXmlBuiltin) - 1);
    feed_rewrite(kXmlCdata, sizeof(kXmlCdata) - 1);
    feed_rewrite(kXmlTruncOpen, sizeof(kXmlTruncOpen) - 1);
    feed_rewrite(kXmlTruncClose, sizeof(kXmlTruncClose) - 1);
    feed_rewrite(kXmlNoClose, sizeof(kXmlNoClose) - 1);
    feed_rewrite(kXmlNeedleNoClose, sizeof(kXmlNeedleNoClose) - 1);
    feed_rewrite(kXmlSelf, sizeof(kXmlSelf) - 1);
    feed_zero(kXmlNeedleNoClose, sizeof(kXmlNeedleNoClose) - 1);
    wxkeep_runtime_test_set_policy(1);
    feed_rewrite(kXmlSelf, sizeof(kXmlSelf) - 1);
    wxkeep_runtime_test_set_policy(0);
    // 空与极小输入
    feed_rewrite((const unsigned char *)"", 0);
    feed_zero((const unsigned char *)"", 0);
    feed_uuid((const unsigned char *)"", 0);
    // UUID 头面：合法 sizeofcmds / 非法 cmdsize（<8 触发停走）/ 病态尾部
    (void)mk_uuid_blob(24, 0x97);
    (void)mk_uuid_blob(0x40000, 0x97);
    { unsigned char b[64]; memset(b, 0, sizeof(b));
      memcpy(b, "\xCF\xFA\xED\xFE", 4);
      unsigned int sc = 12; memcpy(b + 16, &sc, 4);          // cmdsize=4 <8
      memcpy(b + 32, "\x1b\x00\x00\x00\x04\x00\x00\x00", 8);
      feed_uuid(b, sizeof(b)); }
    { unsigned char b[64]; memset(b, 0xFF, sizeof(b));       // 全 0xFF
      memcpy(b, "\xCF\xFA\xED\xFE", 4);
      unsigned int sc = 24; memcpy(b + 16, &sc, 4);
      feed_uuid(b, sizeof(b)); }
    // corpus 目录（若给出）：按扩展名分发
    for (int a = 1; a < argc; a++) {
        DIR *d = opendir(argv[a]);
        if (!d) { fprintf(stderr, "opendir %s 失败\n", argv[a]); return 2; }
        struct dirent *de;
        char path[4096];
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "%s/%s", argv[a], de->d_name);
            feed_file(path);
        }
        closedir(d);
    }
    printf("runtime_driver: 全部语料驱动完成，无 sanitizer 报告\n");
    return 0;
}
