// wxkeep Verifier spike — mini-loader route (no dyld, no initializers).
//
// Maps the whole thin x86_64 slice into an anonymous RWX region exploiting
// this image's "VA == file offset" layout, then redirects the GOT slots used
// by the two PLT stubs the target function calls (strlen / memcmp) to native
// harness implementations, and invokes the patch point directly.
//
// Usage: verifier_mini <dylib> <target-VA-hex> <stub1-VA-hex> <stub2-VA-hex>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// The argument is WeChat's own SSO string layout, NOT std::string:
//   short: byte0 = size<<1 (LSB=0), inline data at +1
//   long:  byte0 LSB=1, size at +8, data pointer at +0x10
struct WxString { uint8_t b[24]; };
typedef bool (*IsRevokeFn)(WxString *);

static WxString wxstr(const char *c) {
    WxString s{};
    size_t n = strlen(c);
    if (n < 23) {
        s.b[0] = (uint8_t)(n << 1);
        memcpy(s.b + 1, c, n);
    } else {
        s.b[0] = 1;
        static char keep[64];
        strncpy(keep, c, 63);
        *(uint64_t *)(s.b + 8) = n;
        *(const char **)(s.b + 0x10) = keep;
    }
    return s;
}

static size_t my_strlen(const char *s) { return strlen(s); }
static int my_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dylib> <VA> [stubVAs...]\n", argv[0]); return 2; }
    const uint64_t targetVA = strtoull(argv[2], nullptr, 16);

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 3; }
    struct stat st;
    fstat(fd, &st);
    const size_t size = (size_t)st.st_size;

    uint8_t *base = (uint8_t *)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 4; }
    if (read(fd, base, size) != (ssize_t)size) { perror("read"); return 5; }
    close(fd);
    printf("[+] mapped %zu bytes at %p (slide == base, VA == file offset)\n", size, base);

    // Redirect GOT slots for any provided stub VAs (ff 25 <rel32> → jmp [rip+disp]).
    // Slot VA = stubVA + 6 + disp. argv: stub1=strlen-ish, stub2=memcmp-ish.
    if (argc > 3) {
        uintptr_t strlenSlot, slotVA = 0;
        uint64_t stub1 = strtoull(argv[3], nullptr, 16);
        const uint8_t *s1 = base + stub1;
        if (s1[0] == 0xFF && s1[1] == 0x25) {
            int32_t disp;
            memcpy(&disp, s1 + 2, 4);
            strlenSlot = stub1 + 6 + disp;
            *(uintptr_t *)(base + strlenSlot) = (uintptr_t)&my_strlen;
            printf("[+] stub 0x%llx → GOT 0x%llx → harness strlen\n",
                   (unsigned long long)stub1, (unsigned long long)strlenSlot);
        }
    }
    if (argc > 4) {
        uint64_t stub2 = strtoull(argv[4], nullptr, 16);
        const uint8_t *s2 = base + stub2;
        if (s2[0] == 0xFF && s2[1] == 0x25) {
            int32_t disp;
            memcpy(&disp, s2 + 2, 4);
            uintptr_t slot = stub2 + 6 + disp;
            *(uintptr_t *)(base + slot) = (uintptr_t)&my_memcmp;
            printf("[+] stub 0x%llx → GOT 0x%llx → harness memcmp\n",
                   (unsigned long long)stub2, (unsigned long long)slot);
        }
    }

    // Magic-static lazy-init state: in a real process the guard flag and the
    // SSO buffer start zeroed (dyld/initializers own that); the raw file bytes
    // here are not the runtime state. Zero them so the function runs its own
    // initialization path — a verifier-owned "state prep" step.
    memset(base + 0xA988320, 0, 16);
    printf("[+] state prep: zeroed magic-static region 0xA988320..0xA98832F\n");

    IsRevokeFn isRevoke = (IsRevokeFn)(base + targetVA);
    const char *probes[] = {"revokemsg", "sysmsg", "NewMsg", ""};
    for (const char *p : probes) {
        WxString s = wxstr(p);
        bool r = isRevoke(&s);
        printf("    isRevokemsg(\"%s\") = %d\n", p, r);
    }
    printf("[+] done, no crash\n");
    return 0;
}
