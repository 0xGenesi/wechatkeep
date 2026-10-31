// wxprobe — 进程内签名代码页写化能力探针（93 轮）。
//
// 背景：macOS 27 起策略级拒绝进程内写化签名文件页（frida#3752 定根因
// CS_LIBRARY_VALIDATION；T4/T5 实测四层阶梯全灭）。本探针以最小代价在
// 「与微信同签名类」（ad-hoc + 同款 entitlements）的自身进程上实测三种
// 写化路径，输出逐项 errno/kern_return，供 `wxkeep runtime probe` 判定。
//
// 输出协议（每行一项，机器可解析）：
//   mprotect_direct=<errno>    对自身 __TEXT 页 mprotect(RW|X)
//   remap_cow=<kern_return>    对自身 __TEXT 页 vm_remap COW 自映射
//   jit_write=<0|errno>        MAP_JIT 区写相写入（诊断面——runtime 阶梯
//                              需要的是「既有页写化」，此路径成功不代表
//                              可武装，仅区分「新 JIT 区可建」）
//
// 注意：本件不依赖任何仓库代码；entitlements 由调用方（CLI）以微信提取
// 的同款重签施加——探针的 CS 策略面才与宿主微信同类。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <pthread.h>

__attribute__((noinline)) static int probe_target(void) { return 42; }

int main(void) {
    const vm_size_t page = 0x4000;   // arm64 macOS 16K 页
    const uintptr_t addr = (uintptr_t)&probe_target;
    const uintptr_t base = addr & ~(page - 1);
    mach_port_t task = mach_task_self();

    // 1) mprotect 直写路径（runtime.m 阶梯第 1 层语义）
    int m = mprotect((void *)base, page, PROT_READ | PROT_WRITE | PROT_EXEC);
    int mprotect_errno = (m == 0) ? 0 : errno;
    printf("mprotect_direct=%d\n", mprotect_errno);
    // 无条件回保护态（成功过的情形必须复原，避免带 RW 代码页继续运行）
    (void)mprotect((void *)base, page, PROT_READ | PROT_EXEC);

    // 2) vm_remap COW 自映射路径（runtime.m 阶梯第 2 层语义）
    vm_address_t remap_addr = 0;
    kern_return_t kr = vm_remap(task, &remap_addr, page, 0,
                                VM_FLAGS_ANYWHERE,
                                task, (vm_address_t)base, 0,
                                &(int){0},
                                VM_PROT_READ | VM_PROT_EXECUTE,
                                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    printf("remap_cow=%d\n", (kr == KERN_SUCCESS) ? 0 : (int)kr);
    if (kr == KERN_SUCCESS) {
        // COW 副本写测（真写一字节再释放——完整复刻「COW 后可写」语义）
        *(volatile unsigned int *)remap_addr = 0xD65F03C0u;   // arm64 ret
        vm_deallocate(task, remap_addr, page);
    }

    // 3) MAP_JIT 新区写相（诊断面：WeChat 持 allow-jit——区分
    //    「新 JIT 区可建可写」与「既有签名页可写化」，后者才是
    //    runtime 阶梯的必要条件）
#if defined(__arm64__) || defined(__aarch64__)
    void *jit = mmap(NULL, page, PROT_READ | PROT_WRITE,
                     MAP_JIT | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (jit == MAP_FAILED) {
        printf("jit_write=%d\n", errno);
    } else {
        pthread_jit_write_protect_np(0);
        *(volatile unsigned int *)jit = 0xD65F03C0u;   // arm64 ret
        pthread_jit_write_protect_np(1);
        printf("jit_write=0\n");
        munmap(jit, page);
    }
#else
    printf("jit_write=0\n");   // x64 无写相开关——RWX anon 区恒可写
#endif
    return 0;
}
