#import <Foundation/Foundation.h>

// wxkeep 运行时组件（可选功能，M-R1：加载证明 + 标记文件）。
// 由 `wxkeep runtime install` 拷入微信 bundle 并注入 LC_LOAD_DYLIB；
// `runtime remove` 时随 bundle 删除。构造器在微信启动时执行一次。

static void write_marker(void) {
    @autoreleasepool {
        NSString *dir = @"~/Library/Application Support/wxkeep";
        dir = [dir stringByExpandingTildeInPath];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *marker = [dir stringByAppendingPathComponent:@"runtime.marker"];
        NSString *now = [NSString stringWithFormat:@"loaded ts=%f\n",
                         [NSDate date].timeIntervalSince1970];
        [now writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[wxkeep-runtime] loaded, marker at %@", marker);
    }
}

__attribute__((constructor)) static void wxkeep_runtime_init(void) {
    write_marker();
}
