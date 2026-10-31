// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "wxkeep",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "wxkeep_runtime", type: .dynamic, targets: ["WxkeepRuntime"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "wxkeep",
            dependencies: [.product(name: "ArgumentParser", package: "swift-argument-parser")]
        ),
        // 能力探针（93 轮）：微型可执行件，实测本机 OS 策略是否允许进程内
        // 写化签名代码页（mprotect 直写 / vm_remap COW / MAP_JIT 写相）。
        // `wxkeep runtime probe` 以微信同款 entitlements 重签后运行——
        // install 前 go/no-go 门（T4/T5 教训：机制工程前先做机制探针）。
        .executableTarget(name: "wxprobe"),
        // 运行时注入组件（可选功能）：dynamic library 产物，
        // `wxkeep runtime install` 拷入微信 bundle 并注入 LC_LOAD_DYLIB。
        .target(name: "WxkeepRuntime"),
        .testTarget(name: "wxkeepTests", dependencies: ["wxkeep", "WxkeepRuntime"]),
    ]
)
