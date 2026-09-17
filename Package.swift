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
        // 运行时注入组件（可选功能）：dynamic library 产物，
        // `wxkeep runtime install` 拷入微信 bundle 并注入 LC_LOAD_DYLIB。
        .target(name: "WxkeepRuntime"),
        .testTarget(name: "wxkeepTests", dependencies: ["wxkeep"]),
    ]
)
