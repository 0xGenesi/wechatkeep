// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WeChatKeepGUI",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "WeChatKeepGUI", path: "Sources/WeChatKeepGUI")
    ]
)
