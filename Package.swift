// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "wxkeep",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "wxkeep",
            dependencies: [.product(name: "ArgumentParser", package: "swift-argument-parser")]
        ),
        .testTarget(name: "wxkeepTests", dependencies: ["wxkeep"]),
    ]
)
