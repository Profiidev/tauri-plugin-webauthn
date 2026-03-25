// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "WebauthnBridge",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "WebauthnBridge",
            type: .static,
            targets: ["WebauthnBridge"]),
    ],
    targets: [
        .target(
            name: "WebauthnBridge",
            dependencies: []
        )
    ]
)
