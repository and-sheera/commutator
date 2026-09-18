// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VPNRouter",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "VPNRouterCore", targets: ["VPNRouterCore"]),
        .executable(name: "VPNRouterApp", targets: ["VPNRouterApp"]),
        .executable(name: "VPNRouterDaemon", targets: ["VPNRouterDaemon"]),
    ],
    targets: [
        .target(name: "VPNRouterCore"),
        .executableTarget(name: "VPNRouterApp", dependencies: ["VPNRouterCore"]),
        .executableTarget(name: "VPNRouterDaemon", dependencies: ["VPNRouterCore"]),
        .testTarget(name: "VPNRouterCoreTests", dependencies: ["VPNRouterCore", "VPNRouterDaemon"]),
    ]
)
