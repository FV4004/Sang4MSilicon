// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ConnectApp", platforms: [.macOS(.v13)], products: [.executable(name: "ConnectApp", targets: ["ConnectApp"])], targets: [.executableTarget(name: "ConnectApp"), .testTarget(name: "ConnectAppTests", dependencies: ["ConnectApp"])])
