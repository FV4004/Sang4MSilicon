// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ConnectApp", platforms: [.macOS(.v13)], products: [.executable(name: "ConnectApp", targets: ["ConnectApp"]), .executable(name: "ConnectBroker", targets: ["ConnectBroker"])], targets: [.executableTarget(name: "ConnectApp"), .executableTarget(name: "ConnectBroker"), .testTarget(name: "ConnectAppTests", dependencies: ["ConnectApp"])])
