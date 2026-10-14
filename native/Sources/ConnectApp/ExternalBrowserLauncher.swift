import Foundation

@MainActor enum ExternalBrowserLauncher {
    static func arguments(for url: URL) throws -> [String] {
        guard ResourceBrowser.safe(url), !url.absoluteString.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw VPNError("资源地址无效。") }
        return [url.absoluteString]
    }
    static func open(_ url: URL) async throws {
        let args = try arguments(for: url)
        try Task.checkCancellation()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = args
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        let deadline = Date().addingTimeInterval(10)
        while process.isRunning && Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        try Task.checkCancellation()
        guard !process.isRunning, process.terminationStatus == 0 else { throw VPNError("无法打开系统浏览器，请复制网址后手动访问。") }
    }
}
