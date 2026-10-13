import Foundation
import CryptoKit
import Darwin

func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
func appleQuote(_ value: String) -> String { "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r") + "\"" }
func helperInstallScript(source: String, hash: String, socket: String, uid: uid_t) throws -> String {
    guard hash.count == 64, hash.allSatisfy({ $0.isHexDigit }), uid > 0, socket.range(of: "^/var/run/mchip-vpn/\(uid)-[a-f0-9]{32}\\.sock$", options: .regularExpression) != nil else { throw VPNError("VPN 安装参数无效。") }
    let destination = "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-helper"
    return """
    set -eu
    parent='/Library/PrivilegedHelperTools'
    [ ! -L "$parent" ] || exit 70
    if [ ! -e "$parent" ]; then /usr/bin/install -d -o root -g wheel -m 0755 "$parent"; fi
    [ -d "$parent" ] && [ "$(/usr/bin/stat -f %u "$parent")" = 0 ] || exit 70
    perm=$(/usr/bin/stat -f %Lp "$parent")
    [ $((0$perm & 0022)) = 0 ] || exit 70
    [ ! -L \(shellQuote(destination)) ] || exit 70
    tmp=$(/usr/bin/mktemp "$parent/.mchip-vpn.XXXXXX")
    trap '/bin/rm -f "$tmp"' EXIT HUP INT TERM
    /bin/cp -X \(shellQuote(source)) "$tmp"
    /usr/sbin/chown root:wheel "$tmp"
    /bin/chmod 0755 "$tmp"
    actual=$(/usr/bin/shasum -a 256 "$tmp")
    [ "${actual%% *}" = \(shellQuote(hash)) ] || exit 71
    /usr/bin/codesign --verify --strict "$tmp" >/dev/null 2>&1
    /bin/mv -f "$tmp" \(shellQuote(destination))
    trap - EXIT HUP INT TERM
    exec \(shellQuote(destination)) --tun-control \(shellQuote(socket)) --owner-uid \(uid) </dev/null >/dev/null 2>&1
    """
}
func connectSocket(_ path: String, uid: uid_t) throws -> FileHandle? {
    var directory = stat(); var file = stat()
    guard lstat("/var/run/mchip-vpn", &directory) == 0, lstat(path, &file) == 0 else { if errno == ENOENT { return nil }; throw VPNError("无法检查 VPN 控制接口。") }
    guard directory.st_mode & S_IFMT == S_IFDIR, directory.st_uid == 0, directory.st_mode & 0o022 == 0, file.st_mode & S_IFMT == S_IFSOCK, file.st_uid == uid, file.st_mode & 0o777 == 0o600 else { throw VPNError("VPN 控制接口权限无效。") }
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { throw VPNError("无法创建 VPN 控制连接。") }
    var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8) + [0]
    guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { Darwin.close(fd); throw VPNError("VPN 控制路径过长。") }
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in buffer.copyBytes(from: bytes) }
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let result = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    guard result == 0 else { let reason = errno; Darwin.close(fd); if reason == ECONNREFUSED || reason == ENOENT { return nil }; throw VPNError("无法连接 VPN 控制接口。") }
    var peerUID: uid_t = 0, peerGID: gid_t = 0
    guard getpeereid(fd, &peerUID, &peerGID) == 0, peerUID == 0 else { Darwin.close(fd); throw VPNError("后台服务身份验证失败。") }
    var noSignal: Int32 = 1; _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
}
// FileHandle.read(upToCount:) can wait to fill its buffer on an open stream.
// One read(2) returns the bytes currently available, including short JSON events.
func readHelperChunk(_ handle: FileHandle) throws -> Data? {
    var bytes = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = Darwin.read(handle.fileDescriptor, &bytes, bytes.count)
        if count > 0 { return Data(bytes.prefix(count)) }
        if count == 0 { return nil }
        if errno == EINTR { continue }
        throw VPNError("VPN 控制接口读取失败。")
    }
}
@MainActor final class VPNController {
    private(set) var state = "disconnected"
    private(set) var mode = "tun"
    private(set) var detail = "未连接"
    var onChange: (() -> Void)?
    private var socket: FileHandle?
    private var writer: FileHandle?
    private var process: Process?
    private var reader: Task<Void, Never>?
    private var stopped = false
    private var cleanupFailed = false
    private var failureMessage: String?
    private var activeID = UUID()
    private func publish(_ state: String, _ detail: String) { self.state = state; self.detail = detail; onChange?() }
    func start(host: String, port: Int, sessionID: String, mode: String, socksPort: Int, httpPort: Int) async throws {
        guard state == "disconnected", (1...65535).contains(port), ["tun", "proxy"].contains(mode), !sessionID.isEmpty, sessionID.count <= 4096, !sessionID.contains("\n"), !sessionID.contains("\r"), !sessionID.contains("\0") else { throw VPNError("VPN 连接参数无效或已有连接。") }
        guard let resources = Bundle.main.resourceURL else { throw VPNError("应用缺少 VPN 组件。") }
        let helper = resources.appendingPathComponent("bin/mchip-vpn-helper")
        let data = try Data(contentsOf: helper); let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let expected = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-helper.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard hash == expected else { throw VPNError("VPN 组件校验失败。") }
        self.mode = mode; stopped = false; cleanupFailed = false; failureMessage = nil; let id = UUID(); activeID = id
        publish("connecting", mode == "tun" ? "等待管理员授权…" : "正在连接…")
        let host = host.hasPrefix("[") ? String(host.dropFirst().dropLast()) : host
        var config: [String: Any] = ["server": "\(host.contains(":") ? "[\(host)]" : host):\(port)", "sessionId": sessionID, "mode": mode]
        if mode == "proxy" { guard (1024...65535).contains(socksPort), (1024...65535).contains(httpPort), socksPort != httpPort else { publish("disconnected", "代理端口无效"); throw VPNError("代理端口必须不同且为 1024 至 65535。") }; config["socksPort"] = socksPort; config["httpPort"] = httpPort }
        do {
            if mode == "tun" {
                let uid = getuid(); let path = "/var/run/mchip-vpn/\(uid)-service.sock"
                let broker = resources.appendingPathComponent("bin/mchip-vpn-broker")
                let brokerHash = SHA256.hash(data: try Data(contentsOf: broker)).map { String(format: "%02x", $0) }.joined()
                let brokerExpected = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-broker.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard brokerHash == brokerExpected else { throw VPNError("后台服务组件校验失败。") }
                let identity = try clientCodeHash()
                if !serviceInstalled(uid: uid, client: identity, helper: hash, broker: brokerHash) {
                    let script = try serviceInstallScript(helper: helper.path, helperHash: hash, broker: broker.path, brokerHash: brokerHash, clientHash: identity, uid: uid)
                    let authorization = Process(); authorization.executableURL = URL(fileURLWithPath: "/usr/bin/osascript"); authorization.arguments = ["-e", "do shell script \(appleQuote(script)) with administrator privileges"]
                    authorization.standardOutput = FileHandle.nullDevice; authorization.standardError = FileHandle.nullDevice
                    try authorization.run(); process = authorization
                } else { publish("connecting", "正在复用已授权的后台服务…") }
                let deadline = Date().addingTimeInterval(180)
                if let installer = process {
                    while installer.isRunning && Date() < deadline { try Task.checkCancellation(); try await Task.sleep(nanoseconds: 100_000_000) }
                    guard !installer.isRunning, installer.terminationStatus == 0 else { throw VPNError("管理员授权或后台服务安装失败。") }
                }
                while socket == nil && Date() < deadline {
                    guard activeID == id, state == "connecting", !Task.isCancelled else { throw CancellationError() }
                    if let handle = try connectSocket(path, uid: uid) { socket = handle; writer = handle; break }
                    if let process, !process.isRunning, process.terminationStatus != 0 { throw VPNError("管理员授权或后台服务安装失败。") }
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                guard socket != nil else { throw VPNError("管理员授权或控制接口等待超时，请重试。") }
                publish("connecting", "管理员授权已完成，正在建立 VPN 隧道…")
            } else {
                let child = Process(); child.executableURL = helper
                let input = Pipe(), output = Pipe(); child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
                try child.run(); process = child; socket = output.fileHandleForReading; writer = input.fileHandleForWriting
            }
            guard let input = writer, let output = socket else { throw VPNError("VPN 控制接口不可用。") }
            try input.write(contentsOf: JSONSerialization.data(withJSONObject: config) + Data([10])); config["sessionId"] = ""
            if mode == "proxy" { try input.close(); writer = nil }
            reader = Task.detached { [weak self] in
                var buffer = Data()
                do {
                    while let chunk = try readHelperChunk(output), !chunk.isEmpty {
                        buffer.append(chunk); guard buffer.count <= 16384 else { throw VPNError("VPN 状态响应无效。") }
                        while let end = buffer.firstIndex(of: 10) {
                            let line = Data(buffer[..<end]); buffer.removeSubrange(...end)
                            if !line.isEmpty { await self?.receive(line, id: id) }
                        }
                    }
                } catch { await self?.readFailed(id: id) }
                await self?.ended(id: id)
            }
            let deadline = Date().addingTimeInterval(mode == "tun" ? 180 : 60)
            while state == "connecting" && Date() < deadline { guard !Task.isCancelled else { throw CancellationError() }; try await Task.sleep(nanoseconds: 100_000_000) }
            guard state == "connected" else { let message = detail; try? await stop(); throw VPNError(message == "正在连接…" ? "VPN 连接超时。" : message) }
        } catch { if activeID == id { try? await stop() }; throw error }
    }
    private func receive(_ data: Data, id: UUID) {
        guard activeID == id, let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let name = event["event"] as? String else { return }
        if name == "stopped" { stopped = true; return }
        if name == "error" { let code = event["code"] as? String ?? "TUNNEL_FAILED"; failureMessage = Self.message(code); cleanupFailed = cleanupFailed || code == "CLEANUP_FAILED"; publish(state == "stopping" ? "stopping" : "error", Self.message(code)); return }
        if state == "stopping" { return }
        if name == "stage" { publish("connecting", "正在建立 VPN 隧道…") }
        else if name == "ready" && state == "connecting" {
            if mode == "tun" { guard event["mode"] as? String == "tun", (event["interface"] as? String)?.range(of: "^utun[0-9]+$", options: .regularExpression) != nil, (event["routeCount"] as? Int ?? 0) > 0 else { publish("error", "VPN TUN 状态无效。"); return } }
            publish("connected", "已连接 · \(event["ip"] as? String ?? "")\(mode == "tun" ? " · 内网分流" : " · 本地代理")")
        }
    }
    private func readFailed(id: UUID) { guard activeID == id else { return }; if state != "stopping" { publish("error", "VPN 控制连接中断。") } }
    private func ended(id: UUID) {
        guard activeID == id else { return }
        if mode == "tun" && !stopped { cleanupFailed = true }
        if state != "stopping" { publish("disconnected", failureMessage ?? (cleanupFailed ? "VPN 后台控制连接中断；请检查网络配置后重试。" : "VPN 连接已结束。")) }
    }
    func stop() async throws {
        guard socket != nil || process != nil else { if state != "disconnected" { publish("disconnected", "未连接") }; return }
        let id = activeID; publish("stopping", "正在恢复网络配置…")
        if mode == "tun", let writer { try? writer.write(contentsOf: Data("{\"event\":\"stop\"}\n".utf8)) }
        else if let process, process.isRunning { process.terminate() }
        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if mode == "tun" ? stopped || socket == nil : process?.isRunning != true { break }
            // Before any configuration was sent, terminating authorization is sufficient.
            if socket == nil { if process?.isRunning == true { process?.terminate() }; break }
            // Network cleanup must still yield when its caller was cancelled.
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { continuation.resume() } }
        }
        if mode == "tun", socket != nil, !stopped { cleanupFailed = true }
        if let handle = socket { _ = Darwin.shutdown(handle.fileDescriptor, SHUT_RDWR); try? handle.close() }
        if writer !== socket { try? writer?.close() }
        socket = nil; writer = nil; process = nil; reader?.cancel(); reader = nil
        if activeID == id { activeID = UUID(); publish("disconnected", cleanupFailed ? Self.message("CLEANUP_FAILED") : "未连接") }
        if cleanupFailed { throw VPNError(Self.message("CLEANUP_FAILED")) }
    }
    static func message(_ code: String) -> String {
        let messages = ["TUN_BUSY": "已有 VPN 隧道在运行，请先断开旧客户端。", "CONFIG_FAILED": "无法获取 VPN 资源配置。", "RESOURCE_FETCH_FAILED": "网关未返回资源列表。", "DNS_ROUTING_UNAVAILABLE": "网关未提供可用内网路由或 DNS。", "DNS_DOMAIN_LIMIT": "网关分流域名数量超过限制。", "AUTH_FAILED": "隧道认证失败，请重新登录。", "TLS_CERT_INVALID": "网关证书验证失败。", "CLEANUP_FAILED": "未能确认网络配置恢复，请检查系统路由和 DNS 后再连接。", "ROUTE_FAILED": "内网路由配置失败。", "DNS_CONFLICT": "内网 DNS 配置冲突。", "PERMISSION_DENIED": "管理员授权未完成。", "TUN_UNAVAILABLE": "无法启动系统 TUN。", "CONNECT_FAILED": "无法连接 VPN 隧道，请检查端口。"]
        return messages[code] ?? "VPN 连接失败（\(code)）。"
    }
}
