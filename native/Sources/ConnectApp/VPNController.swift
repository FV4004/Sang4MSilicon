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
    guard lstat("/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control", &directory) == 0, lstat(path, &file) == 0 else { if errno == ENOENT { return nil }; throw VPNError("无法检查 VPN 控制接口。") }
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
func brokerHandshake(_ handle: FileHandle) async throws {
    let fd = handle.fileDescriptor
    var timeout = timeval(tv_sec: 10, tv_usec: 0)
    guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else { throw VPNError("无法设置后台服务等待时间。") }
    defer { var unlimited = timeval(tv_sec: 0, tv_usec: 0); _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &unlimited, socklen_t(MemoryLayout<timeval>.size)) }
    let data: Data?
    do {
        data = try await Task.detached { () throws -> Data? in
            var buffer = Data()
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                guard let chunk = try readHelperChunk(handle), !chunk.isEmpty else { return buffer.isEmpty ? nil : buffer }
                buffer.append(chunk)
                guard buffer.count < 4096 else { throw VPNError("后台服务握手响应过长。") }
                if buffer.contains(10) { return buffer }
            }
            throw VPNError("后台服务握手超时。")
        }.value
    }
    catch { throw VPNError("后台服务未完成连接握手，请点击修复后台服务后重试。") }
    guard let data, data.count < 4096, let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw VPNError("后台服务关闭了连接，尚未接纳请求。请点击修复后台服务。") }
    if event["code"] as? String == "SERVICE_IDENTITY_REJECTED" { throw VPNError("后台服务拒绝当前应用身份。请从新版应用点击修复后台服务，重新授权。") }
    guard event["event"] as? String == "service", event["code"] as? String == "SERVICE_READY" else { throw VPNError("后台服务版本不匹配，请点击修复后台服务。") }
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
    private var lastStage = "初始化"
    private var connectionDetail = "已连接 · 内网分流"
    private var recoveringChannels = Set<String>()
    private var forceServiceInstall = false
    private func publish(_ state: String, _ detail: String) { self.state = state; self.detail = detail; onChange?() }
    func start(host: String, port: Int, sessionID: String, mode: String, socksPort: Int, httpPort: Int) async throws {
        guard sessionID.utf8.count == 16 else { throw VPNError("登录会话格式无效，请退出登录后重新认证。") }
        guard ["tun", "proxy"].contains(mode) else { throw VPNError("VPN 连接模式无效。") }
        try await startSession(host: host, port: port, sessionID: sessionID, mode: mode, socksPort: socksPort, httpPort: httpPort)
    }
    func recoverNetwork() async throws {
        if state != "disconnected" || socket != nil || process != nil { try? await stop() }
        try await startSession(host: "127.0.0.1", port: 443, sessionID: "recovery", mode: "recover", socksPort: 0, httpPort: 0)
    }
    func repairService() async throws {
        forceServiceInstall = true
        defer { forceServiceInstall = false }
        try await recoverNetwork()
    }
    private func startSession(host: String, port: Int, sessionID: String, mode: String, socksPort: Int, httpPort: Int) async throws {
        guard state == "disconnected", (1...65535).contains(port), ["tun", "proxy", "recover"].contains(mode), !sessionID.isEmpty, sessionID.count <= 4096, !sessionID.contains("\n"), !sessionID.contains("\r"), !sessionID.contains("\0") else { throw VPNError("VPN 连接参数无效或已有连接。") }
        guard let resources = Bundle.main.resourceURL else { throw VPNError("应用缺少 VPN 组件。") }
        let helper = resources.appendingPathComponent("bin/mchip-vpn-helper")
        let data = try Data(contentsOf: helper); let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let expected = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-helper.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard hash == expected else { throw VPNError("VPN 组件校验失败。") }
        self.mode = mode; stopped = false; cleanupFailed = false; failureMessage = nil; lastStage = "初始化"; let id = UUID(); activeID = id
        publish("connecting", mode != "proxy" ? "等待管理员授权…" : "正在连接…")
        let host = host.hasPrefix("[") ? String(host.dropFirst().dropLast()) : host
        var config: [String: Any] = ["server": "\(host.contains(":") ? "[\(host)]" : host):\(port)", "sessionId": sessionID, "mode": mode]
        if mode == "recover" { config = ["mode": "recover"] }
        if mode == "proxy" { guard (1024...65535).contains(socksPort), (1024...65535).contains(httpPort), socksPort != httpPort else { publish("disconnected", "代理端口无效"); throw VPNError("代理端口必须不同且为 1024 至 65535。") }; config["socksPort"] = socksPort; config["httpPort"] = httpPort }
        do {
            if mode != "proxy" {
                let uid = getuid(); let path = "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control/\(uid)-service.sock"
                let broker = resources.appendingPathComponent("bin/mchip-vpn-broker")
                let brokerHash = SHA256.hash(data: try Data(contentsOf: broker)).map { String(format: "%02x", $0) }.joined()
                let brokerExpected = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-broker.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard brokerHash == brokerExpected else { throw VPNError("后台服务组件校验失败。") }
                let identity = try clientCodeHash()
                if forceServiceInstall || !serviceInstalled(uid: uid, client: identity, helper: hash, broker: brokerHash) {
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
                guard let control = socket else { throw VPNError("后台服务控制接口等待超时，请点击修复后台服务后重试。") }
                do { try await brokerHandshake(control) }
                catch {
                    _ = Darwin.shutdown(control.fileDescriptor, SHUT_RDWR); try? control.close()
                    socket = nil; writer = nil; process = nil; publish("disconnected", error.localizedDescription)
                    throw error
                }
                publish("connecting", mode == "recover" ? "正在恢复上次网络配置…" : "管理员授权已完成，正在建立 VPN 隧道…")
            } else {
                let child = Process(); child.executableURL = helper
                let input = Pipe(), output = Pipe(); child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
                try child.run(); process = child; socket = output.fileHandleForReading; writer = input.fileHandleForWriting
            }
            guard let input = writer, let output = socket else { throw VPNError("VPN 控制接口不可用。") }
            try input.write(contentsOf: JSONSerialization.data(withJSONObject: config) + Data([10])); config["sessionId"] = ""
            if mode == "proxy" { try input.close(); writer = nil }
            monitor(output, writer: input, mode: mode, id: id)
            let deadline = Date().addingTimeInterval(mode != "proxy" ? 180 : 60)
            while state == "connecting" && Date() < deadline { guard !Task.isCancelled else { throw CancellationError() }; try await Task.sleep(nanoseconds: 100_000_000) }
            if mode == "recover" {
                guard stopped && !cleanupFailed && failureMessage == nil else { throw VPNError(failureMessage ?? Self.message("CLEANUP_FAILED")) }
                // EOF releases the old control channel before another attempt.
                let completion = reader
                await completion?.value
                return
            }
            guard state == "connected" else { let message = detail; try? await stop(); throw VPNError(message == "正在连接…" ? "VPN 连接超时。" : message) }
        } catch { if activeID == id { try? await stop() }; throw error }
    }
    // Shared transport observer; EOF releases every retained session handle.
    func monitor(_ output: FileHandle, writer: FileHandle?, mode: String, id: UUID) {
        activeID = id; self.socket = output; self.writer = writer; self.mode = mode
        stopped = false; cleanupFailed = false; failureMessage = nil; recoveringChannels = []
        publish("connecting", detail)
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
    }
    private func receive(_ data: Data, id: UUID) {
        guard activeID == id, let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let name = event["event"] as? String else { return }
        if name == "retry" && state == "connected" { if let direction = event["direction"] as? String { recoveringChannels.insert(direction) }; publish("connected", "数据连接中断，正在重新建立隧道…"); return }
        if name == "resumed" && state == "connected" { if let direction = event["direction"] as? String { recoveringChannels.remove(direction) }; if recoveringChannels.isEmpty { publish("connected", connectionDetail) }; return }
        if name == "workerExit" {
            if !stopped && failureMessage == nil {
                let status = event["status"] as? Int ?? -1
                let reason = event["reason"] as? String == "signal" ? "信号" : "退出码"
                failureMessage = "VPN 工作进程异常结束（\(reason) \(status)，阶段：\(lastStage)。请恢复网络配置后重试。"
            }
            return
        }
        if name == "stopped" { stopped = true; if mode == "recover" && state != "stopping" { publish("disconnected", failureMessage ?? "网络配置已恢复，可以重新连接 VPN。") }; return }
        if name == "error" { let code = event["code"] as? String ?? "TUNNEL_FAILED"; failureMessage = Self.message(code) + Self.diagnosticSuffix(event["diagnostic"] as? String); cleanupFailed = cleanupFailed || code == "CLEANUP_FAILED"; publish(state == "stopping" ? "stopping" : "error", failureMessage ?? Self.message(code)); return }
        if state == "stopping" { return }
        if name == "stage" {
            let labels = ["token": "网关认证", "ip": "获取虚拟 IP", "tunnel": "建立数据隧道", "routes": "配置路由和 DNS"]
            lastStage = labels[event["stage"] as? String ?? ""] ?? "建立隧道"
            publish("connecting", "正在建立 VPN 隧道 · \(lastStage)…")
        }
        else if name == "ready" && state == "connecting" {
            if mode == "tun" { guard event["mode"] as? String == "tun", (event["interface"] as? String)?.range(of: "^utun[0-9]+$", options: .regularExpression) != nil, (event["routeCount"] as? Int ?? 0) > 0 else { publish("error", "VPN TUN 状态无效。"); return } }
            connectionDetail = "已连接 · \(event["ip"] as? String ?? "")\(mode == "tun" ? " · 内网分流" : " · 本地代理")"
            publish("connected", connectionDetail)
        }
    }
    private func readFailed(id: UUID) { guard activeID == id else { return }; if state != "stopping" { publish("error", "VPN 控制连接中断。") } }
    private func ended(id: UUID) {
        guard activeID == id else { return }
        if mode != "proxy" && !stopped { cleanupFailed = true }
        // EOF is terminal: never retain a closed socket for the next session.
        let wasStopping = state == "stopping"
        if writer !== socket { try? writer?.close() }
        try? socket?.close(); socket = nil; writer = nil
        if process?.isRunning == true { process?.terminate() }
        process = nil; reader = nil
        if !wasStopping { activeID = UUID() }
        if state != "stopping" { publish("disconnected", failureMessage ?? (mode == "recover" && stopped && !cleanupFailed ? "网络配置已恢复，可以重新连接 VPN。" : cleanupFailed ? "后台服务连接中断，未收到工作进程退出信息（阶段：\(lastStage)）。请点击修复后台服务后重试。" : "VPN 连接已结束。")) }
    }
    func stop() async throws {
        guard socket != nil || process != nil else { if state != "disconnected" { publish("disconnected", "未连接") }; return }
        let id = activeID; publish("stopping", "正在恢复网络配置…")
        if mode != "proxy", let writer { try? writer.write(contentsOf: Data("{\"event\":\"stop\"}\n".utf8)) }
        else if let process, process.isRunning { process.terminate() }
        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if mode != "proxy" ? stopped || socket == nil : process?.isRunning != true { break }
            // Before any configuration was sent, terminating authorization is sufficient.
            if socket == nil { if process?.isRunning == true { process?.terminate() }; break }
            // Network cleanup must still yield when its caller was cancelled.
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { continuation.resume() } }
        }
        if mode != "proxy", socket != nil, !stopped { cleanupFailed = true }
        if let handle = socket { _ = Darwin.shutdown(handle.fileDescriptor, SHUT_RDWR); try? handle.close() }
        if writer !== socket { try? writer?.close() }
        socket = nil; writer = nil; process = nil; reader?.cancel(); reader = nil
        if activeID == id { activeID = UUID(); publish("disconnected", cleanupFailed ? ((failureMessage ?? Self.message("CLEANUP_FAILED")) + " 未收到网络清理确认，请恢复网络配置。") : (failureMessage ?? "未连接")) }
        if cleanupFailed { throw VPNError(Self.message("CLEANUP_FAILED")) }
    }
    static func diagnosticSuffix(_ text: String?) -> String {
        guard let text, text.hasPrefix("D12 "), text.count <= 2048,
              text.range(of: "^[A-Za-z0-9_ =,@.]+$", options: .regularExpression) != nil else { return "" }
        return "\n通道诊断：" + text
    }
    static func message(_ code: String) -> String {
        // Experimental helpers append fixed first-I/O labels. Keep the original
        // human-readable action while exposing the full label for comparison.
        if code.count <= 256,
           code.range(of: "^LAB_[ABC]_[A-Z0-9_]+_FIRST_[A-Z0-9_]*$", options: .regularExpression) != nil,
           let separator = code.range(of: "_FIRST_") {
            let raw = String(code[code.index(code.startIndex, offsetBy: 6)..<separator.lowerBound])
            return message(raw) + " 实验诊断：" + code
        }
        let messages = ["TUN_SERVER_SHUTDOWN": "网关主动终止了数据会话（指令 0x08）。请重新登录；若仅访问特定资源触发，需要检查网关访问策略或协议兼容性。", "TUN_RECONNECT_LATER": "网关要求暂缓重连，有限重试后仍未接受连接。请稍后重试，无需立即重新登录。", "TUN_SESSION_EXPIRED": "网关未返回已认证的资源配置，当前登录会话可能已失效，请重新登录。", "TUN_FRAME_INVALID": "网关数据流不是有效 IPv4 数据帧，请反馈此提示以检查协议兼容性。", "TUN_REMOTE_CLOSED": "网关关闭了数据连接，请重新认证后连接。", "UNSUPPORTED_SESSION": "登录会话格式无效，请退出登录后重新认证。", "WORKER_START_FAILED": "后台服务无法启动 VPN 工作进程，请点击修复后台服务。", "WORKER_PANIC": "VPN 数据处理异常。请恢复网络配置后重试。", "STATE_DIRECTORY_UNSAFE": "VPN 恢复目录权限异常，需要检查目录所有者及权限。", "CONTROL_DIRECTORY_UNSAFE": "VPN 控制目录权限异常，请检查是否有旧版客户端残留。", "TUN_LOCK_FAILED": "无法获取 VPN 工作锁，请检查旧版客户端是否仍在运行。", "TUN_FAILD": "VPN 数据隧道失败，请恢复网络配置后重试。", "TUN_FAILED": "VPN 数据隧道失败，请恢复网络配置后重试。", "TUNNEL_FAILED": "VPN 数据隧道中断，请重试连接；如仍失败，请恢复网络配置。", "TUN_UNSUPPORTED": "网关仅支持 TCP 应用隧道，无法使用本版 TUN。", "TUN_BUSY": "已有 VPN 隧道在运行，请先断开旧客户端。", "CONFIG_FAILED": "无法获取 VPN 资源配置。", "RESOURCE_FETCH_FAILED": "网关未返回资源列表。", "DNS_ROUTING_UNAVAILABLE": "网关未提供可用内网路由或 DNS。", "DNS_DOMAIN_LIMIT": "网关分流域名数量超过限制。", "AUTH_FAILED": "隧道认证失败，请重新登录。", "TLS_CERT_INVALID": "网关证书验证失败。", "CLEANUP_FAILED": "未能确认网络配置恢复，请检查系统路由和 DNS 后再连接。", "ROUTE_FAILED": "内网路由配置失败。", "DNS_CONFLICT": "内网 DNS 配置冲突。", "PERMISSION_DENIED": "管理员授权未完成。", "TUN_UNAVAILABLE": "无法启动系统 TUN。", "CONNECT_FAILED": "无法连接 VPN 隧道，请检查端口。"]
        return messages[code] ?? "VPN 连接失败（\(code)）。"
    }
}
