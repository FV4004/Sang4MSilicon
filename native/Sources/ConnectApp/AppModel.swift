import SwiftUI
import AppKit

@MainActor final class AppModel: ObservableObject {
    @Published var server = UserDefaults.standard.string(forKey: "server") ?? ""
    @Published var username = UserDefaults.standard.string(forKey: "username") ?? ""
    @Published var password = ""
    @Published var rememberPassword = UserDefaults.standard.bool(forKey: "rememberPassword")
    @Published var captcha = ""
    @Published var captchaImage: NSImage?
    @Published var requiresCaptcha = false
    @Published var response = ""
    @Published var message = "输入服务器地址，连接你的网络。"
    @Published var busy = false
    @Published var authenticated = false
    @Published var challenge = false
    @Published var ready = false
    @Published var mode = "tun"
    @Published var tunnelPort = "443"
    @Published var socksPort = "1080"
    @Published var httpPort = "1081"
    @Published var vpnState = "disconnected"
    @Published var vpnDetail = "未连接"
    @Published var groups: [ResourceGroup] = []
    @Published var tab = 0
    @Published var selectedGroup = ""
    @Published var search = ""
    @Published var page = 0
    let vpn = VPNController()
    let browser = ResourceBrowser()
    var onStateChange: (() -> Void)?
    var showWindow: (() -> Void)?
    private var auth: AuthClient?
    private var operation: Task<Void, Never>?
    private var debounce: Task<Void, Never>?
    private var shuttingDown = false
    private let shutdownCoordinator = ShutdownCoordinator()
    private var resourceOrigin: URL?
    init() {
        if rememberPassword { password = PasswordStore.load(server: server, username: username) }
        vpn.onChange = { [weak self] in guard let self else { return }; self.vpnState = self.vpn.state; self.vpnDetail = self.vpn.detail; self.onStateChange?() }
    }
    private func run(_ work: @escaping () async throws -> Void) {
        guard !busy, !shuttingDown else { return }; busy = true; onStateChange?()
        operation = Task { [weak self] in
            guard let self else { return }
            do { try await work() } catch is CancellationError {} catch { if !self.shuttingDown { self.message = error.localizedDescription } }
            self.busy = false; self.operation = nil; self.onStateChange?()
        }
    }
    func serverChanged() {
        UserDefaults.standard.set(server, forKey: "server")
        debounce?.cancel()
        guard !authenticated, !shuttingDown else { return }
        ready = false
        debounce = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: 600_000_000) } catch { return }
            guard let self, !Task.isCancelled else { return }
            self.initialize()
        }
    }
    func rememberChanged() {
        UserDefaults.standard.set(rememberPassword, forKey: "rememberPassword")
        if !rememberPassword { do { try PasswordStore.save(nil, server: server, username: username) } catch { message = error.localizedDescription } }
    }
    func initialize() {
        guard !server.isEmpty, !authenticated else { return }
        run { [self] in
            auth?.close(); ready = false; challenge = false; requiresCaptcha = false; captchaImage = nil; captcha = ""
            let client = try AuthClient(server); auth = client
            if client.base.scheme == "https", let port = client.base.port { tunnelPort = String(port) } else { tunnelPort = "443" }
            let image = try await client.initialize(); try Task.checkCancellation()
            guard auth === client, !shuttingDown else { return }
            requiresCaptcha = client.captchaRequired
            if let image { guard let decoded = NSImage(data: image) else { throw VPNError("服务器未返回有效验证码图片。") }; captchaImage = decoded }
            ready = true; message = "请输入账号、密码\(requiresCaptcha ? "和验证码" : "")。"
        }
    }
    func refreshCaptcha() {
        if !ready || challenge { initialize(); return }
        run { [self] in guard let auth else { throw VPNError("请初始化登录。") }; let image = try await auth.captcha(); try Task.checkCancellation(); guard let decoded = NSImage(data: image) else { throw VPNError("验证码图片无效。") }; captchaImage = decoded; captcha = "" }
    }
    func login() {
        run { [self] in
            guard let client = auth, ready else { throw VPNError("请先获取登录配置。") }
            message = challenge ? try await client.submitChallenge(response) : try await client.login(username: username, password: password, captcha: captcha)
            try Task.checkCancellation(); authenticated = client.authenticated; challenge = !client.challenge.isEmpty
            if authenticated {
                UserDefaults.standard.set(server, forKey: "server"); UserDefaults.standard.set(username, forKey: "username"); UserDefaults.standard.set(rememberPassword, forKey: "rememberPassword")
                if rememberPassword { do { try PasswordStore.save(password, server: server, username: username) } catch { message += " " + error.localizedDescription } }
                captcha = ""; response = ""; captchaImage = nil
                do { try await fetchResources() } catch { message = "认证成功；资源列表加载失败：" + error.localizedDescription }
            }
        }
    }
    private func gatewayOrigin() throws -> URL {
        guard let auth, let port = Int(tunnelPort), (1...65535).contains(port) else { throw VPNError("请输入有效隧道端口。") }
        var c = URLComponents(url: auth.base, resolvingAgainstBaseURL: false)!; c.scheme = "https"; c.port = port; c.path = "/"; return c.url!
    }
    private func fetchResources() async throws {
        guard let client = auth, authenticated else { throw VPNError("请先登录。") }
        let origin = try gatewayOrigin()
        let data = try await client.request("/por/rclist.csp", origin: origin, headers: ["TWFID": client.twfid, "Cookie": "TWFID=" + client.twfid])
        try Task.checkCancellation(); guard auth === client, authenticated else { return }
        groups = try parseResources(data); resourceOrigin = origin; selectedGroup = ""; page = 0
    }
    func refreshResources() { run { [self] in try await fetchResources() } }
    var filteredResources: [VPNResource] { groups.filter { selectedGroup.isEmpty || $0.id == selectedGroup }.flatMap(\.items).filter { search.isEmpty || ($0.name + " " + $0.hosts.joined(separator: " ")).localizedCaseInsensitiveContains(search) } }
    var pageCount: Int { max(1, (filteredResources.count + 3) / 4) }
    var pageItems: [VPNResource] { Array(filteredResources.dropFirst(min(page, pageCount - 1) * 4).prefix(4)) }
    func open(_ resource: VPNResource, target: ResourceTarget) {
        run { [self] in guard let auth, authenticated, let origin = resourceOrigin else { throw VPNError("请刷新资源列表。") }; try await browser.open(resource, target: target, auth: auth, origin: origin, tunConnected: vpnState == "connected" && vpn.mode == "tun") }
    }
    func connect() {
        guard authenticated else { showWindow?(); message = "请先完成账号认证。"; return }
        run { [self] in guard let auth, let host = auth.base.host, let port = Int(tunnelPort) else { throw VPNError("隧道端口无效。") }; try await vpn.start(host: host, port: port, sessionID: auth.twfid, mode: mode, socksPort: Int(socksPort) ?? 0, httpPort: Int(httpPort) ?? 0) }
    }
    func disconnect() {
        if busy && vpnState != "disconnected" {
            let pending = operation; pending?.cancel()
            Task { [self] in do { try await vpn.stop() } catch { message = error.localizedDescription }; await pending?.value }
        } else { run { [self] in try await vpn.stop() } }
    }
    func logout() { run { [self] in try await cleanup() } }
    private func cleanup() async throws {
        var errors: [String] = []; await browser.close()
        do { try await vpn.stop() } catch { errors.append(error.localizedDescription) }
        let client = auth; auth = nil
        do { try await client?.logout() } catch { errors.append("网关注销未确认：" + error.localizedDescription) }
        authenticated = false; ready = false; challenge = false; groups = []; resourceOrigin = nil; tab = 0; message = "登录会话已清除。"
        if !errors.isEmpty { throw VPNError(errors.joined(separator: "\n")) }
    }
    func shutdown() async -> String? {
        shuttingDown = true
        let pending = operation
        return await shutdownCoordinator.shutdown(cancel: { [self] in
            debounce?.cancel(); operation?.cancel(); await auth?.cancelPending()
        }, stopVPN: { [self] in try await vpn.stop() }, drain: { await pending?.value }, closeWeb: { [self] in await browser.close() }, logout: { [self] in
            let client = auth; auth = nil; try await client?.logout()
        }, clear: { [self] in
            authenticated = false; ready = false; challenge = false; groups = []; resourceOrigin = nil; password = ""; UserDefaults.standard.synchronize()
        })
    }
}
