import SwiftUI
import AppKit

enum FeedbackTone { case neutral, success, warning, error }
struct VPNConnectionRequest {
    let host: String; let port: Int; let sessionID: String; let mode: String; let socksPort: Int; let httpPort: Int
}
@MainActor final class AppModel: ObservableObject {
    @Published var server = ""
    @Published var username = ""
    @Published var password = ""
    @Published var rememberPassword = false
    @Published var captcha = ""
    @Published var captchaImage: NSImage?
    @Published var requiresCaptcha = false
    @Published var response = ""
    @Published var message = "输入服务器地址，连接你的网络。"
    @Published var loginMessage = "输入服务器地址，连接你的网络。"
    @Published var loginTone: FeedbackTone = .neutral
    @Published var busy = false
    @Published private(set) var preparingServer = false
    @Published var authenticated = false
    @Published var challenge = false
    @Published var ready = false
    @Published var mode = "tun"
    @Published var tunnelPort = "443"
    @Published var socksPort = "1080"
    @Published var httpPort = "1081"
    @Published var vpnState = "disconnected"
    @Published var vpnDetail = "未连接"
    @Published var vpnDiagnostic = ""
    @Published var groups: [ResourceGroup] = []
    @Published var tab = 0
    @Published var selectedGroup = ""
    @Published var search = ""
    let vpn: VPNController
    let browser: ResourceBrowser
    var onStateChange: (() -> Void)?
    var showWindow: (() -> Void)?
    private var auth: AuthClient?
    private var operation: Task<Void, Never>?
    private var directOperation: Task<Void, Never>?
    private var preparationWait: Task<Void, Never>?
    private var serverEditing = false
    private let preferences: UserDefaults
    private let authFactory: (String) throws -> AuthClient
    private let vpnConnector: (VPNConnectionRequest) async throws -> Void
    private var shuttingDown = false
    private let shutdownCoordinator = ShutdownCoordinator()
    private var resourceOrigin: URL?
    init(preferences: UserDefaults = .standard, authFactory: ((String) throws -> AuthClient)? = nil, vpnConnector: ((VPNConnectionRequest) async throws -> Void)? = nil, browser: ResourceBrowser? = nil) {
        self.browser = browser ?? ResourceBrowser()
        self.preferences = preferences; self.authFactory = authFactory ?? { try AuthClient($0) }
        let controller = VPNController(); self.vpn = controller
        self.vpnConnector = vpnConnector ?? { request in try await controller.start(host: request.host, port: request.port, sessionID: request.sessionID, mode: request.mode, socksPort: request.socksPort, httpPort: request.httpPort) }
        server = preferences.string(forKey: "server") ?? ""
        username = preferences.string(forKey: "username") ?? ""
        // Every launch starts with password memory off, including upgrades from an
        // older persisted opt-in. Stored entries are read only after explicit opt-in.
        rememberPassword = false
        preferences.removeObject(forKey: "rememberPassword")
        vpn.onChange = { [weak self] in guard let self else { return }; self.vpnState = self.vpn.state; self.vpnDetail = self.vpn.detail; self.vpnDiagnostic = self.vpn.diagnostic; self.onStateChange?() }
    }
    private func run(_ work: @escaping () async throws -> Void) {
        guard !busy, !shuttingDown else { return }; busy = true; onStateChange?()
        operation = Task { [weak self] in
            guard let self else { return }
            do { try await work() } catch is CancellationError {} catch { if !self.shuttingDown && !Task.isCancelled { self.message = error.localizedDescription; if !self.authenticated { self.loginMessage = error.localizedDescription; self.loginTone = .error } } }
            self.busy = false; self.operation = nil; self.onStateChange?()
        }
    }
    func serverChanged() {
        preferences.set(server, forKey: "server")
        preparationWait?.cancel()
        guard !authenticated, !shuttingDown else { return }
        ready = false
        // Editing never starts a request. Cancel preparation for the old address
        // without cancelling an authenticated connection or password submission.
        if preparingServer { operation?.cancel() }
        if !busy || preparingServer { auth?.close(); auth = nil; captchaImage = nil; requiresCaptcha = false; captcha = "" }
    }
    func serverEditingChanged(_ editing: Bool) {
        serverEditing = editing
        preparationWait?.cancel()
        guard !editing, !authenticated, !shuttingDown, !ready, (try? serverURL(server)) != nil else { return }
        let pending = operation
        preparationWait = Task { [weak self] in
            await pending?.value
            guard let self, !Task.isCancelled, !self.serverEditing, !self.shuttingDown, !self.ready else { return }
            self.initialize()
        }
    }
    func rememberChanged() {
        preferences.removeObject(forKey: "rememberPassword")
        if rememberPassword && password.isEmpty { password = PasswordStore.load(server: server, username: username) }
        if !rememberPassword { do { try PasswordStore.save(nil, server: server, username: username) } catch { message = error.localizedDescription } }
    }
    func initialize() {
        guard !server.isEmpty, !authenticated, !busy, !shuttingDown else { return }
        let requestedServer = server
        preparingServer = true
        run { [self] in
            defer { preparingServer = false }
            auth?.close(); ready = false; challenge = false; requiresCaptcha = false; captchaImage = nil; captcha = ""
            let client = try authFactory(requestedServer); auth = client
            if client.base.scheme == "https", let port = client.base.port { tunnelPort = String(port) } else { tunnelPort = "443" }
            let image = try await client.initialize(); try Task.checkCancellation()
            guard auth === client, server == requestedServer, !shuttingDown else { return }
            requiresCaptcha = client.captchaRequired
            if let image { guard let decoded = NSImage(data: image) else { throw VPNError("服务器未返回有效验证码图片。") }; captchaImage = decoded }
            ready = true; message = "请输入账号、密码\(requiresCaptcha ? "和验证码" : "")。"; loginMessage = message; loginTone = .neutral
        }
    }
    func refreshCaptcha() {
        if !ready || challenge { initialize(); return }
        run { [self] in guard let auth else { throw VPNError("请初始化登录。") }; let image = try await auth.captcha(); try Task.checkCancellation(); guard let decoded = NSImage(data: image) else { throw VPNError("验证码图片无效。") }; captchaImage = decoded; captcha = "" }
    }
    func login() {
        guard !busy, !shuttingDown else { return }
        loginMessage = "正在认证…"; loginTone = .neutral
        run { [self] in
            guard let client = auth, ready else { throw VPNError("请先获取登录配置。") }
            message = challenge ? try await client.submitChallenge(response) : try await client.login(username: username, password: password, captcha: captcha)
            try Task.checkCancellation(); authenticated = client.authenticated; challenge = !client.challenge.isEmpty
            loginMessage = message; loginTone = authenticated ? .success : .neutral
            if authenticated {
                preferences.set(server, forKey: "server"); preferences.set(username, forKey: "username")
                if rememberPassword { do { try PasswordStore.save(password, server: server, username: username) } catch { loginMessage += " " + error.localizedDescription; loginTone = .warning } }
                captcha = ""; response = ""; captchaImage = nil
                // Load portal configuration before establishing the data tunnel,
                // matching the sequence used by the previously stable client.
                do { try await fetchResources() } catch { try Task.checkCancellation(); message += " 资源列表加载失败：" + error.localizedDescription }
                try Task.checkCancellation()
                mode = "tun"
                do { try await startVPN() } catch { try Task.checkCancellation(); message = "认证成功，自动连接 TUN 失败：" + error.localizedDescription }

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
        groups = try parseResources(data); resourceOrigin = origin; selectedGroup = ""
    }
    func refreshResources() { run { [self] in try await fetchResources() } }
    var filteredResources: [VPNResource] { groups.filter { selectedGroup.isEmpty || $0.id == selectedGroup }.flatMap(\.items).filter { search.isEmpty || ($0.name + " " + $0.hosts.joined(separator: " ") + " " + $0.ports.joined(separator: " ")).localizedCaseInsensitiveContains(search) } }
    func open(_ resource: VPNResource, target: ResourceTarget) {
        if !resource.gateway {
            guard !busy, !shuttingDown, directOperation == nil else { return }
            guard authenticated else { message = "请先登录。"; return }
            // Ordinary browser launch owns no authentication operation or VPN control handle.
            directOperation = Task { [weak self] in
                guard let self else { return }
                defer { self.directOperation = nil }
                do { try await self.browser.openDirect(target: target, tunConnected: self.vpnState == "connected" && self.vpn.mode == "tun") }
                catch is CancellationError {}
                catch { if !self.shuttingDown { self.message = error.localizedDescription } }
            }
            return
        }
        run { [self] in guard let auth, authenticated, let origin = resourceOrigin else { throw VPNError("请刷新资源列表。") }; try await browser.open(resource, target: target, auth: auth, origin: origin, tunConnected: vpnState == "connected" && vpn.mode == "tun") }
    }
    func connect() {
        guard authenticated else { showWindow?(); message = "请先完成账号认证。"; return }
        run { [self] in try await startVPN() }
    }
    private func startVPN() async throws {
        guard authenticated, !shuttingDown, let auth, let host = auth.base.host, let port = Int(tunnelPort), (1...65535).contains(port) else { throw VPNError("隧道端口或认证会话无效。") }
        try await vpnConnector(VPNConnectionRequest(host: host, port: port, sessionID: auth.twfid, mode: mode, socksPort: Int(socksPort) ?? 0, httpPort: Int(httpPort) ?? 0))
    }
    func repairService() {
        run { [self] in try await vpn.repairService(); message = "后台服务已修复，网络配置已恢复，可以重新连接。" }
    }
    func recoverNetwork() {
        run { [self] in try await vpn.recoverNetwork(); message = "网络配置已恢复，可以重新连接 VPN。" }
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
        authenticated = false; ready = false; challenge = false; groups = []; resourceOrigin = nil; tab = 0; message = "登录会话已清除。"; loginMessage = message; loginTone = .neutral
        if !errors.isEmpty { throw VPNError(errors.joined(separator: "\n")) }
    }
    func shutdown() async -> String? {
        shuttingDown = true
        let pending = operation
        return await shutdownCoordinator.shutdown(cancel: { [self] in
            preparationWait?.cancel(); operation?.cancel(); directOperation?.cancel(); await auth?.cancelPending()
        }, stopVPN: { [self] in try await vpn.stop() }, drain: { await pending?.value }, closeWeb: { [self] in await browser.close() }, logout: { [self] in
            let client = auth; auth = nil; try await client?.logout()
        }, clear: { [self] in
            authenticated = false; ready = false; challenge = false; groups = []; resourceOrigin = nil; password = ""; preferences.synchronize()
        })
    }
}
