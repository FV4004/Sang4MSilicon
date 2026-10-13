import Foundation

final class OriginDelegate: NSObject, URLSessionTaskDelegate {
    let origin: URL
    init(_ origin: URL) { self.origin = origin }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url.map { sameOrigin($0, origin) } == true ? request : nil)
    }
}
@MainActor final class AuthClient {
    let base: URL
    let storage: HTTPCookieStorage
    private let session: URLSession
    private var config: [String: String] = [:]
    private(set) var twfid = ""
    private(set) var challenge = ""
    private(set) var authenticated = false
    private var generation = 0
    private var closed = false
    init(_ origin: String, configuration: URLSessionConfiguration = .ephemeral) throws {
        base = try serverURL(origin)
        configuration.timeoutIntervalForRequest = 15; configuration.timeoutIntervalForResource = 30
        configuration.urlCache = nil
        storage = configuration.httpCookieStorage!
        session = URLSession(configuration: configuration, delegate: OriginDelegate(base), delegateQueue: nil)
    }
    func request(_ path: String, origin: URL? = nil, form: [String: String]? = nil, headers: [String: String] = [:]) async throws -> Data {
        guard !closed else { throw VPNError("登录会话已关闭。") }
        let current = generation; let endpoint = origin ?? base
        guard var components = URLComponents(url: URL(string: path, relativeTo: endpoint)!.absoluteURL, resolvingAgainstBaseURL: false), let raw = components.url, sameOrigin(raw, endpoint) else { throw VPNError("服务器要求跳转到其他地址。") }
        var query = components.queryItems ?? []; if !query.contains(where: { $0.name == "apiversion" }) { query.append(URLQueryItem(name: "apiversion", value: "1")) }; components.queryItems = query
        var request = URLRequest(url: components.url!)
        request.setValue("MChipVPNLogin/0.5.0-beta.1", forHTTPHeaderField: "User-Agent")
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        if let form { request.httpMethod = "POST"; request.httpBody = formBody(form); request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type") }
        // A separate redirect delegate is required for the HTTPS tunnel origin.
        let transport: URLSession
        if sameOrigin(endpoint, base) { transport = session }
        else { let c = URLSessionConfiguration.ephemeral; c.httpCookieStorage = storage; c.timeoutIntervalForRequest = 15; c.timeoutIntervalForResource = 30; c.urlCache = nil; transport = URLSession(configuration: c, delegate: OriginDelegate(endpoint), delegateQueue: nil) }
        defer { if transport !== session { transport.finishTasksAndInvalidate() } }
        let (data, response) = try await transport.data(for: request)
        guard !closed, current == generation else { throw VPNError("操作已取消。") }
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), let final = response.url, sameOrigin(final, endpoint) else { throw VPNError("服务器返回了无效 HTTP 状态或跨站跳转。") }
        guard data.count <= 2 * 1024 * 1024 else { throw VPNError("服务器响应过大。") }
        return data
    }
    private func save(_ fields: [String: String]) { if let id = fields["TwfID"], !id.isEmpty { twfid = id }; if let random = fields["CSRF_RAND_CODE"] { config["CSRF_RAND_CODE"] = random } }
    func initialize() async throws -> Data? {
        let initial = try authFields(await request("/por/login_auth.csp")); guard initial["ErrorCode"] == "1" else { throw VPNError("初始化认证失败（\(initial["ErrorCode"] ?? "未知")）。") }; save(initial)
        let settings = try authFields(await request("/public/psw_config")); guard settings["ErrorCode"] == "1" else { throw VPNError("读取登录配置失败。") }
        config = initial.merging(settings) { _, new in new }; save(settings)
        return captchaRequired ? try await captcha() : nil
    }
    var captchaRequired: Bool { (config["USE_RAND_CODE"] ?? config["RndImg"] ?? "0") == "1" }
    func captcha() async throws -> Data {
        guard !config.isEmpty, !authenticated, challenge.isEmpty else { throw VPNError("请重新初始化登录会话。") }
        guard var url = URLComponents(url: URL(string: config["RAND_CODE_URL"] ?? "/por/rand_code.csp", relativeTo: base)!.absoluteURL, resolvingAgainstBaseURL: false) else { throw VPNError("验证码地址无效。") }
        var items = url.queryItems ?? []; items.append(URLQueryItem(name: "rnd", value: UUID().uuidString)); url.queryItems = items
        return try await request(url.url!.absoluteString)
    }
    func login(username: String, password: String, captcha: String) async throws -> String {
        guard !config.isEmpty, !authenticated, challenge.isEmpty, !username.trimmingCharacters(in: .whitespaces).isEmpty, username.count <= 256, !password.isEmpty, password.count <= 4096, captcha.count <= 128 else { throw VPNError("请输入有效用户名、密码和验证码。") }
        if captchaRequired && captcha.isEmpty { throw VPNError("请输入图片验证码。") }
        let fresh = try authFields(await request("/por/login_auth.csp"))
        guard fresh["ErrorCode"] == "1", fresh["RSA_ENCRYPT_KEY"] != nil, fresh["CSRF_RAND_CODE"] != nil else { throw VPNError("认证配置无效，请重新获取验证码。") }
        config.merge(fresh) { _, new in new }; save(fresh)
        let encrypted = try rsaPassword(password, config: config)
        return try await result(authFields(await request("/por/login_psw.csp?anti_replay=1&encrypt=1", form: ["mitm_result": "", "svpn_req_randcode": config["CSRF_RAND_CODE"]!, "svpn_name": username, "svpn_password": encrypted, "svpn_rand_code": captcha.trimmingCharacters(in: .whitespacesAndNewlines)])))
    }
    func submitChallenge(_ value: String) async throws -> String {
        let routes = ["token": ("/por/login_token.csp", "svpn_inputtoken"), "radius": ("/por/login_radius.csp", "svpn_inputradius"), "sms1": ("/por/login_sms1.csp", "svpn_inputsms"), "sms2": ("/por/login_sms2.csp", "svpn_inputsms"), "totp": ("/auth/token", "svpn_inputtoken")]
        guard let (path, field) = routes[challenge.lowercased()], !value.isEmpty, value.count <= 256 else { throw VPNError("请输入动态验证码或应答。") }
        var form = [field: value]; if challenge.lowercased() == "totp" { form["twfid"] = twfid }
        return try await result(authFields(await request(path, form: form)))
    }
    private func result(_ fields: [String: String]) async throws -> String {
        save(fields); let code = Int(fields["ErrorCode"] ?? "") ?? 0; let next = fields["NextService"] ?? ""
        if [1, 2].contains(code), !next.isEmpty { challenge = next; guard ["token", "radius", "sms1", "sms2", "totp"].contains(next.lowercased()) else { throw VPNError("此版本暂不支持服务器要求的认证步骤。") }; return "请输入动态验证码或应答。" }
        guard code == 1, next.isEmpty, !twfid.isEmpty else { throw VPNError("认证失败（\(code)），请刷新验证码后重试。") }
        var url = URLComponents(url: base.appendingPathComponent("por/update_session.csp"), resolvingAgainstBaseURL: false)!; url.queryItems = [URLQueryItem(name: "twfid", value: twfid)]
        _ = try await request(url.url!.absoluteString, headers: ["TWFID": twfid])
        authenticated = true; challenge = ""; config = [:]; return "认证成功，可以连接 VPN。"
    }
    func cancelPending() { generation += 1; session.getAllTasks { $0.forEach { $0.cancel() } } }
    func logout() async throws {
        defer { close() }
        if !twfid.isEmpty { let data = try await request("/por/logout.csp", form: [:], headers: ["TWFID": twfid]); if String(decoding: data, as: UTF8.self).contains("<Auth") { let result = try authFields(data); guard ["1", "20026"].contains(result["ErrorCode"] ?? "") else { throw VPNError("网关未确认注销登录。") } } }
    }
    func close() { closed = true; generation += 1; session.invalidateAndCancel(); storage.cookies?.forEach { storage.deleteCookie($0) }; twfid = ""; config = [:]; challenge = ""; authenticated = false }
}
