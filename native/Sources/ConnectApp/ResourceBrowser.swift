import AppKit
import WebKit

@MainActor final class ResourceBrowser: NSObject, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate {
    private var windows: [NSWindow] = []
    private var store = WKWebsiteDataStore.nonPersistent()
    private var generation = 0
    func open(_ resource: VPNResource, target: ResourceTarget, auth: AuthClient, origin: URL, tunConnected: Bool) async throws {
        if !resource.gateway { guard tunConnected else { throw VPNError("请先连接系统 TUN，再访问内网网页。") }; guard NSWorkspace.shared.open(target.url) else { throw VPNError("无法打开系统浏览器。") }; return }
        guard windows.count < 16 else { throw VPNError("请先关闭部分资源窗口。") }
        let current = generation
        let cookies = auth.storage.cookies(for: origin) ?? []
        for cookie in cookies where cookie.name != "TWFID" { await setCookie(cookie) }
        guard let host = origin.host, let cookie = HTTPCookie(properties: [.domain: host, .path: "/", .name: "TWFID", .value: auth.twfid, .secure: "TRUE", HTTPCookiePropertyKey("HttpOnly"): "TRUE"]) else { throw VPNError("资源会话无效。") }
        await setCookie(cookie)
        guard current == generation, auth.authenticated else { throw VPNError("资源会话已变更。") }
        var url = URLComponents(url: origin.appendingPathComponent("portal/shortcut.html"), resolvingAgainstBaseURL: false)!
        url.queryItems = [URLQueryItem(name: "twfid", value: auth.twfid), URLQueryItem(name: "url", value: try proxyPath(target.url, disguise: resource.disguise)), URLQueryItem(name: "lang", value: "zh_CN")]
        let configuration = WKWebViewConfiguration(); configuration.websiteDataStore = store
        let view = makeWindow(configuration: configuration, title: resource.name)
        view.load(URLRequest(url: url.url!))
    }
    private func setCookie(_ cookie: HTTPCookie) async { await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in store.httpCookieStore.setCookie(cookie) { continuation.resume() } } }
    private func makeWindow(configuration: WKWebViewConfiguration, title: String) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: configuration); view.navigationDelegate = self; view.uiDelegate = self
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 780), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = title + " · 内网资源"; window.contentView = view; window.delegate = self; window.isReleasedWhenClosed = false; window.center(); window.makeKeyAndOrderFront(nil); windows.append(window)
        return view
    }
    static func safe(_ url: URL?) -> Bool { guard let url else { return false }; return ["http", "https"].contains(url.scheme?.lowercased() ?? "") && url.host != nil && url.user == nil && url.password == nil }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard Self.safe(navigationAction.request.url) else { decisionHandler(.cancel); return }
        if let referrer = navigationAction.request.value(forHTTPHeaderField: "Referer"), referrer.range(of: "[?&]twfid=", options: [.regularExpression, .caseInsensitive]) != nil {
            var request = navigationAction.request; request.setValue(nil, forHTTPHeaderField: "Referer"); decisionHandler(.cancel); webView.load(request); return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        guard windows.count < 16, Self.safe(navigationAction.request.url) else { return nil }
        configuration.websiteDataStore = store
        return makeWindow(configuration: configuration, title: "内网资源")
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) { let alert = NSAlert(); alert.messageText = "网页提示"; alert.informativeText = String(message.prefix(4096)); alert.runModal(); completionHandler() }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) { let alert = NSAlert(); alert.messageText = "网页确认"; alert.informativeText = String(message.prefix(4096)); alert.addButton(withTitle: "确定"); alert.addButton(withTitle: "取消"); completionHandler(alert.runModal() == .alertFirstButtonReturn) }
    func windowWillClose(_ notification: Notification) { if let window = notification.object as? NSWindow { windows.removeAll { $0 === window } } }
    func close() async {
        generation += 1; let old = store; store = .nonPersistent()
        let existing = windows; windows.removeAll(); existing.forEach { ($0.contentView as? WKWebView)?.stopLoading(); $0.close() }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in old.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(), modifiedSince: .distantPast) { continuation.resume() } }
    }
}
