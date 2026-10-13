import AppKit
import SwiftUI

@MainActor final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate {
    let model = AppModel()
    private var window: NSWindow!
    private var statusItem: NSStatusItem!
    private var terminating = false
    private var terminationReplyPending = false
    private var terminationComplete = false
    private var closePromptVisible = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        smokeTrace("didFinishLaunching")
        NSApp.setActivationPolicy(.regular)
        configureMainMenu()
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 800), styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        window.title = "连接你的网络"; window.titleVisibility = .hidden; window.titlebarAppearsTransparent = true; window.isReleasedWhenClosed = false; window.minSize = NSSize(width: 960, height: 800); window.delegate = self
        window.contentView = NSHostingView(rootView: RootView(model: model, closeSettings: { [weak self] in self?.closeSettings() }, quit: { [weak self] in self?.requestQuit() }))
        window.center()
        model.showWindow = { [weak self] in self?.showInterface() }
        model.onStateChange = { [weak self] in self?.updateStatus() }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        let menu = NSMenu(); menu.delegate = self; statusItem.menu = menu
        updateStatus(); showInterface()
        if ProcessInfo.processInfo.arguments.contains("--ui-smoke") {
            Task {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                smokeTrace("smoke task running")
                guard self.window.isVisible, self.window.contentView != nil else { exit(1) }
                let titles = self.statusItem.menu?.items.map(\.title) ?? []
                for title in ["连接 VPN", "断开 VPN", "退出程序", "显示界面"] { guard titles.contains(title) else { exit(2) } }
                self.window.setContentSize(NSSize(width: 960, height: 800))
                self.model.loginMessage = "认证失败，请刷新验证码后重试。"; self.model.loginTone = .error
                self.model.requiresCaptcha = true
                try? await Task.sleep(nanoseconds: 200_000_000)
                self.capturePreview("login-preview.png")
                self.model.authenticated = true
                let fixture = "<Resource><RcGroups><Group id='g' name='演示资源'/></RcGroups><Rcs>" + (1...36).map { "<Rc id='\($0)' name='示例内网资源 \($0)' type='1' rc_grp_id='g' svc='http' host='10.0.0.\($0);10.0.1.\($0)' port='8080~8080;8080~8080'/>" }.joined() + "</Rcs></Resource>"
                self.model.groups = (try? parseResources(Data(fixture.utf8))) ?? []; self.model.tab = 1
                try? await Task.sleep(nanoseconds: 500_000_000)
                self.capturePreview("resources-preview.png")
                guard let scroll = self.resourceScrollView(in: self.window.contentView!), let document = scroll.documentView, document.frame.height > scroll.contentSize.height else { exit(5) }
                scroll.contentView.scroll(to: NSPoint(x: 0, y: max(0, document.frame.height - scroll.contentSize.height)))
                scroll.reflectScrolledClipView(scroll.contentView)
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard scroll.contentView.bounds.origin.y > 0 else { exit(6) }
                self.capturePreview("resources-scrolled-preview.png")
                self.model.loginMessage = "认证成功，已自动连接系统 TUN。"; self.model.loginTone = .success
                self.model.tab = 0; self.model.vpnState = "connected"; self.model.vpnDetail = "已连接 · 10.0.0.100 · 内网分流"
                try? await Task.sleep(nanoseconds: 200_000_000)
                self.capturePreview("connection-preview.png")
                let oldChoice = UserDefaults.standard.string(forKey: "closeAction")
                UserDefaults.standard.set("minimize", forKey: "closeAction")
                guard !self.windowShouldClose(self.window), self.model.authenticated else { exit(3) }
                self.showInterface()
                if let oldChoice { UserDefaults.standard.set(oldChoice, forKey: "closeAction") } else { UserDefaults.standard.removeObject(forKey: "closeAction") }
                smokeTrace("smoke task running")
                guard self.window.isVisible else { exit(4) }
                print("Native window, resource scrolling, status menu, minimize and restore smoke passed")
                smokeTrace("requesting termination")
                self.requestQuit()
            }
        } else { model.initialize() }
    }
    private func resourceScrollView(in view: NSView) -> NSScrollView? {
        if let scroll = view as? NSScrollView, let document = scroll.documentView, document.frame.height > scroll.contentSize.height + 20 { return scroll }
        for child in view.subviews { if let found = resourceScrollView(in: child) { return found } }
        return nil
    }
    private func capturePreview(_ name: String) {
        guard let view = window.contentView, let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        if let data = bitmap.representation(using: .png, properties: [:]) { try? data.write(to: URL(fileURLWithPath: "dist-native/" + name)) }
    }

    private func configureMainMenu() {
        let main = NSMenu(); let application = NSMenuItem(); main.addItem(application)
        let appMenu = NSMenu(); application.submenu = appMenu
        let show = NSMenuItem(title: "显示界面", action: #selector(showInterface), keyEquivalent: "0"); show.target = self; appMenu.addItem(show)
        appMenu.addItem(.separator())
        appMenu.addItem(NSMenuItem(title: "隐藏程序", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h"))
        let quit = NSMenuItem(title: "退出程序", action: #selector(quitApp), keyEquivalent: "q"); quit.target = self; appMenu.addItem(quit)
        let edit = NSMenuItem(); edit.title = "编辑"; main.addItem(edit); let menu = NSMenu(title: "编辑"); edit.submenu = menu
        for (title, action, key) in [("撤销", Selector(("undo:")), "z"), ("剪切", #selector(NSText.cut(_:)), "x"), ("复制", #selector(NSText.copy(_:)), "c"), ("粘贴", #selector(NSText.paste(_:)), "v"), ("全选", #selector(NSText.selectAll(_:)), "a")] { menu.addItem(NSMenuItem(title: title, action: action, keyEquivalent: key)) }
        NSApp.mainMenu = main
    }
    @objc func showInterface() { if window?.isMiniaturized == true { window.deminiaturize(nil) }; window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    @objc private func connectVPN() { model.connect() }
    @objc private func disconnectVPN() { model.disconnect() }
    @objc private func quitApp() { requestQuit() }
    func menuWillOpen(_ menu: NSMenu) { updateStatus() }
    private func updateStatus() {
        guard statusItem != nil else { return }
        let connected = model.vpnState == "connected"
        let image = NSImage(systemSymbolName: connected ? "checkmark.shield.fill" : "network", accessibilityDescription: connected ? "VPN 已连接" : "VPN 未连接")
        image?.isTemplate = true; statusItem.button?.image = image; statusItem.button?.toolTip = "连接你的网络 · " + model.vpnDetail
        guard let menu = statusItem.menu else { return }; menu.removeAllItems(); menu.autoenablesItems = false
        let state = NSMenuItem(title: model.vpnDetail, action: nil, keyEquivalent: ""); state.isEnabled = false; menu.addItem(state); menu.addItem(.separator())
        let connect = NSMenuItem(title: "连接 VPN", action: #selector(connectVPN), keyEquivalent: ""); connect.target = self; connect.isEnabled = !terminating && !model.busy && model.vpnState == "disconnected"; menu.addItem(connect)
        let disconnect = NSMenuItem(title: "断开 VPN", action: #selector(disconnectVPN), keyEquivalent: ""); disconnect.target = self; disconnect.isEnabled = !terminating && model.vpnState != "disconnected" && model.vpnState != "stopping"; menu.addItem(disconnect)
        menu.addItem(.separator())
        let show = NSMenuItem(title: "显示界面", action: #selector(showInterface), keyEquivalent: ""); show.target = self; menu.addItem(show)
        let settings = NSMenuItem(title: "关闭行为设置…", action: #selector(closeSettings), keyEquivalent: ""); settings.target = self; menu.addItem(settings)
        menu.addItem(.separator()); let quit = NSMenuItem(title: "退出程序", action: #selector(quitApp), keyEquivalent: ""); quit.target = self; quit.isEnabled = !terminating; menu.addItem(quit)
    }
    @objc private func closeSettings() { UserDefaults.standard.removeObject(forKey: "closeAction"); showInterface(); let alert = NSAlert(); alert.messageText = "关闭行为已重置"; alert.informativeText = "下次关闭主窗口时，将重新询问退出或最小化。"; alert.beginSheetModal(for: window) }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if terminationComplete { return true }
        if terminating || closePromptVisible { return false }
        let remembered = CloseAction.remembered(UserDefaults.standard.string(forKey: "closeAction"))
        if remembered == .quit { requestQuit(); return false }
        if remembered == .minimize { sender.miniaturize(nil); return false }
        let alert = NSAlert(); alert.messageText = "关闭程序还是最小化？"; alert.informativeText = "最小化会保留 VPN 连接，可通过系统状态栏恢复窗口。退出会断开 VPN 并注销登录认证。"
        alert.addButton(withTitle: "最小化"); alert.addButton(withTitle: "退出程序"); alert.addButton(withTitle: "取消"); alert.showsSuppressionButton = true; alert.suppressionButton?.title = "记忆我的选择"
        closePromptVisible = true
        alert.beginSheetModal(for: sender) { [weak self] result in
            self?.closePromptVisible = false
            let action = result == .alertFirstButtonReturn ? "minimize" : result == .alertSecondButtonReturn ? "quit" : nil
            if let action, alert.suppressionButton?.state == .on { UserDefaults.standard.set(action, forKey: "closeAction") }
            if action == "minimize" { sender.miniaturize(nil) }; if action == "quit" { self?.requestQuit() }
        }
        return false
    }
    private func requestQuit() {
        guard !terminating else { return }
        terminating = true; updateStatus()
        Task {
            smokeTrace("shutdown task running")
            if let warning = await model.shutdown() { let alert = NSAlert(); alert.alertStyle = .warning; alert.messageText = "退出清理提示"; alert.informativeText = warning; alert.runModal() }
            smokeTrace("shutdown complete")
            terminationComplete = true
            if let statusItem { NSStatusBar.system.removeStatusItem(statusItem) }
            if terminationReplyPending { NSApp.reply(toApplicationShouldTerminate: true) } else { NSApp.terminate(nil) }
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if terminationComplete { return .terminateNow }
        // System termination is an AppKit event; explicit UI/menu quits start
        // cleanup before terminate(), avoiding nested-run-loop starvation.
        terminationReplyPending = true; requestQuit(); return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { showInterface(); return true }
}
func smokeTrace(_ message: String) {
    if ProcessInfo.processInfo.arguments.contains("--ui-smoke") { FileHandle.standardError.write(Data(("UI smoke: " + message + "\n").utf8)) }
}
@main struct NativeApp {
    @MainActor static func main() { smokeTrace("starting application"); let app = NSApplication.shared; let delegate = AppDelegate(); smokeTrace("delegate initialized"); app.delegate = delegate; withExtendedLifetime(delegate) { app.run() } }
}
