import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel
    @FocusState private var serverFocused: Bool
    let closeSettings: () -> Void
    let quit: () -> Void
    var body: some View {
        HStack(spacing: 0) {
            sidebar
            VStack(alignment: .leading, spacing: 14) {
                if model.authenticated {
                    Picker("页面", selection: $model.tab) { Text("连接").tag(0); Text("内网资源").tag(1) }.pickerStyle(.segmented).labelsHidden().frame(width: 220)
                }
                if model.tab == 0 { connection; Spacer(minLength: 0) } else { resources }
                if model.authenticated { Text(model.message).font(.caption).foregroundStyle(.secondary).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading).accessibilityIdentifier("statusMessage") }
                HStack(spacing: 20) { Button("关闭方式", action: closeSettings); Button("退出程序", action: quit); Spacer(); if model.vpnState == "disconnected" { Button("恢复网络配置", action: model.recoverNetwork).disabled(model.busy); Button("修复后台服务", action: model.repairService).disabled(model.busy) } }.buttonStyle(.link).font(.caption)
                Text("仅供开源学习与研究。默认记忆服务器与用户 ID；密码可选保存到钥匙串，会话不保存。").font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2)
            }.padding(.top, 44).padding(.horizontal, 40).padding(.bottom, 20).frame(maxWidth: .infinity, maxHeight: .infinity)
        }.frame(minWidth: 960, minHeight: 760).background(Color(nsColor: .windowBackgroundColor)).tint(.accentColor)
        .onChange(of: model.server) { _ in model.serverChanged() }
        .onChange(of: serverFocused) { model.serverEditingChanged($0) }
        .onChange(of: model.username) { value in UserDefaults.standard.set(value, forKey: "username") }
        .onChange(of: model.rememberPassword) { _ in model.rememberChanged() }
    }
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Text("M").font(.system(size: 24, weight: .semibold)).foregroundStyle(.white).frame(width: 40, height: 40).background(Color.accentColor).clipShape(RoundedRectangle(cornerRadius: 11))
                Text("CONNECT LAB").font(.system(size: 11, weight: .semibold)).tracking(2)
            }
            Text("MACOS · NATIVE").font(.system(size: 10, weight: .semibold)).tracking(1.4).foregroundStyle(.secondary).padding(.top, 54)
            Text("从这里，\n连接你的网络。").font(.system(size: 32, weight: .medium)).lineSpacing(10).padding(.top, 16)
            Text("输入 VPN 服务器地址，完成账号认证与人机核验。").font(.system(size: 13)).foregroundStyle(.secondary).lineSpacing(7).padding(.top, 16)
            Divider().padding(.top, 38).padding(.bottom, 18)
            Label("开源网络实验", systemImage: "network").font(.system(size: 12, weight: .semibold)).foregroundStyle(Color.accentColor)
            Text("支持 macOS TUN 分流：内网资源通过系统隧道连接。也可选择本地 SOCKS5 / HTTP 代理。").font(.system(size: 11)).foregroundStyle(.secondary).lineSpacing(6).padding(.top, 10)
            Divider().padding(.top, 18)
            Spacer()
            StatusBadge(title: model.vpnState == "connected" ? "VPN 已连接" : "VPN 未连接", color: model.vpnState == "connected" ? Color(nsColor: .systemGreen) : .secondary, solid: model.vpnState == "connected")
            Text("macOS · Apple Silicon / Intel").font(.system(size: 10)).foregroundStyle(.secondary).padding(.top, 18)
            Text("仅供开源学习与研究").font(.system(size: 10)).foregroundStyle(.secondary).padding(.top, 7)
        }.padding(.top, 58).padding(.horizontal, 28).padding(.bottom, 26).frame(width: 280).frame(maxHeight: .infinity).background(Color(nsColor: .controlBackgroundColor))
        .overlay(alignment: .trailing) { Divider() }
    }
    private var connection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                heading("账号认证", model.authenticated ? "连接你的网络" : "登录 VPN 网关")
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                StatusBadge(title: model.authenticated ? "认证成功" : "未认证", color: model.authenticated ? Color(nsColor: .systemGreen) : .secondary, solid: model.authenticated)
            }
            if !model.authenticated {
                field("服务器地址") { TextField("https://vpn.example.com", text: $model.server).textFieldStyle(.roundedBorder).controlSize(.large).focused($serverFocused).onSubmit { serverFocused = false; model.serverEditingChanged(false) }.disabled((model.busy && !model.preparingServer) || model.challenge) }
                Text("支持 HTTP / HTTPS；默认端口为 80 / 443，也可指定其他端口。").font(.system(size: 10)).foregroundStyle(.secondary)
                if !model.challenge {
                    field("用户 ID") { TextField("输入你的用户 ID", text: $model.username).textFieldStyle(.roundedBorder).controlSize(.large).disabled(model.busy) }
                    field("密码") { SecureField("输入你的密码", text: $model.password).textFieldStyle(.roundedBorder).controlSize(.large).disabled(model.busy) }
                    HStack(spacing: 12) { Toggle("记忆密码", isOn: $model.rememberPassword).toggleStyle(.checkbox).disabled(model.busy); Text("默认记忆用户 ID；密码可选保存到钥匙串。").foregroundStyle(.secondary) }.font(.system(size: 11))
                    if model.requiresCaptcha {
                        field("人机核验") {
                            HStack(spacing: 10) {
                                TextField("输入图片中的字符", text: $model.captcha).textFieldStyle(.roundedBorder).controlSize(.large).disabled(model.busy)
                                Group { if let image = model.captchaImage { Image(nsImage: image).resizable().scaledToFit().accessibilityLabel("人机核验验证码") } else { Text("等待验证码").font(.caption).foregroundStyle(.secondary) } }.frame(width: 115, height: 38).background(Color(nsColor: .textBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 7))
                                Button { model.refreshCaptcha() } label: { Image(systemName: "arrow.clockwise").font(.title3) }.buttonStyle(.borderless).foregroundStyle(Color.accentColor).help("刷新验证码").disabled(model.busy)
                            }
                        }
                    }
                } else { field("后续认证 · 动态验证码或应答") { TextField("输入动态验证码或应答", text: $model.response).textFieldStyle(.roundedBorder).controlSize(.large).disabled(model.busy) } }
                Button(action: model.login) { Text(model.challenge ? "提交验证" : "登录").frame(maxWidth: .infinity) }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy || !model.ready).keyboardShortcut(.defaultAction)
                loginFeedback
            } else {
                loginFeedback
                Button("退出登录会话", action: model.logout).controlSize(.large).disabled(model.busy)
                Divider().padding(.vertical, 4)
                HStack { Text("VPN 连接").font(.headline); Spacer(); vpnBadge }
                field("连接模式") { Picker("连接模式", selection: $model.mode) { Text("系统 TUN · 内网分流").tag("tun"); Text("本地代理 · 应用单独配置").tag("proxy") }.labelsHidden().controlSize(.large).disabled(model.busy || model.vpnState != "disconnected") }
                Text(model.mode == "tun" ? "首次连接需通过 macOS 系统弹窗授权管理员操作。仅接管网关提供的 IPv4 内网资源；不接管全流量或 IPv6。" : "本地代理监听 127.0.0.1，浏览器和应用需单独设置代理。").font(.system(size: 10)).foregroundStyle(.secondary)
                HStack {
                    field("隧道端口") { portField($model.tunnelPort, "443") }
                    if model.mode == "proxy" { field("SOCKS5 端口") { portField($model.socksPort, "1080") }; field("HTTP 代理端口") { portField($model.httpPort, "1081") } }
                }
                Text("隧道端口独立于 HTTP 登录端口，默认 443；HTTPS 自定义端口会自动沿用。").font(.system(size: 10)).foregroundStyle(.secondary)
                HStack {
                    if model.vpnState == "disconnected" { Button("连接 VPN", action: model.connect).buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy) }
                    else { Button("断开连接", action: model.disconnect).buttonStyle(.borderedProminent).tint(Color(nsColor: .systemRed)).controlSize(.large).disabled(model.vpnState == "stopping") }
                }.padding(.top, 4)
                Text(model.vpnDetail).font(.callout).foregroundStyle(model.vpnState == "connected" ? Color(nsColor: .systemGreen) : .secondary).textSelection(.enabled).lineLimit(3)
                Text("TUN 模式无需单独配置应用代理；断开后恢复本次添加的路由与内网 DNS。").font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
    }
    private var loginFeedback: some View {
        let color: Color
        switch model.loginTone {
        case .neutral: color = .secondary
        case .success: color = Color(nsColor: .systemGreen)
        case .warning: color = Color(nsColor: .systemOrange)
        case .error: color = Color(nsColor: .systemRed)
        }
        return Text(model.loginMessage).font(.callout).foregroundStyle(color).lineLimit(3).frame(maxWidth: .infinity, alignment: .leading).accessibilityIdentifier("loginFeedback")
    }
    private var vpnBadge: some View {
        let connected = model.vpnState == "connected"
        let moving = model.vpnState == "connecting" || model.vpnState == "stopping"
        let failed = model.vpnState == "error" || model.vpnDetail.contains("失败")
        return StatusBadge(title: connected ? "已连接" : moving ? "正在连接 / 断开" : failed ? "连接失败" : "未连接", color: connected ? Color(nsColor: .systemGreen) : failed ? Color(nsColor: .systemRed) : moving ? .accentColor : .secondary, solid: connected || moving || failed)
    }
    private var resources: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { heading("授权内网资源", "资源目录"); Spacer(); Button("刷新", action: model.refreshResources).controlSize(.large).disabled(model.busy) }
            HStack(spacing: 12) {
                Picker("分组", selection: $model.selectedGroup) { Text("全部分组").tag(""); ForEach(model.groups) { Text($0.name).tag($0.id) } }.labelsHidden().controlSize(.large).frame(maxWidth: 220)
                TextField("搜索名称或网址", text: $model.search).textFieldStyle(.roundedBorder).controlSize(.large)
            }
            Text("\(model.filteredResources.count) 个资源 · 可连续滚动浏览").font(.caption).foregroundStyle(.secondary)
            GeometryReader { geometry in
                let rowHeight = max(132, (geometry.size.height - 24) / 3)
                ScrollViewReader { proxy in
                    ScrollView(.vertical) {
                        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 3), spacing: 12) {
                            ForEach(model.filteredResources) { item in
                                ResourceCard(item: item, group: model.groups.first(where: { $0.id == item.groupID })?.name ?? "", busy: model.busy, height: rowHeight, open: { model.open(item, target: $0) })
                            }
                        }.padding(.trailing, 2).id("resource-top")
                    }.accessibilityIdentifier("resourceGrid")
                    .onChange(of: model.selectedGroup) { _ in proxy.scrollTo("resource-top", anchor: .top) }
                    .onChange(of: model.search) { _ in proxy.scrollTo("resource-top", anchor: .top) }
                    .overlay { if model.filteredResources.isEmpty { Text("暂无匹配资源，请刷新或调整筛选条件。").foregroundStyle(.secondary) } }
                }
            }.frame(minHeight: 420)
            Text("普通网页通过系统浏览器访问；网关 Web 资源在独立窗口打开。地址范围和非 Web 资源仅展示。").font(.system(size: 10)).foregroundStyle(.secondary)
        }.frame(maxHeight: .infinity)
    }
    private func heading(_ eyebrow: String, _ title: String) -> some View { VStack(alignment: .leading, spacing: 7) { Text(eyebrow).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary); Text(title).font(.system(size: 24, weight: .semibold)) } }
    private func field<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View { VStack(alignment: .leading, spacing: 6) { Text(title).font(.system(size: 12, weight: .semibold)); content() }.frame(maxWidth: .infinity, alignment: .leading) }
    private func portField(_ binding: Binding<String>, _ placeholder: String) -> some View { TextField(placeholder, text: binding).textFieldStyle(.roundedBorder).controlSize(.large).disabled(model.busy || model.vpnState != "disconnected") }
}
struct StatusBadge: View {
    let title: String; let color: Color; var solid = true
    var body: some View { Text(title).font(.system(size: 11, weight: .semibold)).foregroundStyle(solid ? .white : color).padding(.horizontal, 12).padding(.vertical, 7).background(color.opacity(solid ? 1 : 0.12)).clipShape(Capsule()) }
}
struct ResourceCard: View {
    let item: VPNResource; let group: String; let busy: Bool; let height: CGFloat; let open: (ResourceTarget) -> Void
    @State private var selection = 0
    @State private var copied = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(group).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
            Text(item.name).font(.system(size: 12, weight: .semibold)).lineLimit(2).help(item.name)
            Spacer(minLength: 0)
            if item.targets.isEmpty { Text(item.reason).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2) }
            HStack(spacing: 6) {
                if item.copyTargets.count > 1 { Picker("选择网址", selection: $selection) { ForEach(Array(item.copyTargets.enumerated()), id: \.element.id) { offset, target in Text("网址 \(offset + 1)").tag(target.id) } }.labelsHidden().controlSize(.small) }
                if !item.targets.isEmpty {
                    Button(item.gateway ? "网关 Web" : "浏览器访问") { if let target = item.targets.first(where: { $0.id == selection }) ?? item.targets.first { open(target) } }.buttonStyle(.borderedProminent).controlSize(.small).disabled(busy)
                }
                Spacer(minLength: 0)
                Button {
                    guard let value = resourceCopyValue(item, index: selection) else { return }
                    NSPasteboard.general.clearContents()
                    copied = NSPasteboard.general.setString(value, forType: .string)
                    Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
                } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc").foregroundStyle(copied ? Color(nsColor: .systemGreen) : .accentColor) }.buttonStyle(.borderless).help(copied ? "已复制" : "复制网址").accessibilityLabel("复制网址").disabled(resourceCopyValue(item, index: selection) == nil)
            }

        }.padding(10).frame(maxWidth: .infinity, minHeight: height, maxHeight: height, alignment: .topLeading).background(Color(nsColor: .controlBackgroundColor)).clipShape(RoundedRectangle(cornerRadius: 10)).overlay { RoundedRectangle(cornerRadius: 10).stroke(Color(nsColor: .separatorColor), lineWidth: 0.5) }
    }
}
