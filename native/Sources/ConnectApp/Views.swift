import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel
    let closeSettings: () -> Void
    let quit: () -> Void
    private let accent = Color(red: 0.18, green: 0.42, blue: 0.38)
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 24) {
                Image(systemName: "checkmark.shield").font(.system(size: 38)).foregroundStyle(accent)
                Text("连接你的网络").font(.title2.bold())
                Text("安全连接 · 内网分流").foregroundStyle(.secondary)
                Button { model.tab = 0 } label: { Label("账号与连接", systemImage: "person.crop.circle") }.buttonStyle(.plain).foregroundStyle(model.tab == 0 ? accent : .secondary)
                Button { model.tab = 1 } label: { Label("内网资源", systemImage: "square.grid.2x2") }.buttonStyle(.plain).disabled(!model.authenticated).foregroundStyle(model.tab == 1 ? accent : .secondary)
                Spacer()
                Label(model.vpnState == "connected" ? "VPN 已连接" : "VPN 未连接", systemImage: model.vpnState == "connected" ? "checkmark.shield.fill" : "shield").foregroundStyle(model.vpnState == "connected" ? accent : .secondary)
                Text("仅供开源学习与研究").font(.caption).foregroundStyle(.secondary)
            }.padding(28).frame(width: 240).frame(maxHeight: .infinity).background(accent.opacity(0.06))
            VStack(alignment: .leading, spacing: 18) {
                HStack { Text(model.tab == 0 ? "账号认证" : "内网资源").font(.largeTitle.bold()); Spacer(); if model.busy { ProgressView().controlSize(.small) }; Text(model.authenticated ? "认证成功" : "待认证").font(.callout).padding(.horizontal, 14).padding(.vertical, 8).background(accent.opacity(0.1)).clipShape(Capsule()) }
                if model.tab == 0 { connection } else { resources }
                Spacer(minLength: 0)
                Text(model.message).font(.callout).foregroundStyle(.secondary).lineLimit(3).frame(maxWidth: .infinity, alignment: .leading).accessibilityIdentifier("statusMessage")
                Divider()
                HStack { Button("关闭行为设置", action: closeSettings); Spacer(); Button("退出程序", action: quit) }
            }.padding(30).frame(maxWidth: .infinity, maxHeight: .infinity)
        }.frame(minWidth: 960, minHeight: 760).tint(accent)
        .onChange(of: model.server) { _ in model.serverChanged() }
        .onChange(of: model.username) { value in UserDefaults.standard.set(value, forKey: "username") }
        .onChange(of: model.rememberPassword) { _ in model.rememberChanged() }
        .onChange(of: model.selectedGroup) { _ in model.page = 0 }
        .onChange(of: model.search) { _ in model.page = 0 }
    }
    private var connection: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !model.authenticated {
                field("VPN 服务器地址") { TextField("https://vpn.example.com 或 http://vpn.example.com:8080", text: $model.server).textFieldStyle(.roundedBorder).disabled(model.busy || model.challenge) }
                if !model.challenge {
                    field("用户 ID") { TextField("用户名", text: $model.username).textFieldStyle(.roundedBorder).disabled(model.busy) }
                    field("密码") { HStack { SecureField("密码", text: $model.password).textFieldStyle(.roundedBorder); Toggle("记忆密码", isOn: $model.rememberPassword).toggleStyle(.checkbox) }.disabled(model.busy) }
                    if model.requiresCaptcha {
                        field("验证码") {
                            HStack(spacing: 12) {
                                TextField("", text: $model.captcha).textFieldStyle(.roundedBorder).disabled(model.busy)
                                if let image = model.captchaImage { Image(nsImage: image).resizable().scaledToFit().frame(width: 120, height: 38).accessibilityLabel("人机核验验证码") } else { Text("等待验证码").frame(width: 120, height: 38).foregroundStyle(.secondary) }
                                Button { model.refreshCaptcha() } label: { Image(systemName: "arrow.clockwise") }.help("刷新验证码").disabled(model.busy)
                            }
                        }
                    }
                } else { field("动态验证码或应答") { TextField("输入动态验证码", text: $model.response).textFieldStyle(.roundedBorder).disabled(model.busy) } }
                HStack {
                    Button(model.challenge ? "提交验证" : "登录", action: model.login).buttonStyle(.borderedProminent).disabled(model.busy || !model.ready).keyboardShortcut(.defaultAction)
                    if !model.challenge { Button(model.ready ? "重新获取验证码" : "获取登录配置", action: model.initialize).disabled(model.busy || model.server.isEmpty) }
                }
            } else {
                Text("认证成功，可以连接 VPN。").foregroundStyle(.green)
                Button("退出登录会话", action: model.logout).disabled(model.busy)
            }
            Divider().padding(.vertical, 4)
            HStack { Text("VPN 连接").font(.title3.bold()); Spacer(); Text(model.vpnDetail).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            field("连接模式") { Picker("连接模式", selection: $model.mode) { Text("系统 TUN · 内网分流").tag("tun"); Text("本地 SOCKS5／HTTP 代理").tag("proxy") }.labelsHidden().disabled(model.busy || model.vpnState != "disconnected") }
            HStack {
                field("隧道端口") { TextField("443", text: $model.tunnelPort).textFieldStyle(.roundedBorder).disabled(model.busy || model.vpnState != "disconnected") }
                if model.mode == "proxy" {
                    field("SOCKS5 端口") { TextField("1080", text: $model.socksPort).textFieldStyle(.roundedBorder).disabled(model.busy || model.vpnState != "disconnected") }
                    field("HTTP 代理端口") { TextField("1081", text: $model.httpPort).textFieldStyle(.roundedBorder).disabled(model.busy || model.vpnState != "disconnected") }
                }
            }
            Text(model.mode == "tun" ? "首次连接需管理员授权。仅接管网关下发的 IPv4 内网资源；断开后恢复本次路由和 DNS。" : "本地代理监听 127.0.0.1，浏览器和应用需单独设置代理。").font(.caption).foregroundStyle(.secondary).lineLimit(2)
            HStack {
                Button("连接 VPN", action: model.connect).buttonStyle(.borderedProminent).disabled(!model.authenticated || model.busy || model.vpnState != "disconnected")
                Button("断开 VPN", action: model.disconnect).disabled(model.vpnState == "disconnected" || model.vpnState == "stopping")
            }
        }
    }
    private var resources: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Picker("分组", selection: $model.selectedGroup) { Text("全部分组").tag(""); ForEach(model.groups) { Text($0.name).tag($0.id) } }.frame(maxWidth: 240)
                TextField("搜索名称、IP 或域名", text: $model.search).textFieldStyle(.roundedBorder)
                Button { model.refreshResources() } label: { Image(systemName: "arrow.clockwise") }.help("刷新资源列表").disabled(model.busy)
            }
            if model.pageItems.isEmpty { ContentUnavailablePlaceholder() }
            else {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 16) {
                    ForEach(model.pageItems) { item in ResourceCard(item: item, group: model.groups.first(where: { $0.id == item.groupID })?.name ?? "", busy: model.busy, open: { model.open(item, target: $0) }) }
                }
            }
            HStack { Text("\(model.filteredResources.count) 个资源").foregroundStyle(.secondary); Spacer(); Button("上一页") { model.page -= 1 }.disabled(model.page <= 0); Text("\(min(model.page, model.pageCount - 1) + 1) / \(model.pageCount)"); Button("下一页") { model.page += 1 }.disabled(model.page + 1 >= model.pageCount) }.font(.callout)
            Text("普通网页通过系统浏览器访问；网关 Web 资源在独立窗口打开。地址范围和非 Web 资源仅展示。").font(.caption).foregroundStyle(.secondary)
        }
    }
    private func field<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View { VStack(alignment: .leading, spacing: 6) { Text(title).font(.callout.bold()); content() }.frame(maxWidth: .infinity, alignment: .leading) }
}
struct ContentUnavailablePlaceholder: View { var body: some View { VStack(spacing: 12) { Image(systemName: "square.grid.2x2").font(.largeTitle); Text("暂无匹配资源，请刷新或调整筛选条件。") }.foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 380) } }
struct ResourceCard: View {
    let item: VPNResource; let group: String; let busy: Bool; let open: (ResourceTarget) -> Void
    @State private var selection = 0
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(group).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Text(item.name).font(.headline).lineLimit(2).frame(height: 36, alignment: .topLeading)
            Text("地址：" + item.hosts.joined(separator: "；")).font(.callout).lineLimit(2).textSelection(.enabled)
            Text("端口：" + (item.ports.isEmpty ? "默认" : item.ports.joined(separator: "；"))).font(.callout).lineLimit(1).textSelection(.enabled)
            Spacer(minLength: 0)
            if item.targets.count > 1 { Picker("访问地址", selection: $selection) { ForEach(item.targets) { Text($0.label).tag($0.id) } }.labelsHidden() }
            if item.targets.isEmpty { Text(item.reason).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            else { Button(item.gateway ? "打开网关 Web" : "浏览器访问") { if let target = item.targets.first(where: { $0.id == selection }) ?? item.targets.first { open(target) } }.disabled(busy) }
        }.padding(16).frame(maxWidth: .infinity, minHeight: 208, maxHeight: 208, alignment: .topLeading).background(Color.primary.opacity(0.035)).clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
