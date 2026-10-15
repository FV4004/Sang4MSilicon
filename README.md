<p align="center">
  <img src="assets/Connect.png" width="144" height="144" alt="Connect 应用图标">
</p>

<h1 align="center">Connect · M Chip VPN</h1>
<p align="center">macOS 原生网络客户端 · Apple Silicon  · 仅供开源学习与研究</p>

[下载 v0.5.0-beta.22 DMG](https://github.com/FV4004/m-chip-vpn-login/releases/download/v0.5.0-beta.22/Connect-0.5.0-beta.22-mac-universal.dmg) · [发行说明与源码](https://github.com/FV4004/m-chip-vpn-login/releases/tag/v0.5.0-beta.22)

Connect 使用 SwiftUI、AppKit 和 WKWebView 构建界面，使用 Go 辅助程序连接 VPN。发行应用不包含 Electron、Node.js 或 Chromium。蓝色圆角图标以交织路径融合 M 形与网络连接，用于应用、Dock 和 DMG 挂载磁盘。

当前发行源码位于 [`experiment/beta-12-diagnostics`](https://github.com/FV4004/m-chip-vpn-login/tree/experiment/beta-12-diagnostics)，Release 同时提供对应源码 ZIP；默认分支保留此前开发历史。beta.19 的内网访问和持续连接已经用户实测；beta.20 修复密码记忆，beta.21 集成应用图标，beta.22 将同款交织路径用于状态栏并自动适应深浅色，保留这些功能与修复。网关版本及业务系统兼容性仍以实际测试为准。

## 安装与使用

要求 **macOS 13 或更新版本**，支持 Apple Silicon（含 M 系列）与 Intel x86_64。

1. 退出旧版 Connect，下载并打开 DMG，将 **Connect 拖入“应用程序”**；已有旧版时选择替换。
2. 推出磁盘映像，从“应用程序”启动。测试版使用临时签名，尚未进行 Apple Developer ID 签名或公证；若系统阻止打开，请在“系统设置 → 隐私与安全性”按系统提示允许。
3. 输入 HTTP 或 HTTPS 服务器地址、用户 ID 和密码，按网关要求输入验证码或完成后续认证。默认端口为 HTTP 80／HTTPS 443，也支持自定义端口。
4. 认证成功后自动连接 **TUN 内网分流**。首次使用需要 macOS 管理员授权安装后台服务；同版后续连接复用授权，更新程序后可能需要重新授权。管理员密码不保存。
5. 在“内网资源”中按分组查找资源，点击“浏览器访问”或复制地址。正常退出会断开 VPN、清理本次路由与 DNS，并请求结束网关登录会话。

服务器和用户 ID 默认记忆。**密码首次默认不记忆**；勾选并成功登录后，密码保存到 macOS 钥匙串，下次启动保留勾选并恢复密码。取消勾选会删除当前服务器／用户对应的保存项。升级自旧版后请重新勾选一次并成功登录。密码及认证会话不以明文保存到偏好设置；认证会话不落盘。系统可能要求确认钥匙串访问权限。

## 功能

- HTTP／HTTPS 账号登录、图片验证码及网关后续认证步骤；登录失败保留本次输入。
- 原生 IPv4 TUN：仅接管网关下发的资源路由和域名 DNS，不修改默认路由，不接管全流量或 IPv6。
- TUN 出站按下发的 **IP 范围、协议和端口**校验；域名解析只绑定该资源声明的协议／端口，避免将未授权连接转发给网关而触发会话关闭。
- 备选本地 SOCKS5／HTTP 代理：监听 `127.0.0.1:1080`／`127.0.0.1:1081`，需由应用设置代理。SOCKS5 支持 CONNECT，暂不支持 UDP ASSOCIATE。
- 资源分组、搜索、三列连续滚动；卡片默认隐藏网址和端口，并提供复制地址按钮。普通内网 HTTP／HTTPS 通过系统默认浏览器访问，网关代理 Web 资源在临时 WKWebView 会话内访问。
- 状态栏使用与应用同款的单色交织路径图标，由系统适配浅色、深色及菜单选中状态；菜单提供连接 VPN、断开 VPN、显示界面和退出。首次关闭窗口可选择退出或最小化，并记忆选择；最小化保持连接。
- 内置“恢复网络配置”“修复后台服务”和日志复制入口。日志提供匿名流量摘要、校验和状态和访问规则拦截统计，不记录原始数据包内容。

自动单点登录、原生远程应用以及所有网关／业务页面的兼容性尚不保证。HTTP 登录缺少传输加密，协议中的密码字段加密不能替代 HTTPS。

## 网络清理

TUN 使用原生 UTUN 和 macOS IPv4 栈。域名 DNS 使用独立 resolver 文件及回环 DNS 服务，不改写网络服务的全局 DNS；动态解析结果添加对应内网路由。应用仅清理本次创建且内容仍匹配的 DNS 配置，外部改动会保留并提示。

正常退出依次取消进行中的操作、停止 VPN、关闭资源 Web 会话、请求网关注销并清除内存认证。异常中断后可使用“恢复网络配置”；网络离线、强制结束或断电时不能保证远端注销。网络切换后建议断开并重新连接。

## 从源码构建

在安装 Xcode／Command Line Tools 和 Go 1.26.0 的 macOS 上，使用发行标签对应的源码：

```sh
git clone https://github.com/FV4004/m-chip-vpn-login.git
cd m-chip-vpn-login
git checkout v0.5.0-beta.22
(cd native && swift test)
python3 scripts/prepare-vpn.py
(cd vpn-helper && go test -race ./...)
LAB_PROFILE=A python3 scripts/package-native.py
python3 scripts/package-dmg.py
```

输出 `dist-native/Connect.app` 和 `dist-native/Connect-0.5.0-beta.22-mac-universal.dmg`。可用 Xcode 打开 `native/Package.swift` 开发；完整 TUN 应用还需要打包脚本生成的 Go 辅助程序、签名和校验文件。

[GitHub Actions](https://github.com/FV4004/m-chip-vpn-login/actions/workflows/diagnostic.yml) 在 macOS 上运行 Swift、Go race、原生 UTUN、签名、后台服务和界面检查；图标转换后检查所有标准分辨率，DMG 实际挂载后检查磁盘图标、应用签名及可执行文件哈希。云端检查不能代替真实网关和用户设备测试。

## 源码与许可

项目采用 [AGPL-3.0-only](LICENSE)。协议 helper 使用 [zju-connect](https://github.com/Mythologyli/zju-connect)，固定提交 `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63`，保留上游许可和署名。构建脚本验证下载归档并应用项目补丁；发行包不包含厂商 DMG 中的二进制或私有脚本。

Release 提供本项目源码 ZIP、固定上游及 compress 1.18.6 源码、构建信息和 SHA256 校验。完整组件署名见[组件说明](app/THIRD_PARTY_NOTICES.md)。原始应用图标位于 [`assets/Connect.png`](assets/Connect.png)，由构建脚本转换成 macOS ICNS。
