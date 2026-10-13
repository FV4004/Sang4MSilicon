# macOS 原生 Swift 客户端（迁移分支）

此分支 `feature/swift-native` 基于资源集成版提交 `8039c4bf1a86cc194d6375fb598058b6c7751461`，将发行应用迁移为 SwiftUI／AppKit／WKWebView。原 Electron 源码保留供协议对照，原生发行包不包含 Electron、Node.js 或 Chromium。VPN 转发仍使用现有 Go 辅助程序，内网分流策略不变。

## 原生功能

- HTTP／HTTPS 登录、会话 Cookie、RSA PKCS#1 防重放密码加密、图片验证码和动态验证步骤。
- 默认记忆服务器及用户 ID；每次启动密码记忆默认关闭，手动勾选后才读取或保存 macOS 钥匙串密码。失败后保留用户输入；服务器地址编辑期间不自动验证，结束编辑或按回车后获取配置，启动时对已记忆地址自动获取验证码。原 Electron 保存的密码不会自动导入。
- 分组、资源名称、IP／域名与端口展示，分组筛选和搜索，三列连续滚动、每屏约三行；卡片隐藏网址并提供复制按钮；普通 HTTP／HTTPS 在 TUN 连通后通过默认浏览器打开；网关 Web 在临时 WKWebView 会话内打开。自动 SSO 和原生远程应用启动仍不支持。
- 最终认证成功后自动连接 TUN。系统状态栏图标与连接状态，菜单提供连接 VPN、断开 VPN、显示界面、关闭行为设置和退出程序。未登录时点击连接会显示登录界面。
- 首次关闭窗口可选择最小化、退出或取消，并记忆选择；最小化保留 VPN，显式退出不受此设置影响。
- 正常退出先取消进行中的操作，再断开 TUN、恢复本次路由／DNS、请求网关注销并清理内存认证及 Web 会话。网关离线或系统清理失败会显示提示；强制结束和断电不能保证远程注销。
- Universal 2：应用和辅助程序均支持 arm64 与 x86_64；macOS 13 及以上。首次授权安装系统后台服务，同版后续连接复用；更新代码需要重新授权。服务仅接受指定用户及当前客户端签名，VPN 工作进程在断连后退出，后台服务空闲时不保留认证会话或网络接管。管理员密码不保存。

## 构建与验证

在安装 Xcode／Command Line Tools 和 Go 1.26.0 的 macOS 上运行：

```sh
cd native
swift test
cd ..
python3 scripts/prepare-vpn.py
(cd vpn-helper && go test -race ./...)
python3 scripts/package-native.py
```

输出 `dist-native/Connect.app`。可用 Xcode 打开 `native/Package.swift` 开发，但完整应用打包及 Go 辅助程序仍使用脚本。单独运行 SwiftPM 可验证界面；TUN 需要完整包内辅助程序与校验文件。

`.github/workflows/native.yml` 运行 Swift 协议测试、Go 回归、原生 UTUN 测试及主窗口／状态栏菜单 smoke，构建两个架构并验证签名与校验。测试包只有临时签名，未做 Developer ID 签名与公证。真实网关认证、管理员授权和 WebKit 页面兼容性需要安装测试。

源码使用 AGPL-3.0，随发行版包含本项目及所用 Go 上游的源码和许可证。

---

以下为保留的 Electron 版本开发说明：

# M Chip VPN · 0.4.0-beta.1

仅供开源学习与研究的 macOS arm64 网络客户端。支持 HTTP／HTTPS 账号认证、服务器图片验证码、原生 IPv4 TUN 分流和本地 SOCKS5／HTTP 代理。账号认证已由用户验证；此版的数据通道与用户网关兼容性仍需实际测试。

## 使用

1. 从 Release 下载 `MChipVPNLogin-0.4.0-beta.1-mac-arm64.zip`，解压并放入“应用程序”。要求 macOS 13+。
2. 输入 HTTP 或 HTTPS 服务器地址；省略端口使用 80／443。应用默认记忆服务器地址与对应用户 ID，下次打开自动回填并获取验证码。密码默认不记忆；勾选“记忆密码”后，提交登录时使用 macOS 钥匙串支持的 Electron safeStorage 加密保存，绑定服务器与用户 ID。取消勾选立即删除已保存的加密密码。登录失败保留本次输入，认证会话不落盘。
3. 认证成功后自动建立“系统 TUN · 内网分流”，首次连接完成 macOS 管理员授权，同版后续连接复用。数据隧道端口通常是 443，独立于 HTTP 登录端口。
4. 界面显示系统接口、虚拟 IP 和资源数量后，应用可以直接访问授权的 IPv4 内网资源，无需设置代理。
5. 断开、退出登录或退出应用会先结束隧道并清理本次网络设置。

TUN 首版只支持 IPv4 与网关资源分流，不修改默认路由，不接管全流量或 IPv6。需要网关支持 L3 数据通道；仅有 TCP 资源通道的网关可选择本地代理。动态资源域名的 IPv4 解析结果会添加对应路由。既有同名 DNS 配置或重复路由存在冲突时会停止连接，不覆盖其他网络工具的设置。

代理备选模式不需要管理员权限；默认 SOCKS5 `127.0.0.1:1080`、HTTP `127.0.0.1:1081`。SOCKS5 支持 CONNECT，暂不支持 UDP ASSOCIATE；HTTP 支持普通 HTTP 与 HTTPS CONNECT。使用 SOCKS5 时应由代理解析域名。

## 网络设置与恢复

管理员 helper 安装到 `/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-helper`，通过 SHA-256 和代码签名检查复制件。每次连接使用受保护的 Unix socket，核对对端 UID 后接收内存中的会话；会话不进入命令行、环境变量或配置文件。helper 退出、socket EOF、取消或隧道异常都会触发清理。

TUN 使用原生 UTUN 和系统 IPv4 栈，TCP／UDP／ICMP 均由实际 L3 通道传输。网关连接固定使用建立 TUN 前的 IPv4 地址与出口接口，避免路由回环。网络切换后需手动断开重连。

DNS 只在 `/private/etc/resolver` 为下发域名创建独立 resolver 文件，指向回环 DNS 服务；不改变网络服务的全局 DNS。DNS 服务仅接受资源域名，使用网关下发 DNS，不回退到公共 DNS。没有可用网关 DNS 时仅安装静态域名记录的 resolver，并保留 IPv4 资源路由，界面明确显示域名访问限制；无效规则被跳过时也显示提示。网关 DNS 与数据网关地址相同时不建立冲突的 DNS 路由。首版对资源域名的 AAAA 查询返回空记录。

DNS 分流最多支持 16,384 个有效域；父域已经覆盖的子域合并到同一 resolver。完整恢复计划在创建文件前一次写入，批量安装支持取消，域名查找按标签索引。

关闭 UTUN 会删除该接口及其关联路由。恢复日志保存在 root 所有的 `/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-state/resolver-lease.json`，仅记录本次创建的 DNS 文件与内容，不含认证信息。异常退出或重启后，界面提供“恢复上次网络配置”；管理员授权恢复完成后再自动获取验证码。仅删除内容仍匹配记录的文件，外部改动会明确报错并保留记录。

界面铺满初始窗口，使用沉浸标题栏，无滚动条；认证成功后切换为连接面板。商业 VPN 品牌文案不出现在应用界面。组件署名和完整许可保留在独立源码文件中。

## 构建与验证

Node.js 24、Go 1.26.0、Electron 44.7.0。

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm ci --ignore-scripts --no-audit --no-fund --prefix app
python3 scripts/prepare-vpn.py
npm test
cd vpn-helper
go test -race ./...
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o ../.build/mchip-vpn-helper .
cd ..
npm run package:mac
```

Actions 在 macOS 上执行 Node／Go 回归测试、原生 UTUN 注入数据包与接口关闭检查、引擎测试、arm64 编译、临时签名与包内源码/最终 helper 哈希校验。UTUN smoke test 只在隔离的 CI runner 通过明确环境开关以 root 运行，不在普通本地测试中自动修改网络。

本地界面预览检查了初始和最小窗口的登录、TUN、代理状态，控件未被裁切且无滚动。云端验证不能代替用户实际网关的内网访问测试，也未验证真实 Mac 的管理员弹窗体验。

没有 Apple Developer ID 签名或 Apple 公证。HTTPS 登录及数据通道验证服务器证书。HTTP 登录缺少传输加密；协议兼容的密码字段加密不能替代 HTTPS。

## 源码与许可

本项目采用 AGPL-3.0-only。协议 helper 复用 [zju-connect](https://github.com/Mythologyli/zju-connect)，固定提交 `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63`，保留上游许可与署名。构建脚本检查下载归档 SHA-256 并应用证书验证和响应边界补丁。

Release 提供本项目源码 ZIP、固定上游源码及 compress 1.18.6 源码归档。依赖版本见 module／npm 锁文件，完整署名见 [组件说明](app/THIRD_PARTY_NOTICES.md)。不打包厂商 DMG 中的二进制或私有脚本。

## 账号记忆

`server.json` 保存服务器地址；`account.json` 保存最近一组服务器和用户 ID，以及用户勾选后的加密密码。配置文件原子替换并使用 0600 权限。加密内容内部同时绑定服务器地址和用户 ID，修改外部元数据不能导致跨服务器回填密码。macOS 钥匙串保存加密密钥，密码文件只有密文；系统安全存储不可用时不使用明文回退，登录仍可进行。

用户 ID 在离开输入框或提交登录时记忆。密码只在勾选且提交登录时保存；服务端拒绝认证不改变本次输入。退出登录清理界面中的密码，但保留用户明确选择的加密记忆项。取消“记忆密码”删除该项。启动恢复密码时，macOS 可能要求确认钥匙串访问。

## 资源目录集成分支

本版位于 `feature/resource-catalog-and-lifecycle`，不合并到 main。登录后自动获取网关资源 XML，增加“内网资源”页：按分组、名称、地址与端口展示，支持搜索、刷新、多地址选择和分页；不使用滚动条。IP 范围、非网页协议和需要自动单点登录的资源显示限制说明。

普通内网 HTTP／HTTPS 资源在系统 TUN 连接后通过默认浏览器打开。网关 Web 代理资源采用原客户端的 `/web/{filter}/{http|https}/0/{目标}` 转换（含可选 `/safeurl`），由网关 shortcut 接续会话，在独立的 Chromium 浏览窗口中打开。该窗口使用无持久化的会话分区、无 privileged preload，关闭 Node 集成并启用隔离与 sandbox；认证数据不会传给系统浏览器。携带会话的 shortcut URL 仅用于内存中的浏览导航，不写入应用配置、应用日志或外部浏览器历史。包含会话参数的 Referer 被去除。

资源请求使用登录服务器同一主机的 HTTPS 数据端口，端口取“隧道端口”设置。证书继续验证；macOS 同时使用系统信任根证书。资源打开由主进程按当前目录中的 opaque key 解析，界面不能传入任意 URL。网页内容与业务系统登录由网关负责，不承诺自动凭据填充、远程应用或所有网关版本的页面兼容性；实际用户网关尚需测试。

## 关闭、最小化和退出

首次点击主窗口关闭按钮会询问“退出程序 / 最小化”，并提供“记住此选择”。取消保持原状。选择最小化保持 TUN 和登录会话；点击 Dock 图标可恢复窗口。“关闭方式”可重新设置记忆项。显式“退出程序”、Cmd+Q 或系统 Quit 始终执行退出，不受记忆的最小化选项影响。

退出顺序：停止进行中的认证操作，关闭资源浏览窗口并清理浏览会话，结束 VPN/TUN 并等待路由与 DNS 清理，向网关 POST `/por/logout.csp`，清除本地认证信息，刷新偏好设置后退出。清理失败也会继续尝试网关注销并提示具体未确认的步骤。网络离线或网关拒绝请求时，不能保证远端会话已注销，但本地会话仍会清理；异常网络恢复记录继续保留。

验证包括资源 XML／分组／类型解析、URL 转换与查询参数保留、浏览会话隔离、来源检查、关闭行为记忆、显式退出顺序、注销失败后本地清理，以及既有登录和 TUN 回归测试。界面在初始和最小窗口尺寸下已检查，资源卡片分页完整显示。管理员弹窗、真实网关资源按钮和网关注销仍需 Mac 用户实际验证。
