# M Chip VPN · 0.2.0-beta.2

Apple Silicon 原生架构的 EasyConnect 兼容测试客户端。账号认证已由用户在实际网关验证；本版新增基于 EasyConnect 传统数据通道的本地 SOCKS5／HTTP 代理，真实网关的数据访问兼容性仍需用户测试。

## 使用

1. 下载 Release 中 `MChipVPNLogin-0.2.0-beta.2-mac-arm64.zip`，解压后将应用放入“应用程序”。支持 macOS 13+。
2. 输入 `http://服务器` 或 `https://服务器`，在密码下方获取验证码并完成账号认证。应用默认只保存服务器地址；再次打开后自动获取验证码。输入框位于验证码图片左侧，图片旁可刷新。登录失败保留本次输入的账号、密码；它们不会写入配置文件。省略登录端口时分别使用 80／443，也可以指定其他端口。
3. 认证成功后点击“连接 VPN”。隧道端口独立于 HTTP 登录端口，通常为 443；HTTPS 自定义登录端口会作为默认隧道端口，也可手动修改。
4. 等待界面显示代理已连接。默认代理地址：
   - SOCKS5：`127.0.0.1:1080`
   - HTTP：`127.0.0.1:1081`
5. 在浏览器或应用中配置其中一种代理，再访问授权内网资源。使用 SOCKS5 时应让代理解析域名，例如 Firefox 的“使用 SOCKS v5 时代理 DNS”。HTTP 代理同时支持普通 HTTP 和 HTTPS CONNECT。
6. 点击“断开连接”停止代理，认证会话保留；退出登录或退出应用会先停止代理，再清理本地会话。

本版不修改系统代理、虚拟网卡、路由或 DNS；不需要管理员权限。代理使用网关下发的资源与 DNS 规则；非 VPN 资源可能直连，不是全流量代理。SOCKS5 本版仅支持 CONNECT，不支持 UDP ASSOCIATE；VPN L3 为 IPv4。网关若只提供 TCP 资源通道，会显示 TCP 按需建连模式，不虚构虚拟 IP。

可用 curl 验证（将地址替换为你有权限访问的内网目标）：

```bash
curl --proxy http://127.0.0.1:1081 http://内网目标/
curl --socks5-hostname 127.0.0.1:1080 https://内网目标/
```

## 连接行为

保留已验证的 HTTP／HTTPS + 验证码 + RSA + Cookie 登录。认证完成后，主进程将 TwfID 仅通过 helper stdin 传入；不重复输入密码，不在命令行、环境变量或磁盘保存认证会话。

VPN helper 获取数据通道令牌和网关资源，申请虚拟 IP，建立收发通道，并接入用户态 IPv4 网络栈。L3 模式只有在两条数据通道握手成功且本地监听就绪后才报告连接。TCP 模式显示按需建连状态；具体资源连接发生在代理请求时。

HTTP 与 HTTPS 登录均支持。HTTPS 与数据通道保持证书验证；不自动跳过不受信任证书。HTTP 不提供传输加密，即使密码字段使用兼容 RSA 加密，认证会话和其他字段仍缺少 HTTPS 的传输保护。数据通道使用厂商兼容的旧 TLS 协议，与登录地址是否 HTTP 分开处理。

辅助进程固定只监听回环地址。本地端口可调整，范围 1024—65535；端口占用、连接超时、证书错误、helper 异常退出会显示明确失败，不会继续显示已连接。取消、断开和退出会终止进程；不会自动修改系统网络。

## 构建与发布

Node.js 24、Go 1.26.0、Electron 44.7.0。应用和 VPN helper 都打包为 macOS arm64。

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

`prepare-vpn.py` 下载固定提交并检查归档 SHA-256，重现证书验证和会话/响应长度补丁。锁文件、补丁与 helper 源码均在仓库中。macOS Actions 验证两份可执行文件的 arm64 架构，并进行 ad-hoc 临时签名后生成发布包。没有 Apple Developer ID 签名或公证。

本地开发使用原生 helper 放在 `app/bin/mchip-vpn-helper`，再运行 `npm start`。Linux 可以运行协议/代理测试和交叉编译 helper，不能代替真实 Mac 运行验证。

## 验证范围

- 35 项 Node 测试：认证、验证码、RSA、TLS、会话刷新、代理生命周期，以及地址记忆、自动获取验证码、失败保留输入和密码不落盘。
- 6 项 Go 测试（race 检查）：配置校验、SOCKS5 转发、HTTP 转发、HTTPS CONNECT、提前缓冲的数据及代理凭证隔离。
- 复用引擎的 EasyConnect 客户端、gVisor 栈、DNS 与分流测试通过。
- helper 已交叉编译为真实 Mach-O arm64；打包后的应用源码与工作区源码逐项验证一致。

这些测试使用本地模拟连接。未取得用户网关的数据通道测试结果，不能保证当前网关支持相同旧协议，也没有宣称实际内网访问已经验证。官方 DMG 中另一套原生私有封包形态仍是研究线索；本版采用开源社区已实现的 EasyConnect 传统 L3／TCP 兼容路径。

## 开源组件与对应源码

本项目采用 AGPL-3.0-only。VPN helper 复用 [zju-connect](https://github.com/Mythologyli/zju-connect)，固定提交 `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63`，原始项目基于 EasierConnect。保留上游许可和署名，使用公开源码，不打包上传 DMG 中的厂商二进制或私有 JS。

Release 同时附带本项目源码 ZIP、固定上游源码和 compress 1.18.6 源码归档；构建脚本和 Go module 锁文件给出其余依赖的准确版本。完整许可见 LICENSE 与 [组件说明](app/THIRD_PARTY_NOTICES.md)。
