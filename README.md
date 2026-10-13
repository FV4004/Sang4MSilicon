# M Chip VPN · 0.3.0-beta.1

仅供开源学习与研究的 macOS arm64 网络客户端。支持 HTTP／HTTPS 账号认证、服务器图片验证码、原生 IPv4 TUN 分流和本地 SOCKS5／HTTP 代理。账号认证已由用户验证；此版的数据通道与用户网关兼容性仍需实际测试。

## 使用

1. 从 Release 下载 `MChipVPNLogin-0.3.0-beta.1-mac-arm64.zip`，解压并放入“应用程序”。要求 macOS 13+。
2. 输入 HTTP 或 HTTPS 服务器地址；省略端口使用 80／443。应用只记忆服务器地址，下次打开自动获取验证码；账号、密码及认证会话不写入配置文件。登录失败保留本次输入。
3. 认证后默认选择“系统 TUN · 内网分流”，点击连接并完成 macOS 管理员授权。数据隧道端口通常是 443，独立于 HTTP 登录端口。
4. 界面显示系统接口、虚拟 IP 和资源数量后，应用可以直接访问授权的 IPv4 内网资源，无需设置代理。
5. 断开、退出登录或退出应用会先结束隧道并清理本次网络设置。

TUN 首版只支持 IPv4 与网关资源分流，不修改默认路由，不接管全流量或 IPv6。需要网关支持 L3 数据通道；仅有 TCP 资源通道的网关可选择本地代理。动态资源域名的 IPv4 解析结果会添加对应路由。既有同名 DNS 配置或重复路由存在冲突时会停止连接，不覆盖其他网络工具的设置。

代理备选模式不需要管理员权限；默认 SOCKS5 `127.0.0.1:1080`、HTTP `127.0.0.1:1081`。SOCKS5 支持 CONNECT，暂不支持 UDP ASSOCIATE；HTTP 支持普通 HTTP 与 HTTPS CONNECT。使用 SOCKS5 时应由代理解析域名。

## 网络设置与恢复

管理员 helper 安装到 `/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-helper`，通过 SHA-256 和代码签名检查复制件。每次连接使用受保护的 Unix socket，核对对端 UID 后接收内存中的会话；会话不进入命令行、环境变量或配置文件。helper 退出、socket EOF、取消或隧道异常都会触发清理。

TUN 使用原生 UTUN 和系统 IPv4 栈，TCP／UDP／ICMP 均由实际 L3 通道传输。网关连接固定使用建立 TUN 前的 IPv4 地址与出口接口，避免路由回环。网络切换后需手动断开重连。

DNS 只在 `/private/etc/resolver` 为下发域名创建独立 resolver 文件，指向回环 DNS 服务；不改变网络服务的全局 DNS。DNS 服务仅接受资源域名，使用网关下发 DNS，不回退到公共 DNS。首版对资源域名的 AAAA 查询返回空记录。

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
