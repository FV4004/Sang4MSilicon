# 0.1.0-beta.2

- 登录地址同时支持 HTTP 和 HTTPS。
- 省略端口时自动使用 HTTP 80 / HTTPS 443；支持自定义端口。
- HTTPS 验证服务器证书，对不受信任、过期或地址不匹配的证书提示失败。
- 仅使用 HTTP 时显示明文传输提示。
- 增加 HTTPS 认证、Cookie、验证码和证书错误测试。

仍为认证测试版，未实现 VPN 数据隧道，未做 Apple Developer ID 签名或公证。

# 0.1.0-beta.1

Apple Silicon HTTP 网关认证测试版：

- HTTP 服务器地址、端口、用户名和密码输入。
- 网关图片验证码获取、展示、刷新及同会话提交。
- 兼容 EasyConnect 7.6.7 的 RSA 密码字段、XML 响应与 Cookie 会话。
- 显示认证失败、超时、后续认证及认证成功状态。
- 认证成功后可以退出登录会话。

本版本只验证认证，不建立 VPN 数据隧道。没有 Apple Developer ID 签名和公证。已通过 12 项模拟网关测试；真实网关和 M 芯片 Mac 运行验证待完成。
