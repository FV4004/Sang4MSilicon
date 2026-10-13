# M Chip VPN Login · 0.1.0-beta.2

面向 Apple Silicon 的 macOS HTTP / HTTPS 认证测试客户端，依据用户提供的 EasyConnect 7.6.7 安装包中实际 SDK 调用实现。提供服务器地址、用户名、密码、网关图片验证码、刷新与认证结果反馈。**认证成功不代表 VPN 已连接：本版本未实现 VPN 数据隧道。**

## 使用

1. 解压发布包，把 `M Chip VPN Login.app` 拖到“应用程序”。
2. 输入 `https://服务器` 或 `http://服务器`（可指定自定义端口），点击“获取验证码”。地址应为网关根地址，不是登录网页完整路径。省略端口时 HTTP 使用 80、HTTPS 使用 443。HTTPS 保持证书校验，证书过期、地址不匹配或不受信任时会提示失败。
3. 输入用户名、密码及服务器图片中的验证码，点击“登录”。不要求图片验证码的网关会隐藏该输入区域。
4. 服务器要求后续令牌/RADIUS/短信/TOTP 时，受支持的步骤显示应答输入；无法支持的证书或设备认证会明确提示，不能绕过这些检查。
5. “认证成功”后可以退出登录会话。本程序不会添加 VPN 路由或宣称已建立隧道。

验证码来自网关，沿同一个 Cookie 会话核验；不是客户端自制的图片。密码仅留在当前认证过程内存，不写入配置或日志。HTTP 不提供传输加密，即使采用兼容的 RSA 密码字段加密，会话、其他字段和服务器响应仍缺少 HTTPS 的传输保护。

本版本没有 Apple Developer ID 证书或公证。macOS Actions 产物进行 ad-hoc 临时签名，它不代表 Apple 身份签名或公证。按 macOS 正常的“隐私与安全性”设置处理来源提示。Linux 直接打包产物未在真实 Mac 上签名或运行，优先使用经过 macOS Actions 处理的发布产物。

## 构建

依赖锁文件已提交。Node.js 24；Electron 44.7.0；无客户端原生 addon。

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm ci --ignore-scripts --no-audit --no-fund --prefix app
npm test
npm run package:mac
```

`package:mac` 使用官方 Electron darwin-arm64 运行时与自有应用源码组装 `.app`，不重新编译 Electron/Chromium。可以在 Linux 下载并打包；macOS 签名、平台验证和发布由 `.github/workflows/beta.yml` 完成。

本地开发可运行 `npm start`，首次启动会下载对应宿主架构的 Electron 44.7.0。发行打包使用 macOS arm64 runtime，不依赖开发机运行时。

## GitHub 云端发布

上传此目录的源代码到用户指定仓库后：

- 手动运行 `macOS arm64 beta`：测试、打包、arm64 验证、临时签名，生成 Actions artifact。
- 首次推送 `main`：同一流程通过后自动创建 `v0.1.0-beta.2` GitHub prerelease，附件含 macOS arm64 ZIP、SHA256SUMS.txt 与构建元数据。
- 后续发行需更新项目版本及工作流中的发行版本，避免覆盖已发布标签。

工作流无需 Apple 签名 secrets。发布 job 仅使用该仓库 Actions 自动提供的 GitHub token。

## 协议实现与测试

`app/auth.cjs` 使用以下调用流程：`/por/login_auth.csp` → `/public/psw_config` → `/por/rand_code.csp`（按需）→ `/por/login_psw.csp?anti_replay=1&encrypt=1` → 必要后续认证 → `/por/update_session.csp`。服务端 XML 和 Cookie 保存在主进程；UI 不接触 TwfID 或会话 Cookie。

密码字段兼容 `RSA PKCS#1 v1.5(password + "_" + CSRF_RAND_CODE)`，十六进制密文。缺少公钥或随机码时停止请求，不发送明文密码回退。请求默认追加 `apiversion=1`，表单使用 application/x-www-form-urlencoded。

14 项本地模拟网关测试已通过：地址校验、RSA 解密对应性、防重放字段、XML 异常、Cookie 与会话同步、验证码刷新/错误、无验证码网关、后续认证、未知认证、跨地址重定向拦截、超时、HTTPS 登录及不受信任证书拒绝。未获得真实网关地址与授权测试记录，尚未完成真实网关、M5 Pro UI 和端到端 VPN 连接验证。

## 与逆向分析结果的关系

本项目重新实现认证流程，不打包用户上传的厂商客户端、x64 原生后台、旧内核扩展或其专有 JS 代码。网关配置和认证方式可能随版本不同。用户输入 HTTP / HTTPS 地址可在客户端本机访问，不依赖云端连通该 VPN 内网。
