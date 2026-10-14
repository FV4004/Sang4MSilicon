# Connect beta.17 A/B · 会话更新对照

beta.16 用户实测中，TCP 握手与前期网页数据正常；旧连接丢弃和本机重置计数均为零，后来仍由网关终止。此次测试没有证明旧 TCP 是断连原因。

后台核心每 20 秒请求 `/por/update_session.csp`。原客户端已定位的 JS 调用位于 `cookieSaveLocal`，描述为 TWFID 到 Cookie 的切换，尚未找到每 20 秒作为心跳调用的证据。当前断开时间接近会话建立后 20 秒，但时间相近不能证明因果。本轮只对这一后台请求做 A/B 对照。

| 版本 | 唯一主要变量 |
|---|---|
| v0.5.0-beta.17-a | 停止 TUN 核心的周期 update_session 请求；记录 REFRESH_DISABLED。 |
| v0.5.0-beta.17-b | 保留每 20 秒的原请求，记录 REFRESH_BEGIN、OK/ERROR，以及返回 Cookie/XML 中的 TWFID 是否变化；不记录标识的值，也不应用新的标识。 |

两版均保留 beta.16 的 TCP 会话规则、浏览器入口和完整复制日志，不添加猜测的协议心跳。SDK 的该选项默认关闭（即保留原更新行为），只有 A 的 TUN 客户端明确启用“停止更新”。其他 SDK 调用者及本地代理模式的请求行为不受此实验选项影响。

## 下载与测试

下载对应页 `mac-universal.zip`，解压即完整应用。两版沿用现有应用标识，默认记忆服务器与用户 ID；切换前断开并完全退出另一版，重新登录，后台服务可能要求重新授权。仅临时签名，未公证。

先测试 A，点击此前出错卡片，持续实际使用至少 2 分钟，复制完整日志。然后切换 B、重新登录，重复相同操作并复制日志。分别标记 A/B、资源是否可用和连接持续时间。

若 B 的时间线在 REFRESH_BEGIN/OK 附近出现 SEND_EOF，或出现 REFRESH_COOKIE_CHANGED/REFRESH_BODY_CHANGED，可进一步核对会话切换；即使 A 稳定，仍需持续运行测试验证长期会话是否超时。A 关闭的只是这一 HTTP 请求，保留系统 TCP keepalive；未实现未经确认的私有控制心跳。日志标签不记录请求/响应中的真实 Cookie、TWFID、账户或密码。

## 检查与源码

新增测试确保关闭模式不发送该请求；默认开启模式仍发送原请求，并仅报告会话变化分类而不泄露或改变会话值。macOS 15 CI 运行 Swift、Go race、协议、UTUN、签名、后台服务和界面检查。真实网关和 macOS 26 仍需上述测试，不宣称已修复。

支持 arm64/x86_64、macOS 13+。AGPL-3.0 源码、固定上游源码、许可证、构建信息和 SHA256 同页提供。源码运行 `python3 scripts/prepare-vpn.py` 后，以 `LAB_PROFILE=A` 或 `B` 运行 `python3 scripts/package-native.py` 构建，每个版本使用全新源码目录。
