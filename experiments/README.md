# Sang4MSilicon 历史实验记录

以下为更名前的 Connect beta.11 实验资料。对应旧预发布现已转为草稿；当前正式版请从[仓库首页](../README.md)进入。历史版本的应用名称、文件名和操作命令仅用于复现，不代表当前发行版。

# Connect beta.11 A/B/C 兼容性实验

三个版本均以 v0.5.0-beta.10 为基线，仍使用 L3IP；未实现原客户端的 IPCP 私有传输。

| 版本 | 实验内容 |
|---|---|
| 0.5.0-beta.11-a | 对照组，仅增加首次隧道 I/O 中断方向和固定错误分类。 |
| 0.5.0-beta.11-b | 在 A 上使用 MTU 1280、SYN MSS 上限 1200，并修复完整 IPv4/TCP/有校验和 UDP 包的校验和；不改分片传输层。 |
| 0.5.0-beta.11-c | 在 A 上完整读取令牌请求的两条 HTTP 响应后再关闭连接，每条响应上限 2 MiB。 |

从对应 Release 下载 mac-universal.zip，解压即得完整 Connect.app，不再运行 Repackage.command。arm64 与 x86_64 核心分别签名后使用 Apple lipo 合并；完整应用进行严格签名校验。未使用 Developer ID 签名或公证，macOS 仍可能拦截下载应用。

三版使用独立应用标识和偏好设置。一次只运行一个版本，切换前断开 VPN 并完全退出，使用新登录会话。切换版本时可能需要重新授权安装后台服务，不保存管理员密码。

建议顺序 A → B → C，记录内网访问是否保持连接、出错前的操作和完整错误。首次错误使用 LAB_A/B/C 前缀；不记录凭据、会话、网址或数据包内容。测试环境无法访问你的实际网关，自动检查通过不代表已解决真实网关的断连。macOS CI 为 macOS 15，macOS 26 安装及访问仍需实际测试。

源码复现：从对应 source.zip 新解压一份完整源码，运行 `python3 scripts/activate-experiment.py A`（或 B、C），再运行 `python3 scripts/prepare-vpn.py`、`swift test --package-path native`；在 macOS 安装 Go 1.26 和 Xcode 命令行工具后，运行 `LAB_PROFILE=A python3 scripts/package-native.py`。每个版本必须使用全新源码目录，避免不同 overlay 混用。压缩库和协议上游固定源码归档、补丁、许可证随 Release 提供。
