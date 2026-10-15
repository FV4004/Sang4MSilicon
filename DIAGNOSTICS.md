# Connect v0.5.0-beta.21 · 全新应用图标

采用已确认的蓝色圆角图标，交织路径融合 M 形和网络连接。内置 16–1024 像素的 macOS ICNS，应用、Dock 和 Finder 使用新图标；DMG 挂载磁盘也使用对应图标。状态栏继续采用适应系统深浅色的单色连接状态图标。

保留 beta.19 的 TUN IP／协议／端口资源规则及 beta.20 的钥匙串密码记忆修复。用户已验证 beta.19 可持续访问内网资源；本版没有改动 VPN 协议和路由逻辑。

## 安装

退出旧版 Connect，下载 `Connect-0.5.0-beta.21-mac-universal.dmg`，打开后将 Connect 拖入“应用程序”替换旧版，推出磁盘映像，再从“应用程序”启动。首次使用密码记忆请勾选并成功登录，下次启动恢复选项和钥匙串密码。

DMG 仍采用临时签名，未做 Developer ID 签名／公证；首次打开可能需要在“系统设置 → 隐私与安全性”按系统提示允许。系统如请求钥匙串访问权限，请按提示授权。

## 验证与源码

macOS CI 运行 40 项 Swift 测试、Go race、UTUN、签名、后台服务和界面检查。图标会转换回 iconset 核对全部标准分辨率，应用 smoke 验证 ICNS 可解码；DMG 验证只读挂载、磁盘图标及 Finder 标记、应用签名和可执行文件 SHA256。

支持 Apple Silicon／Intel、macOS 13+。原始图标位于 `assets/Connect.png`，同页提供 AGPL-3.0 源码、固定上游源码、构建信息和 SHA256。仓库 README 同步更新图标、当前功能和下载说明。
