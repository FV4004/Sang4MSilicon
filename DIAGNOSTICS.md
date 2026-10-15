# Sang4MSilicon · 正式 Release

项目由 Connect／M Chip VPN 更名为 **Sang4MSilicon**。应用显示名称、侧栏、窗口与悬停提示、DMG 磁盘名称及下载文件名已统一更新；沿用蓝色应用图标和适应深浅色的单色状态栏图标。

本次将最后一版 `v0.5.0-beta.22` 取消预发布标记并设为最新正式 Release，保留原标签以免破坏已有引用。更名安装包重新构建，精确源码提交见本页构建链接及 `build-info.json`；原标签仍指向更名前的历史提交。此前预发布转为草稿，仅隐藏发行入口，不删除历史标签和文件。

## 安装与升级

下载 `Sang4MSilicon-0.5.0-beta.22-mac-universal.dmg`，退出旧版，将 Sang4MSilicon 拖入“应用程序”，推出磁盘后启动。如果旧应用名为 `Connect.app`，请退出后删除旧应用，避免启动两个版本。

保留原 Bundle ID、钥匙串服务和后台服务标识，已有服务器、账号、密码记忆与网络恢复记录可以继续使用；更新签名后系统可能重新请求管理员或钥匙串授权。VPN 协议、IP／协议／端口资源访问规则及路由逻辑保持不变。

支持 macOS 13+、Apple Silicon／Intel。正式 Release 表示发行状态，安装包仍为临时签名、未做 Developer ID 签名或 Apple 公证；首次打开可能需要在“系统设置 → 隐私与安全性”按提示允许。

macOS CI 验证 Swift、Go race、UTUN、签名、后台服务、状态栏深浅色模板和 DMG 挂载。AGPL-3.0 源码、固定上游源码、许可证、构建信息和 SHA256 同页提供。
