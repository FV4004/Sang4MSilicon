# 开源许可与源码

M Chip VPN 0.2.0-beta.1 采用 GNU Affero General Public License v3.0（AGPL-3.0-only）；没有担保。用户可以按该许可复制、修改和重新分发。完整许可见同目录 LICENSE。

VPN helper 复用 Mythologyli/zju-connect（及原 EasierConnect）的 EasyConnect 数据通道、DNS、资源规则与用户态网络栈，固定提交 `c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63`。

- 上游源码：https://github.com/Mythologyli/zju-connect/tree/c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63
- 本项目源码与构建脚本：https://github.com/FV4004/m-chip-vpn-login
- Release 同时提供本项目源码 ZIP、固定上游源码及 compress 1.18.6 源码归档；取得测试包的用户可以取得这些对应源码。

本项目增加桌面会话到 helper 的 stdin 桥接、进程清理、监听/转发层，并修改上游以保持 TLS 证书验证和补充 token/IP 响应长度检查。修改均由 scripts/prepare-vpn.py 重现。未将厂商二进制或私有源码打包。

其他组件包括 Electron/Chromium、fast-xml-parser、tough-cookie、gVisor（Apache-2.0）、uTLS（BSD-3-Clause）、klauspost/compress（BSD-3-Clause）及其他 Go 依赖；各自许可保留在依赖源代码中。Electron 自带许可与 Chromium notices 位于发行目录。完整 Go 依赖版本由 vpn-helper/go.mod 与 go.sum 锁定。
