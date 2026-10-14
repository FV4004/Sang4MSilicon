import XCTest
import AppKit
@testable import ConnectApp

final class FeedbackLogTests: XCTestCase {
    @MainActor func testCopyKeepsFullMultilineDiagnosticDespiteDisplayTruncation() {
        let board = NSPasteboard.withUniqueName()
        defer { board.releaseGlobally() }
        let full = "网关主动终止了数据会话。\nLAB_A_TUN_SERVER_SHUTDOWN_FIRST_SEND_DATA_BROKEN_PIPE\nD12 " + String(repeating: "timeline=SEND_EOF@8131ms,", count: 80)
        XCTAssertTrue(FeedbackLog.copy(full, to: board))
        XCTAssertEqual(board.string(forType: .string), full)
    }
    func testOnlyLoginSuccessAndEmptyMessagesHideCopy() {
        XCTAssertFalse(FeedbackLog.canCopy("认证成功", loginSucceeded: true))
        XCTAssertFalse(FeedbackLog.canCopy(" \n", loginSucceeded: false))
        for text in ["认证失败", "密码保存失败", "正在连接", "VPN 已连接", "网络配置已恢复", "D12 tx_try=7 tx_ok=6"] {
            XCTAssertTrue(FeedbackLog.canCopy(text, loginSucceeded: false))
        }
    }
    func testResourcePageReportKeepsVPNFailureAndOmitsLoginSuccess() {
        let vpn = "VPN 隧道中断\nD12 tx_try=7 tx_ok=6 timeline=SEND_EOF@8131ms"
        XCTAssertEqual(FeedbackLog.report(message: "认证成功", loginMessage: "认证成功", loginSucceeded: true, vpnDetail: vpn), vpn)
        XCTAssertEqual(FeedbackLog.report(message: "资源加载失败", loginMessage: "认证成功", loginSucceeded: true, vpnDetail: vpn), "资源加载失败\n\n" + vpn)
        XCTAssertEqual(FeedbackLog.report(message: vpn, loginMessage: "认证成功", loginSucceeded: true, vpnDetail: vpn), vpn)
    }
}

extension FeedbackLogTests {
    func testHealthySnapshotIsIncludedWithoutDuplicatingFailureSnapshot() {
        let snapshot = "D12 tx_try=10 tx_ok=10 rx_ok=8 packets=TX_F1_TCP_FLAGS_02_SRC_VIP"
        let report = FeedbackLog.withDiagnostic("VPN 已连接", diagnostic: snapshot)
        XCTAssertTrue(report.contains(snapshot))
        XCTAssertEqual(FeedbackLog.withDiagnostic(report, diagnostic: snapshot), report)
        XCTAssertEqual(FeedbackLog.withDiagnostic("VPN 已连接", diagnostic: ""), "VPN 已连接")
    }
}
