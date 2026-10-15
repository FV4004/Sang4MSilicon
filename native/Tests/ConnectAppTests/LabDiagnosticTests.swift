import XCTest
@testable import ConnectApp

final class LabDiagnosticTests: XCTestCase {
    @MainActor func testExperimentalDiagnosticsPreserveOriginalRecoveryInstructions() {
        for profile in ["A", "B", "C"] {
            for raw in ["CONNECT_FAILED", "TUN_SERVER_SHUTDOWN", "TUN_SESSION_EXPIRED", "TUN_FRAME_INVALID"] {
                let code = "LAB_" + profile + "_" + raw + "_FIRST_RECV_DATA_TRUNCATED"
                let shown = VPNController.message(code)
                XCTAssertTrue(shown.hasPrefix(VPNController.message(raw)))
                XCTAssertTrue(shown.contains(code))
            }
        }
        XCTAssertTrue(VPNController.message("LAB_A_CONNECT_FAILED_FIRST_").hasPrefix(VPNController.message("CONNECT_FAILED")))
    }
}
