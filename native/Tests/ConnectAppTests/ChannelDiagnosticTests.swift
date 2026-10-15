import XCTest
@testable import ConnectApp

final class ChannelDiagnosticTests: XCTestCase {
    @MainActor func testChannelDiagnosticTextIsBoundedAndPlain() {
        let text = "D12 tx_try=1 tx_ok=0 rx_ok=0 age_ms=2000 timeline=SEND_EOF@100ms,TX_BEGIN_TCP@2000ms"
        XCTAssertTrue(VPNController.diagnosticSuffix(text).contains(text))
        XCTAssertEqual(VPNController.diagnosticSuffix(nil), "")
        XCTAssertEqual(VPNController.diagnosticSuffix("D12 " + String(repeating: "x", count: 4096)), "")
        XCTAssertEqual(VPNController.diagnosticSuffix("D12 <script>private</script>"), "")
        XCTAssertEqual(VPNController.diagnosticSuffix("D12 secret\nextra-line"), "")
    }
}
