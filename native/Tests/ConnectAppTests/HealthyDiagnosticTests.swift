import XCTest
import Darwin
@testable import ConnectApp

final class HealthyDiagnosticTests: XCTestCase {
    @MainActor func testHealthySnapshotsDoNotChangeTunnelStateAndFreezeAfterFailure() async throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let control = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        let peer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        defer { try? peer.close() }
        let controller = VPNController()
        controller.monitor(control, writer: control, mode: "tun", id: UUID())
        let healthy = "D12 tx_try=4 tx_ok=4 rx_ok=4 timeline=READY@100ms packets=TX_F1_TCP_FLAGS_02_SRC_VIP"
        try peer.write(contentsOf: Data(("{\"event\":\"ready\",\"mode\":\"tun\",\"interface\":\"utun42\",\"routeCount\":1}\n{\"event\":\"diagnostic\",\"diagnostic\":\"" + healthy + "\"}\n").utf8))
        for _ in 0..<100 { if controller.diagnostic == healthy { break }; try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertEqual(controller.state, "connected")
        XCTAssertEqual(controller.diagnostic, healthy)
        let failed = "D12 tx_try=7 tx_ok=6 rx_ok=1 timeline=SEND_EOF@200ms packets=TX_F1_TCP_FLAGS_10_SRC_OTHER"
        try peer.write(contentsOf: Data(("{\"event\":\"error\",\"code\":\"TUN_SERVER_SHUTDOWN\",\"diagnostic\":\"" + failed + "\"}\n{\"event\":\"diagnostic\",\"diagnostic\":\"" + healthy + "\"}\n{\"event\":\"stopped\"}\n").utf8))
        _ = Darwin.shutdown(peer.fileDescriptor, SHUT_WR)
        for _ in 0..<100 { if controller.state == "disconnected" { break }; try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertEqual(controller.state, "disconnected")
        XCTAssertEqual(controller.diagnostic, failed)
        XCTAssertTrue(controller.detail.contains(failed))
    }
}
