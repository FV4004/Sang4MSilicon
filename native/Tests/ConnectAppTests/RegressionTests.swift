import XCTest
import Darwin
@testable import ConnectApp

final class RegressionTests: XCTestCase {
    func testShortHelperEventsArriveBeforeSocketCloses() async throws {
        var descriptors: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
        let input = FileHandle(fileDescriptor: descriptors[0], closeOnDealloc: true)
        let peer = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: true)
        defer { try? input.close(); try? peer.close() }
        let delivered = expectation(description: "short ready event delivered on live socket")
        let event = Data("{\"event\":\"ready\",\"mode\":\"tun\"}\n".utf8)
        let reader = Task.detached {
            do { let chunk = try readHelperChunk(input); XCTAssertEqual(chunk, event); delivered.fulfill() }
            catch { XCTFail(error.localizedDescription); delivered.fulfill() }
        }
        try peer.write(contentsOf: event)
        await fulfillment(of: [delivered], timeout: 1)
        // Release an old buffering implementation after timeout instead of hanging CI.
        _ = Darwin.shutdown(peer.fileDescriptor, SHUT_WR)
        await reader.value
        XCTAssertNil(try readHelperChunk(input))
    }
    @MainActor func testTunnelFailureReleasesControlAndAcceptsFreshSession() async throws {
        let controller = VPNController()
        for attempt in 0..<2 {
            var fds: [Int32] = [0, 0]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
            let control = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
            let peer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
            defer { try? peer.close() }
            controller.monitor(control, writer: control, mode: "tun", id: UUID())
            try peer.write(contentsOf: Data("{\"event\":\"ready\",\"mode\":\"tun\",\"interface\":\"utun42\",\"routeCount\":1}\n".utf8))
            for _ in 0..<100 { if controller.state == "connected" { break }; try await Task.sleep(nanoseconds: 5_000_000) }
            XCTAssertEqual(controller.state, "connected", "fresh session \(attempt) did not connect")
            try peer.write(contentsOf: Data("{\"event\":\"error\",\"code\":\"TUNNEL_FAILED\"}\n{\"event\":\"stopped\"}\n".utf8))
            _ = Darwin.shutdown(peer.fileDescriptor, SHUT_WR)
            for _ in 0..<100 { if controller.state == "disconnected" { break }; try await Task.sleep(nanoseconds: 5_000_000) }
            XCTAssertEqual(controller.state, "disconnected")
            XCTAssertEqual(controller.detail, VPNController.message("TUNNEL_FAILED"))
            XCTAssertEqual(fcntl(fds[0], F_GETFD), -1, "closed session descriptor was retained")
            XCTAssertEqual(errno, EBADF)
            try await controller.stop()
            XCTAssertEqual(controller.detail, VPNController.message("TUNNEL_FAILED"))
        }
    }
    func testBrokerHandshakeHandlesFragmentationAndIdentityRejection() async throws {
        for accepted in [true, false] {
            var fds: [Int32] = [0, 0]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
            let control = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
            let peer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
            defer { try? control.close(); try? peer.close() }
            let message = accepted ? "{\"event\":\"service\",\"code\":\"SERVICE_READY\"}\n" : "{\"event\":\"error\",\"code\":\"SERVICE_IDENTITY_REJECTED\"}\n"
            let bytes = Data(message.utf8)
            let sender = Task.detached {
                try peer.write(contentsOf: bytes.prefix(10))
                try await Task.sleep(nanoseconds: 20_000_000)
                try peer.write(contentsOf: bytes.dropFirst(10))
            }
            do { try await brokerHandshake(control); XCTAssertTrue(accepted) }
            catch { XCTAssertFalse(accepted); XCTAssertTrue(error.localizedDescription.contains("拒绝当前应用身份")) }
            try await sender.value
        }
    }
    @MainActor func testWorkerExitPreservesStatusAndLastStage() async throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let control = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        let peer = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        defer { try? peer.close() }
        let controller = VPNController()
        controller.monitor(control, writer: control, mode: "tun", id: UUID())
        try peer.write(contentsOf: Data("{\"event\":\"stage\",\"stage\":\"tunnel\"}\n{\"event\":\"workerExit\",\"reason\":\"signal\",\"status\":9}\n".utf8))
        _ = Darwin.shutdown(peer.fileDescriptor, SHUT_WR)
        for _ in 0..<100 { if controller.state == "disconnected" { break }; try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertEqual(controller.state, "disconnected")
        XCTAssertTrue(controller.detail.contains("信号 9")); XCTAssertTrue(controller.detail.contains("建立数据隧道"))
    }
    @MainActor func testInvalidSessionIsRejectedBeforeHelperInstallation() async throws {
        let controller = VPNController()
        do {
            try await controller.start(host: "127.0.0.1", port: 1, sessionID: "short", mode: "tun", socksPort: 0, httpPort: 0)
            XCTFail("invalid session was accepted")
        } catch { XCTAssertTrue(error.localizedDescription.contains("登录会话格式无效")) }
        XCTAssertEqual(controller.state, "disconnected")
    }
    @MainActor func testTypingNeverStartsValidationAndFocusLossDoes() async throws {
        let suite = "ConnectInputTest-" + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        MockProtocol.reset(offline: false)
        var initialized: [String] = []
        let model = AppModel(preferences: preferences, authFactory: { server in
            initialized.append(server)
            let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [MockProtocol.self]
            return try AuthClient(server, configuration: config)
        })
        model.serverEditingChanged(true)
        for address in ["https://v", "https://vpn", "https://vpn.example"] { model.server = address; model.serverChanged(); try await Task.sleep(nanoseconds: 250_000_000) }
        try await Task.sleep(nanoseconds: 800_000_000)
        XCTAssertTrue(initialized.isEmpty); XCTAssertFalse(model.busy); XCTAssertEqual(model.server, "https://vpn.example")
        model.serverEditingChanged(false)
        for _ in 0..<200 { if model.ready { break }; try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertEqual(initialized, ["https://vpn.example"]); XCTAssertTrue(model.ready); XCTAssertFalse(model.preparingServer)
        model.username = "kept-user"; model.password = "kept-password"
        model.serverEditingChanged(true); model.server = "https://new.example"; model.serverChanged()
        XCTAssertFalse(model.ready); XCTAssertEqual(model.username, "kept-user"); XCTAssertEqual(model.password, "kept-password")
        try await Task.sleep(nanoseconds: 800_000_000); XCTAssertEqual(initialized.count, 1)
        _ = await model.shutdown()
    }
}
