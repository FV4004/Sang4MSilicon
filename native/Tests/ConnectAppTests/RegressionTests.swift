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
