import XCTest
@testable import ConnectApp

final class LifecycleTests: XCTestCase {
    @MainActor func testQuitOrdersCleanupAndCoalesces() async {
        let coordinator = ShutdownCoordinator(); var events: [String] = []
        func invoke() async -> String? { await coordinator.shutdown(cancel: { events.append("cancel") }, stopVPN: { events.append("stopVPN") }, drain: { events.append("drain") }, closeWeb: { events.append("closeWeb") }, logout: { events.append("logout") }, clear: { events.append("clear") }) }
        let result = await invoke(); XCTAssertNil(result); let again = await invoke(); XCTAssertNil(again)
        XCTAssertEqual(events, ["cancel", "stopVPN", "drain", "closeWeb", "logout", "clear"])
    }
    @MainActor func testQuitStillLogsOutAndClearsAfterNetworkCleanupErrors() async {
        let coordinator = ShutdownCoordinator(); var loggedOut = false; var cleared = false
        let result = await coordinator.shutdown(cancel: {}, stopVPN: { throw VPNError("cleanup failed") }, drain: {}, closeWeb: {}, logout: { loggedOut = true; throw VPNError("offline") }, clear: { cleared = true })
        XCTAssertTrue(loggedOut); XCTAssertTrue(cleared); XCTAssertTrue(result?.contains("cleanup failed") == true); XCTAssertTrue(result?.contains("offline") == true)
    }
    func testOnlyExplicitCloseChoicesAreRemembered() {
        XCTAssertEqual(CloseAction.remembered("minimize"), .minimize); XCTAssertEqual(CloseAction.remembered("quit"), .quit)
        XCTAssertNil(CloseAction.remembered(nil)); XCTAssertNil(CloseAction.remembered("cancel")); XCTAssertNil(CloseAction.remembered("invalid"))
    }
}
