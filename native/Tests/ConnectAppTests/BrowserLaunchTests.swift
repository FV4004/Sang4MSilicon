import XCTest
@testable import ConnectApp

final class BrowserLaunchTests: XCTestCase {
    @MainActor func testBrowserArgumentsEqualCopiedURLIncludingPortPathAndQuery() throws {
        let xml = "<Resource><Rcs><Rc id='ehr' type='1' svc='http' host='ehress.example.test/login.jsp?next=%2Fa%3Fb%3Dc;second.example.test/home' port='80~80;8080~8080'/></Rcs></Resource>"
        let item = try XCTUnwrap(parseResources(Data(xml.utf8)).first?.items.first)
        for target in item.targets {
            XCTAssertEqual(try ExternalBrowserLauncher.arguments(for: target.url), [try XCTUnwrap(resourceCopyValue(item, index: target.id))])
        }
        XCTAssertEqual(try ExternalBrowserLauncher.arguments(for: item.targets[0].url)[0], "http://ehress.example.test:80/login.jsp?next=%2Fa%3Fb%3Dc")
        for bad in ["file:///tmp/test", "https://user:secret@example.test/", "javascript:alert(1)"] {
            XCTAssertThrowsError(try ExternalBrowserLauncher.arguments(for: XCTUnwrap(URL(string: bad))))
        }
    }
    @MainActor func testOrdinaryCardOpensWithoutAuthenticationOperationOrTunnelStateChange() async throws {
        var opened: [URL] = []
        let browser = ResourceBrowser(externalOpen: { opened.append($0) })
        let preferences = UserDefaults(suiteName: UUID().uuidString)!
        let model = AppModel(preferences: preferences, authFactory: { _ in XCTFail("ordinary card created authentication transport"); throw VPNError("unexpected auth") }, vpnConnector: { _ in XCTFail("ordinary card started a tunnel") }, browser: browser)
        model.authenticated = true; model.vpnState = "connected"; model.vpnDetail = "active session"
        let item = try XCTUnwrap(parseResources(Data("<Resource><Rcs><Rc type='1' svc='https' host='example.test/path' port='443~443'/></Rcs></Resource>".utf8)).first?.items.first)
        model.open(item, target: item.targets[0])
        for _ in 0..<100 { if !opened.isEmpty { break }; try await Task.sleep(nanoseconds: 1_000_000) }
        XCTAssertEqual(opened, [item.targets[0].url])
        XCTAssertFalse(model.busy)
        XCTAssertEqual(model.vpnState, "connected")
        XCTAssertEqual(model.vpnDetail, "active session")
        XCTAssertTrue(model.authenticated)
        try await model.browser.close()
    }
    @MainActor func testDisconnectedTunnelDoesNotLaunchBrowser() async throws {
        var called = false
        let browser = ResourceBrowser(externalOpen: { _ in called = true })
        do { try await browser.openDirect(target: ResourceTarget(id: 0, label: "", url: URL(string: "http://example.test/")!), tunConnected: false); XCTFail("disconnected resource opened") }
        catch { XCTAssertTrue(error.localizedDescription.contains("TUN")) }
        XCTAssertFalse(called)
    }
}
