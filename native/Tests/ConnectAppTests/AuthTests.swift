import XCTest
@testable import ConnectApp

final class MockProtocol: URLProtocol {
    static var requests: [URLRequest] = []
    static var failLogout = false
    static let lock = NSLock()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock(); Self.requests.append(request); let fail = Self.failLogout; Self.lock.unlock()
        let path = request.url!.path
        if path == "/por/logout.csp" && fail { client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet)); return }
        let xml = path == "/public/psw_config" ? "<Auth><ErrorCode>1</ErrorCode><USE_RAND_CODE>0</USE_RAND_CODE></Auth>" : "<Auth><ErrorCode>1</ErrorCode><TwfID>session-123</TwfID></Auth>"
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/xml"])!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(xml.utf8)); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
final class AuthTests: XCTestCase {
    @MainActor func testLogoutUsesSessionAndAlwaysClearsLocalState() async throws {
        for offline in [false, true] {
            MockProtocol.lock.lock(); MockProtocol.requests = []; MockProtocol.failLogout = offline; MockProtocol.lock.unlock()
            let configuration = URLSessionConfiguration.ephemeral; configuration.protocolClasses = [MockProtocol.self]
            let auth = try AuthClient("http://vpn.example:8080", configuration: configuration)
            _ = try await auth.initialize(); XCTAssertEqual(auth.twfid, "session-123")
            if offline { do { try await auth.logout(); XCTFail("Offline logout must report failure") } catch {} } else { try await auth.logout() }
            XCTAssertEqual(auth.twfid, ""); XCTAssertFalse(auth.authenticated)
            MockProtocol.lock.lock(); let logout = MockProtocol.requests.last { $0.url?.path == "/por/logout.csp" }; MockProtocol.lock.unlock()
            XCTAssertEqual(logout?.httpMethod, "POST"); XCTAssertEqual(logout?.value(forHTTPHeaderField: "TWFID"), "session-123")
            do { _ = try await auth.request("/por/login_auth.csp"); XCTFail("Closed session must reject requests") } catch {}
        }
    }
}
