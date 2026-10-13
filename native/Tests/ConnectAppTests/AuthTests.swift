import XCTest
import Security
@testable import ConnectApp

final class MockProtocol: URLProtocol {
    static var requests: [URLRequest] = []
    static var failLogout = false
    static var handler: ((URLRequest) -> Data)?
    static let lock = NSLock()
    static func reset(offline: Bool) { lock.lock(); defer { lock.unlock() }; requests = []; failLogout = offline; handler = nil }
    static func install(_ handler: @escaping (URLRequest) -> Data) { lock.lock(); defer { lock.unlock() }; self.handler = handler }
    static func snapshot() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return requests }
    static func lastLogout() -> URLRequest? { lock.lock(); defer { lock.unlock() }; return requests.last { $0.url?.path == "/por/logout.csp" } }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock(); Self.requests.append(request); let fail = Self.failLogout; let handler = Self.handler; Self.lock.unlock()
        let path = request.url!.path
        if path == "/por/logout.csp" && fail { client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet)); return }
        let xml = path == "/public/psw_config" ? "<Auth><ErrorCode>1</ErrorCode><USE_RAND_CODE>0</USE_RAND_CODE></Auth>" : "<Auth><ErrorCode>1</ErrorCode><TwfID>session-123</TwfID></Auth>"
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/xml"])!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: handler?(request) ?? Data(xml.utf8)); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func body(_ request: URLRequest) -> Data {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open(); defer { stream.close() }; var data = Data(); var bytes = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable { let count = stream.read(&bytes, maxLength: bytes.count); if count <= 0 { break }; data.append(contentsOf: bytes.prefix(count)) }
        return data
    }
}
final class AuthTests: XCTestCase {
    @MainActor func testLogoutUsesSessionAndAlwaysClearsLocalState() async throws {
        for offline in [false, true] {
            MockProtocol.reset(offline: offline)
            let configuration = URLSessionConfiguration.ephemeral; configuration.protocolClasses = [MockProtocol.self]
            let auth = try AuthClient("https://vpn.example:8443", configuration: configuration)
            _ = try await auth.initialize(); XCTAssertEqual(auth.twfid, "session-123")
            if offline { do { try await auth.logout(); XCTFail("Offline logout must report failure") } catch {} } else { try await auth.logout() }
            XCTAssertEqual(auth.twfid, ""); XCTAssertFalse(auth.authenticated)
            let logout = MockProtocol.lastLogout()
            XCTAssertEqual(logout?.httpMethod, "POST"); XCTAssertEqual(logout?.value(forHTTPHeaderField: "TWFID"), "session-123")
            do { _ = try await auth.request("/por/login_auth.csp"); XCTFail("Closed session must reject requests") } catch {}
        }
    }
    @MainActor func testFreshRSAChallengeCaptchaAndDynamicAuthentication() async throws {
        MockProtocol.reset(offline: false)
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)) as Data
        var index = 0
        func length() -> Int { let b = Int(der[index]); index += 1; if b < 128 { return b }; var count = 0; for _ in 0..<(b & 127) { count = count * 256 + Int(der[index]); index += 1 }; return count }
        index += 1; _ = length(); index += 1; let size = length(); var modulus = Array(der[index..<(index+size)]); if modulus.first == 0 { modulus.removeFirst() }
        let hex = modulus.map { String(format: "%02x", $0) }.joined()
        let image = Data(base64Encoded: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jhN0AAAAASUVORK5CYII=")!
        var initCalls = 0
        MockProtocol.install { request in
            let path = request.url!.path
            if path == "/por/login_auth.csp" { initCalls += 1; return Data("<Auth><ErrorCode>1</ErrorCode><TwfID>session-123</TwfID><RSA_ENCRYPT_KEY>\(hex)</RSA_ENCRYPT_KEY><CSRF_RAND_CODE>nonce\(initCalls)</CSRF_RAND_CODE></Auth>".utf8) }
            if path == "/public/psw_config" { return Data("<Auth><ErrorCode>1</ErrorCode><USE_RAND_CODE>1</USE_RAND_CODE></Auth>".utf8) }
            if path == "/por/rand_code.csp" { return image }
            if path == "/por/login_psw.csp" {
                let body = String(decoding: MockProtocol.body(request), as: UTF8.self)
                let fields = Dictionary((URLComponents(string: "https://fixture/?" + body)?.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { _, last in last })
                XCTAssertEqual(fields["svpn_req_randcode"], "nonce2"); XCTAssertEqual(fields["svpn_rand_code"], "1234")
                XCTAssertEqual(request.url?.query?.contains("anti_replay=1"), true)
                let cipher = fields["svpn_password"] ?? ""; var encrypted = Data(); var offset = cipher.startIndex
                while offset < cipher.endIndex { let end = cipher.index(offset, offsetBy: 2); encrypted.append(UInt8(cipher[offset..<end], radix: 16)!); offset = end }
                let plain = SecKeyCreateDecryptedData(key, .rsaEncryptionPKCS1, encrypted as CFData, nil) as Data?
                XCTAssertEqual(plain.map { String(decoding: $0, as: UTF8.self) }, "secret_nonce2")
                return Data("<Auth><ErrorCode>2</ErrorCode><NextService>totp</NextService></Auth>".utf8)
            }
            if path == "/auth/token" { XCTAssertEqual(request.httpMethod, "POST"); return Data("<Auth><ErrorCode>1</ErrorCode></Auth>".utf8) }
            return Data("<Auth><ErrorCode>1</ErrorCode></Auth>".utf8)
        }
        let configuration = URLSessionConfiguration.ephemeral; configuration.protocolClasses = [MockProtocol.self]
        let auth = try AuthClient("https://vpn.example", configuration: configuration)
        let captcha = try await auth.initialize(); XCTAssertEqual(captcha, image); XCTAssertTrue(auth.captchaRequired)
        _ = try await auth.login(username: "user", password: "secret", captcha: "1234"); XCTAssertEqual(auth.challenge, "totp"); XCTAssertFalse(auth.authenticated)
        _ = try await auth.submitChallenge("654321"); XCTAssertTrue(auth.authenticated); XCTAssertEqual(auth.challenge, "")
        try await auth.logout(); XCTAssertEqual(auth.twfid, "")
    }

}
