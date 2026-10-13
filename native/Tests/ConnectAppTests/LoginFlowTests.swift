import XCTest
import Security
@testable import ConnectApp

final class LoginFlowTests: XCTestCase {
    private func modulus() throws -> String {
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)) as Data
        var offset = 0
        func length() -> Int { let first = Int(der[offset]); offset += 1; if first < 128 { return first }; var value = 0; for _ in 0..<(first & 127) { value = value * 256 + Int(der[offset]); offset += 1 }; return value }
        offset += 1; _ = length(); offset += 1; let size = length(); var bytes = Array(der[offset..<(offset+size)]); if bytes.first == 0 { bytes.removeFirst() }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    private func installGateway(loginCode: Int = 1, challenge: Bool = false) throws {
        let n = try modulus(); MockProtocol.reset(offline: false)
        MockProtocol.install { request in
            switch request.url!.path {
            case "/por/login_auth.csp": return Data("<Auth><ErrorCode>1</ErrorCode><TwfID>fixture-session</TwfID><RSA_ENCRYPT_KEY>\(n)</RSA_ENCRYPT_KEY><CSRF_RAND_CODE>nonce</CSRF_RAND_CODE></Auth>".utf8)
            case "/public/psw_config": return Data("<Auth><ErrorCode>1</ErrorCode><USE_RAND_CODE>0</USE_RAND_CODE></Auth>".utf8)
            case "/por/login_psw.csp": return Data("<Auth><ErrorCode>\(challenge ? 2 : loginCode)</ErrorCode>\(challenge ? "<NextService>totp</NextService>" : "")</Auth>".utf8)
            case "/por/rclist.csp": return Data("<Resource><Rcs/></Resource>".utf8)
            default: return Data("<Auth><ErrorCode>1</ErrorCode></Auth>".utf8)
            }
        }
    }
    @MainActor private func settle(_ model: AppModel) async throws {
        for _ in 0..<1000 { if !model.busy { return }; try await Task.sleep(nanoseconds: 5_000_000) }
        XCTFail("Login flow did not settle")
    }
    @MainActor private func makeModel(preferences: UserDefaults, connector: @escaping (VPNConnectionRequest) async throws -> Void) -> AppModel {
        AppModel(preferences: preferences, authFactory: { server in let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [MockProtocol.self]; return try AuthClient(server, configuration: config) }, vpnConnector: connector)
    }
    @MainActor func testPasswordMemoryStartsOffEvenWithOldPreference() {
        let suite = "PasswordDefault-" + UUID().uuidString; let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        preferences.set(true, forKey: "rememberPassword"); preferences.set("https://vpn.example", forKey: "server"); preferences.set("user", forKey: "username")
        let model = AppModel(preferences: preferences)
        XCTAssertFalse(model.rememberPassword); XCTAssertEqual(model.password, ""); XCTAssertEqual(model.username, "user"); XCTAssertEqual(model.server, "https://vpn.example")
    }
    @MainActor func testSuccessfulAuthenticationAutomaticallyStartsTUN() async throws {
        try installGateway()
        let suite = "AutoTUN-" + UUID().uuidString; let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        var requests: [VPNConnectionRequest] = []
        let model = makeModel(preferences: preferences) { requests.append($0) }
        model.server = "https://vpn.example"; model.username = "user"; model.password = "secret"; model.mode = "proxy"
        model.initialize(); try await settle(model); model.login(); try await settle(model)
        XCTAssertTrue(model.authenticated); XCTAssertEqual(model.loginTone, .success); XCTAssertEqual(model.mode, "tun")
        XCTAssertEqual(requests.count, 1); XCTAssertEqual(requests.first?.mode, "tun"); XCTAssertEqual(requests.first?.host, "vpn.example"); XCTAssertEqual(requests.first?.sessionID, "fixture-session")
        _ = await model.shutdown()
    }
    @MainActor func testChallengeWaitsForFinalAuthenticationBeforeStartingTUN() async throws {
        try installGateway(challenge: true)
        let suite = "ChallengeAutoTUN-" + UUID().uuidString; let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        var count = 0; let model = makeModel(preferences: preferences) { _ in count += 1 }
        model.server = "https://vpn.example"; model.username = "user"; model.password = "secret"
        model.initialize(); try await settle(model); model.login(); try await settle(model)
        XCTAssertTrue(model.challenge); XCTAssertFalse(model.authenticated); XCTAssertEqual(count, 0)
        model.response = "123456"; model.login(); try await settle(model)
        XCTAssertTrue(model.authenticated); XCTAssertEqual(count, 1); XCTAssertEqual(model.loginTone, .success)
        _ = await model.shutdown()
    }
    @MainActor func testAuthenticationFailureKeepsCredentialsAndDoesNotConnect() async throws {
        try installGateway(loginCode: 20004)
        let suite = "FailedAutoTUN-" + UUID().uuidString; let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        var count = 0; let model = makeModel(preferences: preferences) { _ in count += 1 }
        model.server = "https://vpn.example"; model.username = "user"; model.password = "secret"
        model.initialize(); try await settle(model); model.login(); try await settle(model)
        XCTAssertFalse(model.authenticated); XCTAssertEqual(count, 0); XCTAssertEqual(model.loginTone, .error); XCTAssertTrue(model.loginMessage.contains("20004")); XCTAssertEqual(model.password, "secret")
        _ = await model.shutdown()
    }
    @MainActor func testTUNFailurePreservesAuthenticatedSession() async throws {
        try installGateway()
        let suite = "FailedTUN-" + UUID().uuidString; let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite) }
        let model = makeModel(preferences: preferences) { _ in throw VPNError("fixture authorization cancelled") }
        model.server = "https://vpn.example"; model.username = "user"; model.password = "secret"
        model.initialize(); try await settle(model); model.login(); try await settle(model)
        XCTAssertTrue(model.authenticated); XCTAssertEqual(model.loginTone, .success); XCTAssertTrue(model.message.contains("自动连接 TUN 失败"))
        _ = await model.shutdown()
    }
    func testCopyPreservesOriginalURLAndSupportsSSOWithoutSessionBootstrap() throws {
        let xml = "<Resource><Rcs><Rc id='1' name='Portal' type='0' svc='https' host='https://inside.example/path?a=1&amp;b=2' port='0~0'/></Rcs><WebSsoInfos><webssoinfo rcid='1'/></WebSsoInfos></Resource>"
        let resource = try XCTUnwrap(parseResources(Data(xml.utf8)).first?.items.first)
        XCTAssertTrue(resource.targets.isEmpty)
        XCTAssertEqual(resourceCopyValue(resource, index: 0), "https://inside.example/path?a=1&b=2")
        XCTAssertFalse(resourceCopyValue(resource, index: 0)!.contains("twfid="))
    }
}
