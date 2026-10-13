import XCTest
import Security
@testable import ConnectApp

final class ProtocolTests: XCTestCase {
    func testServerAndFormEncoding() throws {
        XCTAssertEqual(try serverURL("https://vpn.example.com").host, "vpn.example.com")
        XCTAssertEqual(try serverURL("HTTP://vpn.example.com").scheme, "http")
        XCTAssertEqual(webURL("HTTPS://web.example/")?.scheme, "https")
        XCTAssertEqual(try serverURL("http://vpn.example.com:8080").port, 8080)
        for bad in ["ftp://vpn.example.com", "https://user:secret@vpn.example.com", "https://vpn.example.com/path", "https://vpn.example.com?x=1", "https://vpn.example.com:70000"] { XCTAssertThrowsError(try serverURL(bad)) }
        XCTAssertEqual(String(decoding: formBody(["password": "a+b& 中"]), as: UTF8.self), "password=a%2Bb%26%20%E4%B8%AD")
        XCTAssertFalse(sameOrigin(URL(string: "https://vpn.example.com")!, URL(string: "https://vpn.example.com:444")!))
        XCTAssertTrue(sameOrigin(URL(string: "https://vpn.example.com")!, URL(string: "https://vpn.example.com:443")!))
    }
    func testXMLSafetyAndAuthentication() throws {
        XCTAssertEqual(try authFields(Data("<Auth><ErrorCode>1</ErrorCode><TwfID>a&amp;b</TwfID></Auth>".utf8))["TwfID"], "a&b")
        for bad in ["<!DOCTYPE Auth [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Auth><ErrorCode>1</ErrorCode></Auth>", "<Auth><ErrorCode>abc</ErrorCode></Auth>", "<Resource/>", "<Auth>"] { XCTAssertThrowsError(try authFields(Data(bad.utf8))) }
    }
    func testResourceGroupsPortsAndUnsupported() throws {
        let xml = """
        <Resource><RcGroups><Group id="g" name="研发"/></RcGroups><Rcs>
        <Rc id="1" name="门户" type="0" rc_grp_id="g" svc="https" host="https://web.example/a?x=1&amp;y=2" port="0~0" enable_disguise="1"/>
        <Rc id="2" name="内网" type="1" rc_grp_id="g" svc="http" host="10.0.0.2" port="8080~8080"/>
        <Rc id="3" name="地址范围" type="2" svc="tcp" host="10.0.0.1~10.0.0.9" port="22"/>
        <Rc id="4" name="隐藏" type="0" attr="1" host="https://hidden.example"/>
        <Rc id="5" name="单点登录" type="0" rc_grp_id="g" host="https://sso.example"/>
        </Rcs><WebSsoInfos><webssoinfo rcid="5"/></WebSsoInfos></Resource>
        """
        let groups = try parseResources(Data(xml.utf8)); XCTAssertEqual(groups.count, 2)
        let items = groups.flatMap(\.items); XCTAssertEqual(items.count, 4)
        let portal = items.first { $0.name == "门户" }!; XCTAssertTrue(portal.gateway)
        XCTAssertEqual(try proxyPath(portal.targets[0].url, disguise: portal.disguise), "/safeurl/web/1/https/0/web.example/a?x=1&y=2")
        XCTAssertEqual(items.first { $0.name == "内网" }?.targets.first?.url.absoluteString, "http://10.0.0.2:8080/")
        XCTAssertTrue(items.first { $0.name == "单点登录" }!.targets.isEmpty)
        XCTAssertTrue(items.first { $0.name == "地址范围" }!.targets.isEmpty)
    }
    func testResourceURLInjectionAndProxyPaths() throws {
        for input in ["javascript:alert(1)", "file:///etc/passwd", "https://user:secret@host/", "10.1.1.1~10.1.1.8", "https://host/\\bad", "https://host/\n"] { XCTAssertNil(webURL(input)) }
        XCTAssertEqual(try proxyPath(URL(string: "https://host:8443/a.css?v=1#section")!), "/web/2/https/0/host:8443/a.css?v=1#section")
        XCTAssertEqual(webURL("10.0.0.2:8080")?.port, 8080)
    }
    func testRSAWithAntiReplayRoundTrip() throws {
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil)) as Data
        var offset = 0
        func length() -> Int { let first = Int(der[offset]); offset += 1; if first < 128 { return first }; var value = 0; for _ in 0..<(first & 127) { value = value * 256 + Int(der[offset]); offset += 1 }; return value }
        XCTAssertEqual(der[offset], 0x30); offset += 1; _ = length(); XCTAssertEqual(der[offset], 2); offset += 1; let n = length(); var modulus = Array(der[offset..<(offset+n)]); if modulus.first == 0 { modulus.removeFirst() }
        let cipher = try rsaPassword("secret中", config: ["RSA_ENCRYPT_KEY": modulus.map { String(format: "%02x", $0) }.joined(), "RSA_ENCRYPT_EXP": "65537", "CSRF_RAND_CODE": "nonce"])
        var bytes = Data(); var index = cipher.startIndex; while index < cipher.endIndex { let end = cipher.index(index, offsetBy: 2); bytes.append(UInt8(cipher[index..<end], radix: 16)!); index = end }
        let plain = try XCTUnwrap(SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, bytes as CFData, nil)) as Data
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "secret中_nonce")
        XCTAssertThrowsError(try rsaPassword("secret", config: [:]))
    }
    func testPrivilegedInstallQuotingAndValidation() throws {
        let path = "/Applications/User's app/Connect.app/helper"
        let script = try helperInstallScript(source: path, hash: String(repeating: "a", count: 64), socket: "/var/run/mchip-vpn/501-" + String(repeating: "b", count: 32) + ".sock", uid: 501)
        XCTAssertTrue(script.contains("User'\\''s")); XCTAssertTrue(script.contains("codesign --verify --strict")); XCTAssertTrue(script.contains("--owner-uid 501"))
        XCTAssertThrowsError(try helperInstallScript(source: path, hash: "bad", socket: "/tmp/unsafe", uid: 501))
    }
    @MainActor func testWebNavigationBlocksLocalPrograms() {
        XCTAssertTrue(ResourceBrowser.safe(URL(string: "https://web.example/")))
        for value in ["file:///etc/passwd", "javascript:alert(1)", "mailto:user@example.com", "https://user:secret@web.example"] { XCTAssertFalse(ResourceBrowser.safe(URL(string: value))) }
    }
}
