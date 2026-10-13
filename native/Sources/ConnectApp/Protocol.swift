import Foundation
import Security

struct VPNError: LocalizedError { let message: String; var errorDescription: String? { message }; init(_ message: String) { self.message = message } }
final class XMLNode {
    let name: String
    let attributes: [String: String]
    var text = ""
    var children: [XMLNode] = []
    init(_ name: String, _ attributes: [String: String] = [:]) { self.name = name; self.attributes = attributes }
    func child(_ name: String) -> XMLNode? { children.first { $0.name == name } }
    func value(_ name: String) -> String { child(name)?.text.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
}
final class XMLDocument: NSObject, XMLParserDelegate {
    var root: XMLNode?
    private var stack: [XMLNode] = []
    private var nodes = 0
    static func parse(_ data: Data) throws -> XMLNode {
        let raw = String(decoding: data, as: UTF8.self).uppercased()
        guard data.count <= 2 * 1024 * 1024, !raw.contains("<!DOCTYPE"), !raw.contains("<!ENTITY") else { throw VPNError("服务器 XML 无效或过大。") }
        let delegate = XMLDocument(); let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false; parser.delegate = delegate
        guard parser.parse(), let root = delegate.root else { throw VPNError("服务器返回了无效 XML。") }
        return root
    }
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
        nodes += 1
        guard nodes <= 100000, stack.count < 64 else { parser.abortParsing(); return }
        let node = XMLNode(name, attributes)
        if let parent = stack.last { parent.children.append(node) } else { root = node }
        stack.append(node)
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { stack.last?.text += string }
    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) { stack.last?.text += String(decoding: CDATABlock, as: UTF8.self) }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) { _ = stack.popLast() }
}
func authFields(_ data: Data) throws -> [String: String] {
    let root = try XMLDocument.parse(data)
    guard root.name == "Auth", Int(root.value("ErrorCode")) != nil else { throw VPNError("服务器响应缺少认证结果。") }
    return Dictionary(root.children.map { ($0.name, $0.text.trimmingCharacters(in: .whitespacesAndNewlines)) }, uniquingKeysWith: { _, last in last })
}
func serverURL(_ value: String) throws -> URL {
    guard value.count <= 2048, let c = URLComponents(string: value.trimmingCharacters(in: .whitespacesAndNewlines)), ["http", "https"].contains(c.scheme?.lowercased() ?? ""), let host = c.host, !host.isEmpty, c.user == nil, c.password == nil, c.query == nil, c.fragment == nil, c.path.isEmpty || c.path == "/", let url = c.url else { throw VPNError("请输入 HTTP 或 HTTPS 服务器地址和可选端口，不包含页面路径。") }
    if let port = c.port, !(1...65535).contains(port) { throw VPNError("服务器端口无效。") }
    return url
}
func sameOrigin(_ a: URL, _ b: URL) -> Bool {
    a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased() && (a.port ?? (a.scheme == "https" ? 443 : 80)) == (b.port ?? (b.scheme == "https" ? 443 : 80))
}
func formBody(_ fields: [String: String]) -> Data {
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
    return Data(fields.sorted { $0.key < $1.key }.map { "\($0.key.addingPercentEncoding(withAllowedCharacters: allowed)!)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed)!)" }.joined(separator: "&").utf8)
}
func rsaPassword(_ password: String, config: [String: String]) throws -> String {
    let hex = (config["RSA_ENCRYPT_KEY"] ?? "").replacingOccurrences(of: "^0x", with: "", options: [.regularExpression, .caseInsensitive])
    let rawE = config["RSA_ENCRYPT_EXP"] ?? "65537"
    let exponent = rawE.lowercased().hasPrefix("0x") ? UInt32(rawE.dropFirst(2), radix: 16) : UInt32(rawE)
    guard hex.count >= 128, hex.count <= 2048, hex.count % 2 == 0, hex.allSatisfy({ $0.isHexDigit }), let e = exponent, e >= 3, e % 2 == 1, let random = config["CSRF_RAND_CODE"], !random.isEmpty else { throw VPNError("服务器 RSA 公钥或防重放随机码无效，请重新获取验证码。") }
    var modulus: [UInt8] = []; var i = hex.startIndex
    while i < hex.endIndex { let end = hex.index(i, offsetBy: 2); modulus.append(UInt8(hex[i..<end], radix: 16)!); i = end }
    func length(_ n: Int) -> [UInt8] { if n < 128 { return [UInt8(n)] }; var x = n; var b: [UInt8] = []; while x > 0 { b.insert(UInt8(x & 255), at: 0); x >>= 8 }; return [0x80 | UInt8(b.count)] + b }
    func integer(_ bytes: [UInt8]) -> [UInt8] { var b = bytes; while b.count > 1 && b.first == 0 { b.removeFirst() }; if (b.first ?? 0) >= 128 { b.insert(0, at: 0) }; return [2] + length(b.count) + b }
    let exp = (0..<4).reversed().map { UInt8((e >> ($0 * 8)) & 255) }
    let content = integer(modulus) + integer(exp)
    let der = Data([0x30] + length(content.count) + content)
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(der as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, &error), let encrypted = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, Data((password + "_" + random).utf8) as CFData, &error) else { throw VPNError("RSA 密码加密失败，请检查密码长度和服务器公钥。") }
    return (encrypted as Data).map { String(format: "%02x", $0) }.joined()
}
