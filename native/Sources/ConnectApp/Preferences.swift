import Foundation
import Security

enum PasswordStore {
    static let service = "dev.connectlab.mchip-vpn.native"
    static func account(server: String, username: String) -> String { server + "\n" + username }
    static func load(server: String, username: String) -> String {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account(server: server, username: username), kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne] as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }
    static func save(_ password: String?, server: String, username: String) throws {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account(server: server, username: username)]
        let deleted = SecItemDelete(query as CFDictionary)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else { throw VPNError("无法更新钥匙串密码。") }
        guard let password else { return }
        var attributes = query; attributes[kSecValueData] = Data(password.utf8); attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw VPNError("无法保存密码到系统钥匙串。") }
    }
}
