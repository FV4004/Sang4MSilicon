import Foundation

struct ResourceTarget: Identifiable { let id: Int; let label: String; let url: URL }
struct VPNResource: Identifiable {
    let id: String; let name: String; let groupID: String; let gateway: Bool
    let hosts: [String]; let ports: [String]; let targets: [ResourceTarget]; let copyTargets: [ResourceTarget]; let reason: String; let disguise: Bool
}
struct ResourceGroup: Identifiable { let id: String; let name: String; var items: [VPNResource] }
func webURL(_ input: String, service: String = "http", port: Int? = nil) -> URL? {
    guard !input.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { return nil }
    let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty, value.count <= 4096, !value.contains("\\"), !value.contains("~"), !value.contains("*"), !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { return nil }
    let explicit = value.contains("://")
    if !explicit && ["javascript:", "data:", "file:", "mailto:", "ftp:"].contains(where: { value.lowercased().hasPrefix($0) }) { return nil }
    guard var c = URLComponents(string: explicit ? value : "\(service == "https" ? "https" : "http")://\(value)"), ["http", "https"].contains(c.scheme?.lowercased() ?? ""), let host = c.host, !host.isEmpty, c.user == nil, c.password == nil else { return nil }
    c.scheme = c.scheme?.lowercased()
    if let existing = c.port, !(1...65535).contains(existing) { return nil }
    if c.port == nil, let port { guard (1...65535).contains(port) else { return nil }; c.port = port }
    if c.path.isEmpty { c.path = "/" }
    return c.url
}
func proxyPath(_ target: URL, disguise: Bool = false) throws -> String {
    guard ["http", "https"].contains(target.scheme ?? ""), target.user == nil, target.password == nil, let c = URLComponents(url: target, resolvingAgainstBaseURL: false), let host = c.host else { throw VPNError("资源地址无效。") }
    let path = c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath
    let filter = path.lowercased().hasSuffix(".css") ? 2 : path.lowercased().hasSuffix(".js") ? 3 : path.lowercased().hasSuffix(".vbs") ? 4 : 1
    let authority = (host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host) + (c.port.map { ":\($0)" } ?? "")
    return "\(disguise ? "/safeurl" : "")/web/\(filter)/\(c.scheme!)/0/\(authority)\(path)\(c.percentEncodedQuery.map { "?\($0)" } ?? "")\(c.percentEncodedFragment.map { "#\($0)" } ?? "")"
}
func parseResources(_ data: Data) throws -> [ResourceGroup] {
    let root = try XMLDocument.parse(data); guard root.name == "Resource" else { throw VPNError("网关未返回资源列表。") }
    var groups: [ResourceGroup] = (root.child("RcGroups")?.children ?? []).filter { $0.name == "Group" }.map { ResourceGroup(id: $0.attributes["id"] ?? "", name: String(($0.attributes["name"] ?? "未命名分组").prefix(256)), items: []) }
    let ssoIDs = Set((root.child("WebSsoInfos")?.children ?? []).compactMap { $0.attributes["rcid"] })
    let legacySSO = Set(root.child("Sso")?.value("data").components(separatedBy: ";").compactMap { $0.split(separator: ":").first.map(String.init) } ?? [])
    var ordinal = 0
    for node in root.child("Rcs")?.children ?? [] where node.name == "Rc" {
        let a = node.attributes
        guard (Int(a["attr"] ?? "0") ?? 0) & 1 == 0, let type = Int(a["type"] ?? ""), [0, 1, 2].contains(type) else { continue }
        ordinal += 1; guard ordinal <= 20000 else { throw VPNError("资源列表过大。") }
        let groupID = a["rc_grp_id"].flatMap { $0.isEmpty ? nil : $0 } ?? "ungrouped"
        if !groups.contains(where: { $0.id == groupID }) { groups.append(ResourceGroup(id: groupID, name: "未分组资源", items: [])) }
        let hosts = String((a["host"] ?? "").prefix(4096)).components(separatedBy: ";").filter { !$0.isEmpty }
        let ports = String((a["port"] ?? "").prefix(4096)).components(separatedBy: ";")
        let service = (a["svc"] ?? "").lowercased()
        let sso = ssoIDs.contains(a["id"] ?? "") || legacySSO.contains(a["id"] ?? "") || (Int(a["sso_type"] ?? "0") ?? 0) != 0
        let supported = ["http", "https"].contains(service) || type == 0 && service.isEmpty
        let labels = hosts.map { value -> String in
            if value.contains("://"), let u = URLComponents(string: value), let host = u.host { return host + (u.port.map { ":\($0)" } ?? "") }
            return value.components(separatedBy: CharacterSet(charactersIn: "?#")).first ?? value
        }
        var targets: [ResourceTarget] = []; var copyTargets: [ResourceTarget] = []
        if supported {
            for (index, host) in hosts.enumerated() {
                guard let original = webURL(host, service: service) else { continue }
                let range = index < ports.count && !ports[index].isEmpty ? ports[index] : ports.first ?? ""
                var selectedPort: Int?
                if type != 0 && !range.isEmpty {
                    let pieces = range.components(separatedBy: "~")
                    guard pieces.count <= 2, let min = Int(pieces[0]), let max = Int(pieces.last!), min >= 0, max <= 65535, min <= max else { continue }
                    if let explicit = original.port { guard (min...max).contains(explicit) else { continue } }
                    else if min == max && min > 0 { selectedPort = min }
                    else { let preferred = original.scheme == "https" ? 443 : 80; guard (min...max).contains(preferred) else { continue }; selectedPort = preferred }
                }
                if let url = webURL(host, service: service, port: selectedPort) { let target = ResourceTarget(id: index, label: labels[index], url: url); copyTargets.append(target); if !sso { targets.append(target) } }
            }
        }
        let item = VPNResource(id: "resource-\(ordinal)", name: String((a["name"] ?? "未命名资源").prefix(256)), groupID: groupID, gateway: type == 0, hosts: labels, ports: ports.filter { !$0.isEmpty }, targets: targets, copyTargets: copyTargets, reason: sso ? "需要单点登录，本版暂不支持" : supported ? targets.isEmpty ? "地址范围或格式不支持直接打开" : "" : "非网页资源，可复制资源地址", disguise: a["enable_disguise"] == "1")
        groups[groups.firstIndex(where: { $0.id == groupID })!].items.append(item)
    }
    return groups.filter { !$0.items.isEmpty }
}

func resourceCopyValue(_ resource: VPNResource, index: Int) -> String? {
    if let target = resource.copyTargets.first(where: { $0.id == index }) ?? resource.copyTargets.first { return target.url.absoluteString }
    let addresses = resource.hosts.filter { !$0.isEmpty }
    return addresses.isEmpty ? nil : addresses.joined(separator: "\n")
}
