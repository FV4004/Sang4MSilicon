import Foundation
import Network

// Plain HTTP is supported only for the user-configured authentication origin.
// HTTPS always uses URLSession and normal system certificate verification.
struct HTTPMessage {
    let status: Int; let headers: [String: String]; let body: Data
}
func decodeHTTP(_ bytes: Data, eof: Bool = false) throws -> HTTPMessage? {
    guard bytes.count <= 2 * 1024 * 1024 + 65536 else { throw VPNError("服务器响应过大。") }
    guard let boundary = bytes.range(of: Data("\r\n\r\n".utf8)) else { if bytes.count > 65536 || eof { throw VPNError("HTTP 响应头无效。") }; return nil }
    guard boundary.lowerBound <= 65536, let head = String(data: bytes[..<boundary.lowerBound], encoding: .isoLatin1) else { throw VPNError("HTTP 响应头无效。") }
    let lines = head.components(separatedBy: "\r\n"); let statusFields = lines[0].split(separator: " ")
    guard statusFields.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(statusFields[0])), let status = Int(statusFields[1]) else { throw VPNError("HTTP 状态无效。") }
    var headers: [String: String] = [:]
    for line in lines.dropFirst() {
        guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { throw VPNError("HTTP 响应头无效。") }
        let key = line[..<colon].lowercased(); let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        if let old = headers[key] { if key == "set-cookie" { headers[key] = old + "\n" + value } else if key == "content-length" && old == value {} else if ["content-length", "transfer-encoding"].contains(key) { throw VPNError("HTTP 重复响应分帧头无效。") } else { headers[key] = old + ", " + value } } else { headers[key] = value }
    }
    let payload = Data(bytes[boundary.upperBound...])
    if (100..<200).contains(status) { guard status == 100 else { throw VPNError("HTTP 协议升级不受支持。") }; return try decodeHTTP(payload, eof: eof) }
    if status == 204 || status == 304 { return HTTPMessage(status: status, headers: headers, body: Data()) }
    if let transfer = headers["transfer-encoding"] {
        guard transfer.lowercased() == "chunked", headers["content-length"] == nil else { throw VPNError("HTTP 响应分帧无效。") }
        var offset = payload.startIndex; var body = Data()
        while true {
            guard let end = payload.range(of: Data("\r\n".utf8), in: offset..<payload.endIndex) else { if eof { throw VPNError("HTTP 分块响应不完整。") }; return nil }
            guard let line = String(data: payload[offset..<end.lowerBound], encoding: .ascii), let size = Int(line.components(separatedBy: ";")[0], radix: 16), size >= 0, size <= 2 * 1024 * 1024, body.count + size <= 2 * 1024 * 1024 else { throw VPNError("HTTP 分块大小无效。") }
            offset = end.upperBound
            if size == 0 { guard payload.count >= offset + 2 else { if eof { throw VPNError("HTTP 分块响应不完整。") }; return nil }; return HTTPMessage(status: status, headers: headers, body: body) }
            guard payload.count >= offset + size + 2 else { if eof { throw VPNError("HTTP 分块响应不完整。") }; return nil }
            guard payload[(offset+size)..<(offset+size+2)] == Data("\r\n".utf8) else { throw VPNError("HTTP 分块响应无效。") }
            body.append(payload[offset..<(offset+size)]); offset += size + 2
        }
    }
    if let length = headers["content-length"] {
        guard let count = Int(length), count >= 0, count <= 2 * 1024 * 1024 else { throw VPNError("HTTP 响应大小无效。") }
        if payload.count < count { if eof { throw VPNError("HTTP 响应不完整。") }; return nil }
        return HTTPMessage(status: status, headers: headers, body: Data(payload.prefix(count)))
    }
    guard payload.count <= 2 * 1024 * 1024 else { throw VPNError("服务器响应过大。") }
    return eof ? HTTPMessage(status: status, headers: headers, body: payload) : nil
}
final class HTTPExchange: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "dev.connectlab.http")
    private let wire: Data
    private var continuation: CheckedContinuation<HTTPMessage, Error>?
    private var buffer = Data()
    private var cancelled = false
    private var finished = false
    init(request: URLRequest, allowedOrigin: URL) throws {
        guard let url = request.url, url.scheme == "http", sameOrigin(url, allowedOrigin), let host = url.host, let port = NWEndpoint.Port(rawValue: UInt16(url.port ?? 80)), let c = URLComponents(url: url, resolvingAgainstBaseURL: false) else { throw VPNError("HTTP 登录地址无效。") }
        connection = NWConnection(host: NWEndpoint.Host(host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))), port: port, using: .tcp)
        let path = (c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath) + (c.percentEncodedQuery.map { "?\($0)" } ?? "")
        let body = request.httpBody ?? Data()
        var headers = request.allHTTPHeaderFields ?? [:]
        headers["Host"] = host + (url.port.map { ":\($0)" } ?? ""); headers["Connection"] = "close"; headers["Accept-Encoding"] = "identity"; headers["Content-Length"] = String(body.count)
        for (key, value) in headers { guard !key.isEmpty, !key.contains(":"), !key.contains("\r"), !key.contains("\n"), !value.contains("\r"), !value.contains("\n"), !value.contains("\0") else { throw VPNError("HTTP 请求头无效。") } }
        wire = Data(("\(request.httpMethod ?? "GET") \(path) HTTP/1.1\r\n" + headers.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)\r\n" }.joined() + "\r\n").utf8) + body
    }
    func perform() async throws -> HTTPMessage {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    guard !cancelled else { continuation.resume(throwing: CancellationError()); return }
                    self.continuation = continuation
                    connection.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        if case .ready = state { self.connection.send(content: self.wire, completion: .contentProcessed { [weak self] error in guard let self else { return }; if let error { self.finish(.failure(error)) } else { self.receive() } }) }
                        if case .failed(let error) = state { self.finish(.failure(error)) }
                    }
                    connection.start(queue: queue)
                    queue.asyncAfter(deadline: .now() + 30) { [weak self] in self?.finish(.failure(VPNError("连接超时，请检查服务器和网络。"))) }
                }
            }
        }, onCancel: { [self] in queue.async { [self] in cancelled = true; finish(.failure(CancellationError())) } })
    }
    private func receive() {
        guard !finished else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, eof, error in
            guard let self, !self.finished else { return }
            if let error { self.finish(.failure(error)); return }
            if let data { self.buffer.append(data) }
            do { if let message = try decodeHTTP(self.buffer, eof: eof) { self.finish(.success(message)) } else { self.receive() } } catch { self.finish(.failure(error)) }
        }
    }
    private func finish(_ result: Result<HTTPMessage, Error>) {
        guard !finished else { return }; finished = true; connection.cancel(); continuation?.resume(with: result); continuation = nil; buffer = Data()
    }
}
