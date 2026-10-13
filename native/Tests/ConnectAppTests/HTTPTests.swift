import XCTest
import Network
@testable import ConnectApp

final class HTTPTests: XCTestCase {
    func testFramingAndSizeLimits() throws {
        let ordinary = Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".utf8)
        XCTAssertEqual(try decodeHTTP(ordinary)?.body, Data("hello".utf8))
        XCTAssertNil(try decodeHTTP(Data(ordinary.dropLast())))
        XCTAssertThrowsError(try decodeHTTP(Data(ordinary.dropLast()), eof: true))
        let chunked = Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".utf8)
        XCTAssertEqual(try decodeHTTP(chunked)?.body, Data("abcde".utf8))
        for bad in ["HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\naaa"] { XCTAssertThrowsError(try decodeHTTP(Data(bad.utf8))) }
    }
    func testPlainHTTPOnlyAllowsConfiguredOrigin() throws {
        let origin = URL(string: "http://127.0.0.1:8080")!
        XCTAssertThrowsError(try HTTPExchange(request: URLRequest(url: URL(string: "http://other.example")!), allowedOrigin: origin))
        XCTAssertThrowsError(try HTTPExchange(request: URLRequest(url: URL(string: "https://127.0.0.1:8080")!), allowedOrigin: origin))
        var request = URLRequest(url: origin); request.setValue("bad\r\nInjected: value", forHTTPHeaderField: "X-Test")
        XCTAssertThrowsError(try HTTPExchange(request: request, allowedOrigin: origin))
    }
    func testConfiguredHTTPOriginOverLoopback() async throws {
        let listener = try NWListener(using: .tcp, on: .any)
        let queue = DispatchQueue(label: "dev.connectlab.http-test")
        let port: NWEndpoint.Port = try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                if case .ready = state, let port = listener.port { continuation.resume(returning: port) }
                if case .failed(let error) = state { continuation.resume(throwing: error) }
            }
            listener.newConnectionHandler = { connection in
                connection.start(queue: queue)
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { _, _, _, _ in
                    let response = Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: SID=abc; Path=/\r\n\r\nhello".utf8)
                    connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            listener.start(queue: queue)
        }
        defer { listener.cancel() }
        let origin = URL(string: "http://127.0.0.1:\(port.rawValue)")!
        let response = try await HTTPExchange(request: URLRequest(url: origin.appendingPathComponent("por/login_auth.csp")), allowedOrigin: origin).perform()
        XCTAssertEqual(response.status, 200); XCTAssertEqual(response.body, Data("hello".utf8)); XCTAssertEqual(response.headers["set-cookie"], "SID=abc; Path=/")
    }
}
