import Foundation
import Security
import Darwin

func digest(_ code: SecCode) throws -> String {
    var staticCode: SecStaticCode?; var info: CFDictionary?
    guard SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let values = info as? [String: Any], let unique = values[kSecCodeInfoUnique as String] as? Data else { throw NSError(domain: "ClientIdentity", code: 1) }
    return unique.map { String(format: "%02x", $0) }.joined()
}
func trusted(_ fd: Int32, uid: uid_t, hash: String) -> Bool {
    var user: uid_t = 0, group: gid_t = 0
    guard getpeereid(fd, &user, &group) == 0, user == uid else { return false }
    var pid: pid_t = 0; var size = socklen_t(MemoryLayout<pid_t>.size)
    guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else { return false }
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess, let code else { return false }
    return (try? digest(code)) == hash
}
func secure(_ path: String, directory: Bool = false) throws {
    var value = stat()
    guard lstat(path, &value) == 0, value.st_uid == 0, value.st_mode & 0o022 == 0,
          value.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) else { throw NSError(domain: "ServicePermissions", code: 1) }
}
func serve(_ fd: Int32, helper: String) {
    let client = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    var timeout = timeval(tv_sec: 20, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    defer { _ = Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
    let child = Process(), input = Pipe(), output = Pipe()
    child.executableURL = URL(fileURLWithPath: helper); child.arguments = ["--tun-stdio"]
    child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
    do { try child.run() } catch { return }
    let done = DispatchGroup(); done.enter()
    DispatchQueue.global().async {
        defer { _ = Darwin.shutdown(fd, SHUT_RDWR); done.leave() }
        var bytes = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = Darwin.read(output.fileHandleForReading.fileDescriptor, &bytes, bytes.count)
            if n <= 0 { break }
            do { try client.write(contentsOf: Data(bytes.prefix(n))) } catch { break }
        }
    }
    // Only a bounded configuration line followed by a stop line is accepted.
    var buffer = Data(); var configurationSent = false; var invalid = false; var bytes = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = Darwin.read(fd, &bytes, bytes.count); if n <= 0 { break }
        buffer.append(contentsOf: bytes.prefix(n)); if buffer.count > 8192 { break }
        while let end = buffer.firstIndex(of: 10) {
            let line = Data(buffer[..<end]); buffer.removeSubrange(...end)
            if configurationSent {
                guard let event = try? JSONSerialization.jsonObject(with: line) as? [String: String], event == ["event": "stop"] else { invalid = true; break }
            }
            do { try input.fileHandleForWriting.write(contentsOf: line + Data([10])) } catch { invalid = true; break }
            configurationSent = true
            var unlimited = timeval(tv_sec: 0, tv_usec: 0)
            _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &unlimited, socklen_t(MemoryLayout<timeval>.size))
        }
        if invalid { break }
    }
    try? input.fileHandleForWriting.close() // EOF cancels the worker and restores its routes/DNS.
    child.waitUntilExit(); done.wait()
    try? output.fileHandleForReading.close()
}
@main struct Broker {
    static func main() {
        let args = CommandLine.arguments
        guard geteuid() == 0, args.count == 4, let uid = uid_t(args[1]), uid > 0,
              args[2].range(of: "^[a-f0-9]{40}$", options: .regularExpression) != nil,
              args[3] == "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-helper" else { exit(64) }
        let path = "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control/\(uid)-service.sock"
        do {
            try secure(args[3]); try secure("/Library/PrivilegedHelperTools", directory: true)
            if mkdir("/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control", 0o755) != 0 && errno != EEXIST { exit(70) }
            try secure("/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control", directory: true)
        } catch { exit(70) }
        let listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0); guard listener >= 0 else { exit(71) }
        _ = unlink(path)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8) + [0]; withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0, chmod(path, 0o600) == 0, chown(path, uid, 0) == 0, Darwin.listen(listener, 4) == 0 else { exit(72) }
        while true {
            let fd = Darwin.accept(listener, nil, nil); if fd < 0 { if errno == EINTR { continue }; exit(73) }
            var noSignal: Int32 = 1; _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            guard trusted(fd, uid: uid, hash: args[2]) else { Darwin.close(fd); continue }
            // Sequential workers retain the existing global TUN lock and cleanup protocol.
            serve(fd, helper: args[3])
        }
    }
}
