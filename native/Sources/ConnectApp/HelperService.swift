import Foundation
import Security
import Darwin

func clientCodeHash() throws -> String {
    var code: SecCode?; var staticCode: SecStaticCode?; var info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dictionary = info as? [String: Any], let data = dictionary[kSecCodeInfoUnique as String] as? Data else { throw VPNError("无法验证当前应用身份。") }
    return data.map { String(format: "%02x", $0) }.joined()
}
func serviceManifestPath(_ uid: uid_t) -> String { "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-\(uid).json" }
func serviceInstalled(uid: uid_t, client: String, helper: String, broker: String) -> Bool {
    let path = serviceManifestPath(uid); var value = stat()
    guard lstat(path, &value) == 0, value.st_uid == 0, value.st_mode & S_IFMT == S_IFREG, value.st_mode & 0o022 == 0,
          let data = FileManager.default.contents(atPath: path), let record = try? JSONSerialization.jsonObject(with: data) as? [String: String] else { return false }
    return record == ["client": client, "helper": helper, "broker": broker]
}
func serviceInstallScript(helper: String, helperHash: String, broker: String, brokerHash: String, clientHash: String, uid: uid_t) throws -> String {
    guard uid > 0, helperHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, brokerHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, clientHash.range(of: "^[a-f0-9]{40}$", options: .regularExpression) != nil else { throw VPNError("后台服务安装参数无效。") }
    let root = "/Library/PrivilegedHelperTools", label = "dev.connectlab.mchip-vpn.\(uid)"
    let helperDest = root + "/dev.connectlab.mchip-vpn-helper", brokerDest = root + "/dev.connectlab.mchip-vpn-broker"
    let plist = "/Library/LaunchDaemons/\(label).plist"
    let values: [String: Any] = ["Label": label, "ProgramArguments": [brokerDest, String(uid), clientHash, helperDest], "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 10]
    let xml = String(decoding: try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0), as: UTF8.self)
    let manifest = String(decoding: try JSONSerialization.data(withJSONObject: ["client": clientHash, "helper": helperHash, "broker": brokerHash]), as: UTF8.self)
    func install(_ source: String, _ destination: String, _ hash: String) -> String { """
    [ ! -L \(shellQuote(destination)) ] || exit 70
    tmp=$(/usr/bin/mktemp '\(root)/.connect.XXXXXX')
    trap '/bin/rm -f "$tmp"' EXIT HUP INT TERM
    /bin/cp -X \(shellQuote(source)) "$tmp"
    /usr/sbin/chown root:wheel "$tmp"; /bin/chmod 0755 "$tmp"
    actual=$(/usr/bin/shasum -a 256 "$tmp")
    [ "${actual%% *}" = \(shellQuote(hash)) ] || exit 71
    /usr/bin/codesign --verify --strict "$tmp" >/dev/null 2>&1
    /bin/mv -f "$tmp" \(shellQuote(destination))
    trap - EXIT HUP INT TERM
    """ }
    return """
    set -eu
    for dir in '\(root)' '/Library/LaunchDaemons'; do
      [ ! -L "$dir" ] || exit 70
      if [ ! -e "$dir" ]; then /usr/bin/install -d -o root -g wheel -m 0755 "$dir"; fi
      [ -d "$dir" ] && [ "$(/usr/bin/stat -f %u "$dir")" = 0 ] || exit 70
      perm=$(/usr/bin/stat -f %Lp "$dir"); [ $((0$perm & 0022)) = 0 ] || exit 70
    done
    /bin/launchctl bootout system/\(label) >/dev/null 2>&1 || true
    \(install(helper, helperDest, helperHash))
    \(install(broker, brokerDest, brokerHash))
    [ ! -L \(shellQuote(plist)) ] && [ ! -L \(shellQuote(serviceManifestPath(uid))) ] || exit 70
    /usr/bin/printf '%s' \(shellQuote(xml)) > \(shellQuote(plist))
    /usr/sbin/chown root:wheel \(shellQuote(plist)); /bin/chmod 0644 \(shellQuote(plist))
    /bin/launchctl bootstrap system \(shellQuote(plist))
    /usr/bin/printf '%s' \(shellQuote(manifest)) > \(shellQuote(serviceManifestPath(uid)))
    /usr/sbin/chown root:wheel \(shellQuote(serviceManifestPath(uid))); /bin/chmod 0644 \(shellQuote(serviceManifestPath(uid)))
    """
}

@MainActor func persistentServiceSmoke() async throws {
    let resources = Bundle.main.resourceURL!
    let helper = resources.appendingPathComponent("bin/mchip-vpn-helper")
    let broker = resources.appendingPathComponent("bin/mchip-vpn-broker")
    let helperHash = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-helper.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    let brokerHash = try String(contentsOf: resources.appendingPathComponent("bin/mchip-vpn-broker.sha256"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    let uid = getuid(), identity = try clientCodeHash()
    let script = try serviceInstallScript(helper: helper.path, helperHash: helperHash, broker: broker.path, brokerHash: brokerHash, clientHash: identity, uid: uid)
    // Only the CI smoke entry uses sudo; production installation uses the system authorization dialog.
    let installer = Process(); installer.executableURL = URL(fileURLWithPath: "/usr/bin/sudo"); installer.arguments = ["/bin/sh", "-c", script]; installer.standardOutput = FileHandle.nullDevice
    try installer.run()
    while installer.isRunning { try await Task.sleep(nanoseconds: 50_000_000) }
    guard installer.terminationStatus == 0 else { throw VPNError("Service smoke installation failed") }
    defer {
        let remove = Process(); remove.executableURL = URL(fileURLWithPath: "/usr/bin/sudo"); remove.arguments = ["/bin/sh", "-c", "/bin/launchctl bootout system/dev.connectlab.mchip-vpn.\(uid); /bin/rm -f /Library/LaunchDaemons/dev.connectlab.mchip-vpn.\(uid).plist \(shellQuote(serviceManifestPath(uid)))"]; try? remove.run(); if remove.isRunning { remove.waitUntilExit() }
    }
    guard serviceInstalled(uid: uid, client: identity, helper: helperHash, broker: brokerHash) else { throw VPNError("Service manifest check failed") }
    let untrusted = Process(); untrusted.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    untrusted.arguments = ["-c", "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control/\(uid)-service.sock'); assert b'SERVICE_IDENTITY_REJECTED' in s.recv(4096)"]
    // Wait for launchd before checking a different executable with the same UID.
    for _ in 0..<200 { if FileManager.default.fileExists(atPath: "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control/\(uid)-service.sock") { break }; try await Task.sleep(nanoseconds: 50_000_000) }
    try untrusted.run(); while untrusted.isRunning { try await Task.sleep(nanoseconds: 50_000_000) }
    guard untrusted.terminationStatus == 0 else { throw VPNError("Untrusted-client rejection failed") }
    for _ in 0..<2 {
        var control: FileHandle?
        for _ in 0..<200 {
            control = try connectSocket("/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-control/\(uid)-service.sock", uid: uid)
            if control != nil { break }; try await Task.sleep(nanoseconds: 50_000_000)
        }
        guard let control else { throw VPNError("Service socket unavailable") }
        try await brokerHandshake(control)
        try control.write(contentsOf: Data("{\"mode\":\"recover\"}\n".utf8))
        let bytes = try await Task.detached { try readHelperChunk(control) }.value
        try? control.close()
        guard let bytes, String(decoding: bytes, as: UTF8.self).contains("stopped") else { throw VPNError("Service rejected trusted client") }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    let controller = VPNController()
    // Exercise the production controller, including a failed loopback-only tunnel.
    // No gateway credentials or private network are used by this smoke test.
    try await controller.recoverNetwork()
    try await controller.recoverNetwork()
    guard controller.state == "disconnected" else { throw VPNError("Recovery did not release controller state") }
    do {
        try await controller.start(host: "127.0.0.1", port: 1, sessionID: "ci-smoke", mode: "tun", socksPort: 0, httpPort: 0)
        throw VPNError("Loopback failure unexpectedly connected")
    } catch {
        guard controller.state == "disconnected", controller.detail != VPNController.message("CLEANUP_FAILED") else { throw VPNError("Failed connection did not release control state") }
    }
    try await controller.recoverNetwork()
    guard controller.state == "disconnected" else { throw VPNError("Recovery after failure was not reusable") }
    print("Persistent service reuse, failed tunnel cleanup and controller recovery passed")
}
