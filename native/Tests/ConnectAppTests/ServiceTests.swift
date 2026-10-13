import XCTest
@testable import ConnectApp
final class ServiceTests: XCTestCase {
    func testServicePinsIdentityAndInstallsOnlyVerifiedBinaries() throws {
        let script = try serviceInstallScript(helper: "/Applications/User's Connect.app/helper", helperHash: String(repeating: "a", count: 64), broker: "/Applications/Connect.app/broker", brokerHash: String(repeating: "b", count: 64), clientHash: String(repeating: "c", count: 40), uid: 501)
        XCTAssertTrue(script.contains("User'\\''s")); XCTAssertTrue(script.contains("codesign --verify --strict")); XCTAssertTrue(script.contains("launchctl bootstrap system")); XCTAssertTrue(script.contains("<string>" + String(repeating: "c", count: 40) + "</string>")); XCTAssertTrue(script.contains("root:wheel"))
        XCTAssertThrowsError(try serviceInstallScript(helper: "x", helperHash: "bad", broker: "x", brokerHash: "bad", clientHash: "bad", uid: 0))
    }
}
