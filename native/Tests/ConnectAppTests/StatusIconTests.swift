import XCTest
import AppKit
@testable import ConnectApp

final class StatusIconTests: XCTestCase {
    @MainActor func testStatusIconIsSystemColoredVectorTemplate() throws {
        for name in [NSAppearance.Name.aqua, .darkAqua] {
            let appearance = try XCTUnwrap(NSAppearance(named: name))
            appearance.performAsCurrentDrawingAppearance {
                let image = StatusIcon.make()
                XCTAssertTrue(image.isTemplate)
                XCTAssertTrue(image.isValid)
                XCTAssertEqual(image.size, NSSize(width: 24, height: 18))
                XCTAssertNotNil(image.tiffRepresentation)
            }
        }
    }
}
