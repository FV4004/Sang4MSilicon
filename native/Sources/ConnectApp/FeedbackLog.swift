import Foundation
import AppKit

enum FeedbackLog {
    static func canCopy(_ text: String, loginSucceeded: Bool) -> Bool {
        !loginSucceeded && !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    static func report(message: String, loginMessage: String, loginSucceeded: Bool, vpnDetail: String) -> String {
        var parts: [String] = []
        if !(loginSucceeded && message == loginMessage), !message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            parts.append(message)
        }
        if !vpnDetail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !parts.contains(vpnDetail) {
            parts.append(vpnDetail)
        }
        return parts.joined(separator: "\n\n")
    }
    static func withDiagnostic(_ text: String, diagnostic: String) -> String {
        guard !diagnostic.isEmpty, !text.contains(diagnostic) else { return text }
        return text + "\n通道诊断：" + diagnostic
    }
    @MainActor static func copy(_ text: String, to pasteboard: NSPasteboard = .general) -> Bool {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        pasteboard.clearContents()
        return pasteboard.setString(text, forType: .string)
    }
}
