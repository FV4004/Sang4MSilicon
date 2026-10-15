import Foundation

@MainActor final class ShutdownCoordinator {
    private var task: Task<String?, Never>?
    func shutdown(cancel: @escaping () async -> Void, stopVPN: @escaping () async throws -> Void, drain: @escaping () async -> Void, closeWeb: @escaping () async -> Void, logout: @escaping () async throws -> Void, clear: @escaping () -> Void) async -> String? {
        if let task { return await task.value }
        let task = Task<String?, Never> {
            var errors: [String] = []
            await cancel()
            do { try await stopVPN() } catch { errors.append(error.localizedDescription) }
            await drain()
            await closeWeb()
            do { try await logout() } catch { errors.append("网关注销未确认：" + error.localizedDescription) }
            clear()
            return errors.isEmpty ? nil : Array(Set(errors)).sorted().joined(separator: "\n")
        }
        self.task = task
        return await task.value
    }
}
enum CloseAction: String { case quit, minimize, cancel
    static func remembered(_ value: String?) -> CloseAction? { guard let value, let action = CloseAction(rawValue: value), action != .cancel else { return nil }; return action }
}
