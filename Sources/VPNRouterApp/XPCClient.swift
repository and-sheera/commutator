import Foundation
import VPNRouterCore

final class XPCClient: @unchecked Sendable {
    /// Screenshot mode: a click there must not reach the real daemon on this Mac.
    static let isDemo = ProcessInfo.processInfo.environment["VPNROUTER_DEMO"] == "1"
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    func request<T: Decodable>(_ operation: IPCOperation, payload: (any Encodable)? = nil, as type: T.Type) async throws -> T {
        guard !Self.isDemo else { throw RouterErrorInfo(.helperUnavailable, "Демо-режим: системный компонент не используется") }
        let payloadData = try payload.map(AnyEncodable.init).map { try IPCCodec.encoder.encode($0) }
        let data = try IPCCodec.encoder.encode(IPCRequest(operation, payload: payloadData))
        let responseData: Data = try await withCheckedThrowingContinuation { continuation in
            let reply = XPCReply(continuation)
            let proxy = remoteProxy { _ in
                reply.resume(throwing: RouterErrorInfo(
                    .helperUnavailable,
                    "Встроенный системный компонент Коммутатора ещё не разрешён в настройках macOS"
                ))
            }
            proxy?.request(data) { response in reply.resume(returning: response) }
            if proxy == nil { reply.resume(throwing: RouterErrorInfo(.helperUnavailable, "Helper недоступен")) }
        }
        let response = try IPCCodec.decoder.decode(IPCResponse.self, from: responseData)
        if let error = response.error { throw error }
        guard let responsePayload = response.payload else { throw RouterErrorInfo(.internalError, "Helper вернул пустой ответ") }
        return try IPCCodec.decoder.decode(T.self, from: responsePayload)
    }

    private func remoteProxy(errorHandler: @escaping @Sendable (Error) -> Void) -> VPNRouterDaemonXPC? {
        lock.lock()
        if connection == nil {
            let newConnection = NSXPCConnection(machServiceName: "com.vpnrouter.daemon", options: .privileged)
            newConnection.remoteObjectInterface = NSXPCInterface(with: VPNRouterDaemonXPC.self)
            newConnection.invalidationHandler = { [weak self] in self?.reset() }
            newConnection.interruptionHandler = { [weak self] in self?.reset() }
            newConnection.resume()
            connection = newConnection
        }
        let active = connection
        lock.unlock()
        return active?.remoteObjectProxyWithErrorHandler(errorHandler) as? VPNRouterDaemonXPC
    }

    private func reset() {
        lock.lock(); connection = nil; lock.unlock()
    }
}

private final class XPCReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?

    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }

    func resume(returning data: Data) {
        take()?.resume(returning: data)
    }

    func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Data, Error>? {
        lock.lock()
        defer { lock.unlock() }
        defer { continuation = nil }
        return continuation
    }
}

private struct AnyEncodable: Encodable {
    private let encodeValue: (Encoder) throws -> Void
    init(_ value: any Encodable) { encodeValue = value.encode }
    func encode(to encoder: Encoder) throws { try encodeValue(encoder) }
}
