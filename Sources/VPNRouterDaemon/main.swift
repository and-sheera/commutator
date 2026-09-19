import Foundation
import Network
import SystemConfiguration
import VPNRouterCore

let coordinator = RouterCoordinator()
let service = DaemonService(coordinator: coordinator)
let delegate = ListenerDelegate(service: service)
let listener = NSXPCListener(machServiceName: "com.vpnrouter.daemon")
listener.delegate = delegate
listener.resume()

let monitor = NWPathMonitor()
monitor.pathUpdateHandler = { _ in Task { await coordinator.networkChanged() } }
monitor.start(queue: DispatchQueue(label: "com.vpnrouter.network"))

// launchd stops the daemon with SIGTERM: on bootout, reinstall and shutdown.
signal(SIGTERM, SIG_IGN)
let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
termination.setEventHandler { Task { await coordinator.shutdown(); exit(0) } }
termination.resume()
RunLoop.current.run()

final class DaemonService: NSObject, VPNRouterDaemonXPC, @unchecked Sendable {
    private let coordinator: RouterCoordinator

    init(coordinator: RouterCoordinator) { self.coordinator = coordinator }

    func request(_ data: Data, withReply reply: @escaping (Data) -> Void) {
        let coordinator = coordinator
        let reply = ReplyBox(reply)
        Task {
            let response: IPCResponse
            do {
                let request = try IPCCodec.decoder.decode(IPCRequest.self, from: data)
                response = await coordinator.handle(request)
            } catch {
                response = .init(error: .init(.invalidConfiguration, "Некорректный XPC-запрос"))
            }
            reply.call((try? IPCCodec.encoder.encode(response)) ?? Data())
        }
    }
}

private final class ReplyBox: @unchecked Sendable {
    private let closure: (Data) -> Void
    init(_ closure: @escaping (Data) -> Void) { self.closure = closure }
    func call(_ data: Data) { closure(data) }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: DaemonService
    init(service: DaemonService) { self.service = service }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard allowedUID(connection.effectiveUserIdentifier) else { return false }
        if ProcessInfo.processInfo.environment["VPNROUTER_ALLOW_UNSIGNED"] != "1" {
            // The identifier alone is forgeable with an ad-hoc signature, so without
            // a team ID or a certificate pin we refuse instead of trusting the name.
            guard let requirement = Self.clientRequirement() else { return false }
            // Checked by the system against the audit token of every message, not
            // against a pid that could have been reused by the time we looked.
            connection.setCodeSigningRequirement(requirement)
        }
        connection.exportedInterface = NSXPCInterface(with: VPNRouterDaemonXPC.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }

    private func allowedUID(_ uid: uid_t) -> Bool {
        if getuid() != 0 { return uid == getuid() }
        var consoleUID: uid_t = 0
        var consoleGID: gid_t = 0
        guard let user = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID) as String?, user != "loginwindow" else { return false }
        return uid == consoleUID
    }

    /// A team ID only counts under Apple's anchor: without it, any self-made
    /// certificate can claim one. A local certificate is pinned by its hash.
    static func clientRequirement() -> String? {
        let environment = ProcessInfo.processInfo.environment
        let identifier = environment["VPNROUTER_ALLOWED_CLIENT_ID"] ?? "com.vpnrouter.app"
        if let team = environment["VPNROUTER_TEAM_ID"], !team.isEmpty {
            return "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        }
        if let hash = environment["VPNROUTER_CERT_SHA1"], !hash.isEmpty {
            return "identifier \"\(identifier)\" and certificate leaf = H\"\(hash.lowercased())\""
        }
        return nil
    }
}
