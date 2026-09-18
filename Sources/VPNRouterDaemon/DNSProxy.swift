import Foundation
import Network
import VPNRouterCore

/// Upstream selection has to be readable from the proxy's own queue: the
/// coordinator actor can be sitting inside a synchronous name lookup that only
/// finishes once we answer it, so asking the actor here would deadlock.
final class UpstreamTable: @unchecked Sendable {
    struct Plan: Sendable {
        var ruleSet: RuleSet
        var corporate: [String]
        var direct: [String]
        var amneziaWG: [String]
    }

    private let lock = NSLock()
    private var plan: Plan?

    func update(_ newPlan: Plan) {
        lock.lock(); defer { lock.unlock() }
        plan = newPlan
    }

    /// Whether an answer for this name can still change the routing tables.
    /// Checked on the proxy's own queue so that ordinary browsing, which the
    /// default route already covers, never waits behind the coordinator.
    func tracksAddresses(for domain: String) -> Bool {
        lock.lock()
        let plan = self.plan
        lock.unlock()
        guard let plan else { return false }
        return plan.ruleSet.classify(domain: domain) != .amneziaWG
    }

    /// An empty list means "refuse": either we are not running yet, or the class
    /// has no reachable resolver. Never silently falls back to another class's
    /// server. More than one entry is a failover list, tried in order.
    func servers(for domain: String) -> [String] {
        lock.lock()
        let plan = self.plan
        lock.unlock()
        guard let plan else { return [] }
        switch plan.ruleSet.classify(domain: domain) {
        case .corporate: return plan.corporate
        case .direct: return plan.direct
        case .amneziaWG: return plan.amneziaWG
        }
    }
}

final class DNSProxy: @unchecked Sendable {
    // Must be 53: `networksetup -setdnsservers` takes an address and no port, so
    // the system resolver can only ever reach us here. The /etc/resolver files
    // carry whatever this says, so both paths stay on one number.
    static let port: NWEndpoint.Port = 53
    private static let upstreamPort: NWEndpoint.Port = 53
    // Two servers per class at two seconds each keeps the worst case under the
    // five seconds a client typically waits before giving up on us.
    private static let perServerTimeout: TimeInterval = 2

    private let queue = DispatchQueue(label: "com.vpnrouter.dns")
    private let upstreams: UpstreamTable
    private let didReceiveResponse: @Sendable (Data, String) async -> Void
    private var udpListener: NWListener?
    private var tcpListener: NWListener?

    init(
        upstreams: UpstreamTable,
        didReceiveResponse: @escaping @Sendable (Data, String) async -> Void
    ) {
        self.upstreams = upstreams
        self.didReceiveResponse = didReceiveResponse
    }

    // Binding the wildcard address would expose the resolver to the whole LAN;
    // the PF anchor only filters outbound traffic and would not cover it.
    private static func loopback(_ parameters: NWParameters) -> NWParameters {
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
        return parameters
    }

    /// Waits for the bind to actually succeed: an occupied port fails the listener
    /// asynchronously, and reporting that as success would leave the system
    /// resolver pointing at a socket nobody is holding.
    func start() async throws {
        let udp = try NWListener(using: Self.loopback(.udp))
        let tcp = try NWListener(using: Self.loopback(.tcp))
        udp.newConnectionHandler = { [weak self] in self?.acceptUDP($0) }
        tcp.newConnectionHandler = { [weak self] in self?.acceptTCP($0) }
        udpListener = udp
        tcpListener = tcp
        do {
            try await ready(udp)
            try await ready(tcp)
        } catch {
            stop()
            throw error
        }
    }

    private func ready(_ listener: NWListener) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let once = OneShot(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: once.finish(nil)
                case .failed(let error): once.finish(error)
                case .cancelled: once.finish(CancellationError())
                default: break
                }
            }
            listener.start(queue: queue)
        }
    }

    func stop() {
        udpListener?.cancel()
        tcpListener?.cancel()
        udpListener = nil
        tcpListener = nil
    }

    private func acceptUDP(_ client: NWConnection) {
        client.stateUpdateHandler = { [weak self, weak client] state in
            if case .ready = state, let client { self?.receiveUDP(from: client) }
        }
        client.start(queue: queue)
        // A query from a fresh source port is a flow of its own, and nothing ever
        // closes a UDP flow, so they piled up for the daemon's whole life. Every
        // answer is due within the two servers' timeouts; a flow this old is done.
        queue.asyncAfter(deadline: .now() + 30) { client.cancel() }
    }

    private func receiveUDP(from client: NWConnection) {
        client.receiveMessage { [weak self, weak client] data, _, _, error in
            guard let self, let client else { return }
            if let data { self.forwardUDP(data, to: client) }
            // A cancelled flow fails every receive at once: looping on it would spin.
            if error == nil { self.receiveUDP(from: client) }
        }
    }

    private func forwardUDP(_ query: Data, to client: NWConnection) {
        guard let name = try? DNSMessage.parse(query).questions.first?.name else {
            failUDP(query, to: client)
            return
        }
        startUDPForward(query, name: name, servers: upstreams.servers(for: name)[...], client: client)
    }

    /// Tries the class's resolvers in order and answers SERVFAIL once they are
    /// exhausted, so a dead first server costs one timeout instead of the class.
    private func startUDPForward(_ query: Data, name: String, servers: ArraySlice<String>, client: NWConnection) {
        guard let server = servers.first else { failUDP(query, to: client); return }
        let connection = NWConnection(host: NWEndpoint.Host(server), port: Self.upstreamPort, using: .udp)
        let once = Once()
        let next: @Sendable () -> Void = { [weak self, weak client] in
            guard once.claim() else { return }
            connection.cancel()
            guard let self, let client else { return }
            self.startUDPForward(query, name: name, servers: servers.dropFirst(), client: client)
        }
        connection.stateUpdateHandler = { [weak self, weak client] state in
            guard let self, let client else { return }
            switch state {
            case .ready:
                connection.send(content: query, completion: .contentProcessed { error in
                    guard error == nil else { next(); return }
                    connection.receiveMessage { response, _, _, _ in
                        guard let response, once.claim() else { next(); return }
                        let deliver = {
                            client.send(content: response, completion: .contentProcessed { _ in })
                            connection.cancel()
                        }
                        guard self.upstreams.tracksAddresses(for: name) else {
                            // Only the traffic view's names need this one, so the
                            // answer goes out without waiting on the actor.
                            Task { await self.didReceiveResponse(response, name) }
                            return deliver()
                        }
                        // The route and the PF pass must exist before the client
                        // learns the address, so this answer waits on the actor.
                        Task {
                            await self.didReceiveResponse(response, name)
                            deliver()
                        }
                    }
                })
            case .failed, .cancelled: next()
            default: break
            }
        }
        connection.start(queue: queue)
        // Also the teardown: the state handler holds `next`, which holds the
        // connection, so the cycle has to be broken whichever way this ended.
        queue.asyncAfter(deadline: .now() + Self.perServerTimeout) {
            next()
            connection.stateUpdateHandler = nil
        }
    }

    private func acceptTCP(_ client: NWConnection) {
        client.stateUpdateHandler = { [weak self, weak client] state in
            if case .ready = state, let client { self?.receiveTCPQuery(from: client) }
        }
        client.start(queue: queue)
    }

    private func receiveTCPQuery(from client: NWConnection) {
        receiveExactly(2, from: client) { [weak self, weak client] header in
            guard let self, let client, let header, header.count == 2 else { client?.cancel(); return }
            let length = Int(header[header.startIndex]) << 8 | Int(header[header.index(after: header.startIndex)])
            guard length > 0, length <= 65_535 else { client.cancel(); return }
            self.receiveExactly(length, from: client) { [weak self, weak client] query in
                guard let self, let client, let query else { client?.cancel(); return }
                self.forwardTCP(query, to: client)
            }
        }
    }

    private func forwardTCP(_ query: Data, to client: NWConnection) {
        guard let name = try? DNSMessage.parse(query).questions.first?.name else {
            failTCP(query, to: client)
            return
        }
        startTCPForward(query, name: name, servers: upstreams.servers(for: name)[...], client: client)
    }

    private func startTCPForward(_ query: Data, name: String, servers: ArraySlice<String>, client: NWConnection) {
        guard let server = servers.first else { failTCP(query, to: client); return }
        let upstream = NWConnection(host: NWEndpoint.Host(server), port: Self.upstreamPort, using: .tcp)
        let once = Once()
        let next: @Sendable () -> Void = { [weak self, weak client] in
            guard once.claim() else { return }
            upstream.cancel()
            guard let self, let client else { return }
            self.startTCPForward(query, name: name, servers: servers.dropFirst(), client: client)
        }
        upstream.stateUpdateHandler = { [weak self, weak client] state in
            guard let self, let client else { return }
            guard case .ready = state else {
                if case .failed = state { next() }
                if case .cancelled = state { next() }
                return
            }
            upstream.send(content: Self.framed(query), completion: .contentProcessed { error in
                guard error == nil else { next(); return }
                self.receiveExactly(2, from: upstream) { header in
                    guard let header, header.count == 2 else { next(); return }
                    let size = Int(header[header.startIndex]) << 8 | Int(header[header.index(after: header.startIndex)])
                    guard size > 0 else { next(); return }
                    self.receiveExactly(size, from: upstream) { response in
                        guard let response, once.claim() else { next(); return }
                        let deliver = {
                            client.send(content: Self.framed(response), completion: .contentProcessed { _ in
                                upstream.cancel()
                                client.cancel()
                            })
                        }
                        guard self.upstreams.tracksAddresses(for: name) else {
                            // Only the traffic view's names need this one, so the
                            // answer goes out without waiting on the actor.
                            Task { await self.didReceiveResponse(response, name) }
                            return deliver()
                        }
                        Task {
                            await self.didReceiveResponse(response, name)
                            deliver()
                        }
                    }
                }
            })
        }
        upstream.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.perServerTimeout) {
            next()
            upstream.stateUpdateHandler = nil
        }
    }

    // A query we cannot forward is answered, not dropped: silence costs the
    // client its own multi-second timeout on a name we already know will fail.
    private func failUDP(_ query: Data, to client: NWConnection) {
        let failure = DNSMessage.serverFailure(for: query)
        guard !failure.isEmpty else { return }
        client.send(content: failure, completion: .contentProcessed { _ in })
    }

    private func failTCP(_ query: Data, to client: NWConnection) {
        let failure = DNSMessage.serverFailure(for: query)
        guard !failure.isEmpty else { client.cancel(); return }
        client.send(content: Self.framed(failure), completion: .contentProcessed { _ in client.cancel() })
    }

    private static func framed(_ message: Data) -> Data {
        var frame = Data([UInt8(message.count >> 8), UInt8(message.count & 0xff)])
        frame.append(message)
        return frame
    }

    private func receiveExactly(_ count: Int, from connection: NWConnection, completion: @escaping @Sendable (Data?) -> Void) {
        ExactReceiver(count: count, connection: connection, completion: completion).start()
    }
}

/// Guards a one-time transition — deliver the answer or move to the next server,
/// never both — against a timeout racing the upstream's own callbacks.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}

/// A listener reports its state more than once — ready now, failed later — and a
/// continuation may only be resumed once.
private final class OneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?

    init(_ continuation: CheckedContinuation<Void, Error>) { self.continuation = continuation }

    func finish(_ error: Error?) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        guard let pending else { return }
        if let error { pending.resume(throwing: error) } else { pending.resume() }
    }
}

private final class ExactReceiver: @unchecked Sendable {
    private let count: Int
    private let connection: NWConnection
    private let completion: @Sendable (Data?) -> Void
    private var data = Data()

    init(count: Int, connection: NWConnection, completion: @escaping @Sendable (Data?) -> Void) {
        self.count = count
        self.connection = connection
        self.completion = completion
    }

    func start() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - data.count) { [self] chunk, _, complete, error in
            if let chunk { data.append(chunk) }
            if data.count == count { completion(data) }
            else if complete || error != nil { completion(nil) }
            else { start() }
        }
    }
}
