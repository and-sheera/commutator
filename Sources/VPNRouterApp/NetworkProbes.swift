import Foundation
import Network
import VPNRouterCore

enum PingState: Equatable {
    case milliseconds(Double)
    case noReply
}

/// Where a check actually went, as the kernel tells it.
struct RouteCheck: Equatable {
    var host: String
    var address: String
    var interface: String?
    var milliseconds: Int?
    /// false: nothing answered on 443, and the interface is the routing
    /// table's account instead of the connection's.
    var connected: Bool
}

/// One request to an address-echo service and what it says about the path.
struct EchoResult: Equatable {
    var ip: String?
    var country: String?
    var city: String?
    /// The network the address belongs to: «AS24940 Hetzner Online GmbH».
    var org: String?
    var interface: String?
    var milliseconds: Int
}

/// nil in a field means that check got no answer.
struct ConnectionReport: Equatable {
    var com: EchoResult?
    var ru: EchoResult?
    var corporate: PingState?
    var checkedAt = Date()
}

enum NetworkProbes {
    /// Shows the address and country .com sites see.
    static let comCheck = URL(string: "https://cloudflare.com/cdn-cgi/trace")!
    /// Shows the address .ru sites see; its country comes from `geo`.
    static let ruCheck = URL(string: "https://yandex.ru/internet/api/v0/ip")!

    /// How long a server takes to answer, straight from this Mac: TCP to its
    /// port, or ICMP for Hysteria2, which listens on UDP. It says the server
    /// is reachable, not that the proxy on it works.
    static func serverPing(host: String, port: Int, udp: Bool) async -> PingState {
        if udp {
            let output = await run("/sbin/ping", ["-n", "-q", "-c", "1", "-t", "3", host])
            return PingOutput.averageMilliseconds(output).map { .milliseconds($0) } ?? .noReply
        }
        // Resolved first, so the time is the server's and not the resolver's.
        guard let address = await Task.detached(operation: { HostResolver.addresses(host).first }).value else { return .noReply }
        let started = ContinuousClock.now
        guard await connect(address, port: port, timeout: 3) != nil else { return .noReply }
        return .milliseconds(started.duration(to: .now) / .milliseconds(1))
    }

    /// Where an address is and whose network it is. The answer is about the
    /// address, not the path, so it may go whichever way the rules send it.
    static func geo(_ ip: String) async -> (country: String?, city: String?, org: String?)? {
        guard let url = URL(string: "https://ipinfo.io/\(ip)/json") else { return nil }
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
        guard let (data, _) = try? await session.data(for: request),
              let fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        func field(_ key: String) -> String? { (fields[key] as? String).flatMap { $0.isEmpty ? nil : $0 } }
        return (field("country"), field("city"), field("org"))
    }

    /// Bound to the tunnel interface, so a reply can only have come through it.
    static func ping(_ tunnel: TunnelStatus?) async -> PingState? {
        guard let tunnel, tunnel.phase == .connected, let interface = tunnel.interfaceName, let target = tunnel.probeAddress else { return nil }
        let output = await run("/sbin/ping", ["-n", "-q", "-c", "3", "-i", "0.2", "-t", "3", "-b", interface, target])
        return PingOutput.averageMilliseconds(output).map { .milliseconds($0) } ?? .noReply
    }

    /// Opens a real TCP connection to port 443, the way a browser would, and
    /// reads the interface from the local address the kernel picked for it.
    /// Resolving goes through the system resolver too, so a name from the rules
    /// gets its route installed exactly as it would for any other app.
    static func checkRoute(_ host: String) async throws -> RouteCheck {
        guard let address = await Task.detached(operation: { HostResolver.addresses(host).first }).value else {
            throw RouterErrorInfo(.invalidConfiguration, "Не удалось найти адрес «\(host)»")
        }
        let started = ContinuousClock.now
        if let local = await connect(address) {
            let elapsed = started.duration(to: .now) / .milliseconds(1)
            return .init(host: host, address: address, interface: interface(owning: local), milliseconds: Int(elapsed), connected: true)
        }
        let table = await run("/sbin/route", address.contains(":") ? ["-n", "get", "-inet6", address] : ["-n", "get", address])
        let interface = table.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix("interface:") }
            .map { $0.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces) }
        return .init(host: host, address: address, interface: interface, milliseconds: nil, connected: false)
    }

    /// An ordinary HTTPS request, routed like any browser's, on a connection of
    /// its own so the local address it reports belongs to this request.
    static func echo(_ url: URL) async -> EchoResult? {
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 8)
        // Plain-text answers are what these services give command-line clients.
        request.setValue("curl/8", forHTTPHeaderField: "User-Agent")
        let metrics = MetricsCollector()
        let started = ContinuousClock.now
        guard let (data, _) = try? await session.data(for: request, delegate: metrics) else { return nil }
        let elapsed = started.duration(to: .now) / .milliseconds(1)
        let body = String(decoding: data, as: UTF8.self)
        // Cloudflare's trace is "key=value" lines; Yandex answers a bare JSON string.
        let fields = Dictionary(body.split(separator: "\n").compactMap { line -> (String, String)? in
            let parts = line.split(separator: "=", maxSplits: 1)
            return parts.count == 2 ? (String(parts[0]), String(parts[1])) : nil
        }, uniquingKeysWith: { first, _ in first })
        let ip = fields["ip"] ?? body.trimmingCharacters(in: CharacterSet(charactersIn: "\" \n"))
        let local = metrics.localAddress.map { $0.split(separator: "%").first.map(String.init) ?? $0 }
        let address = IPAddress(ip) == nil ? nil : ip
        var geo: (country: String?, city: String?, org: String?)?
        if let address { geo = await Self.geo(address) }
        return .init(
            ip: address,
            country: fields["loc"] ?? geo?.country,
            city: geo?.city,
            org: geo?.org,
            interface: local.flatMap(interface(owning:)),
            milliseconds: Int(elapsed)
        )
    }

    private static func connect(_ address: String, port: Int = 443, timeout: Double = 5) async -> String? {
        guard let port = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return nil }
        let connection = NWConnection(host: .init(address), port: port, using: .tcp)
        defer { connection.cancel() }
        return await withCheckedContinuation { continuation in
            let once = Once(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard case .hostPort(let host, _)? = connection.currentPath?.localEndpoint else { return once.resume(nil) }
                    once.resume("\(host)".split(separator: "%").first.map(String.init))
                // A refused or blackholed port shows up as waiting, not failed.
                case .failed, .waiting, .cancelled: once.resume(nil)
                default: break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { once.resume(nil) }
        }
    }

    private static func interface(owning address: String) -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { return nil }
        defer { freeifaddrs(list) }
        var cursor = list
        while let entry = cursor?.pointee {
            defer { cursor = entry.ifa_next }
            guard let socket = entry.ifa_addr, [AF_INET, AF_INET6].contains(Int32(socket.pointee.sa_family)) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(socket, socklen_t(socket.pointee.sa_len), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let text = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if text.split(separator: "%").first.map(String.init) == address { return String(cString: entry.ifa_name) }
        }
        return nil
    }

    static func run(_ path: String, _ arguments: [String]) async -> String {
        await Task.detached {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            guard (try? process.run()) != nil else { return "" }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(decoding: data, as: UTF8.self)
        }.value
    }
}

private final class MetricsCollector: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var address: String?

    var localAddress: String? {
        lock.lock()
        defer { lock.unlock() }
        return address
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock()
        address = metrics.transactionMetrics.last?.localAddress
        lock.unlock()
    }
}

private final class Once<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Never>?

    init(_ continuation: CheckedContinuation<T, Never>) { self.continuation = continuation }

    func resume(_ value: T) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}

/// Who a connection belongs to: the app, even when one of its helper
/// processes opened it, and the process that did.
struct TrafficOwner: Sendable {
    var app: String
    var process: String
    var path: String?
    var pid: Int32

    /// nettop names the process, cut to 16 characters: «Google Chrome He».
    /// The executable's path names both it and the app around it.
    static func resolve(name: String, pid: Int32) -> TrafficOwner {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return .init(app: name, process: name, pid: pid) }
        let path = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let process = URL(fileURLWithPath: path).lastPathComponent
        // The outermost bundle: Chrome's renderer lives inside Google Chrome.app.
        let app = path.split(separator: "/").first { $0.hasSuffix(".app") }.map { String($0.dropLast(4)) }
        return .init(app: app ?? process, process: process, path: path, pid: pid)
    }

    var isSystem: Bool { path.map { $0.hasPrefix("/System/") || $0.hasPrefix("/usr/") } ?? false }
}

struct TrafficEntry: Identifiable {
    /// The daemon's DNS answer names the site; a PTR name only names the
    /// address's owner.
    enum NameSource { case dns, reverse }
    /// Why a connection outside our tunnels need not be a rule's doing: an open
    /// connection stays on the interface it was opened on.
    enum Early { case beforeTunnel, beforeRecording }

    let id = UUID()
    let time: Date
    let owner: TrafficOwner
    let flow: ObservedFlow
    var via: String
    var name: String?
    var nameSource: NameSource?
    var early: Early?
}

/// Every outbound connection with the interface the kernel reports for it,
/// read from `nettop`, which ships with every macOS. Kept in memory, newest
/// first, and capped, so it never grows past what is worth scrolling.
@MainActor
final class TrafficMonitor: ObservableObject {
    @Published private(set) var entries: [TrafficEntry] = []
    private let limit = 1000
    private let lookup: @Sendable ([String]) async -> [String: String]
    private var poller: Task<Void, Never>?
    private var tunnels: [String: String] = [:]
    /// PTR names by address, "" while asked or when there is none.
    private var reverse: [String: String] = [:]
    /// Whether what no rule claims had its tunnel when a sample came in.
    private var ready = false
    private var firstSample = true

    init(lookup: @escaping @Sendable ([String]) async -> [String: String]) { self.lookup = lookup }

    /// Records while routing is on, since only then is «через что» a question,
    /// and the user has switched recording on.
    func follow(_ status: RouterStatus, recording: Bool) {
        // Remembered rather than replaced: a poll that lands mid-reconnect has
        // no interface name, and forgetting ours then labelled our own flows
        // as some other program's tunnel.
        if let name = status.openVPN.interfaceName { tunnels[name] = VPNKind.openVPN.name }
        if let name = status.amneziaWG.interfaceName { tunnels[name] = VPNKind.amneziaWG.name }
        ready = status.protection == .protected || status.amneziaWG.phase == .connected
        // A fresh tunnel carries flows a sample or two before the status names
        // it; those rows were ours all along.
        for index in entries.indices where entries[index].via.hasPrefix("Чужой") {
            if let label = tunnels[entries[index].flow.interface] { entries[index].via = label }
        }
        status.desiredEnabled && recording ? start() : stop()
    }

    func clear() { entries.removeAll() }

    private func start() {
        guard poller == nil else { return }
        firstSample = true
        // One snapshot every two seconds rather than one long-running nettop:
        // left running (`-L 0`), it handles every ntstat event in between and
        // burns ~140% CPU, while a snapshot takes 0.07 s.
        // ponytail: a connection shorter than the interval can fall between
        // snapshots; shorten the sleep if that starts to matter.
        poller = Task.detached { [weak self] in
            var lastSeen: [String: Date] = [:]
            while !Task.isCancelled {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
                process.arguments = ["-L", "1", "-n", "-x", "-J", "interface,state"]
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                guard (try? process.run()) != nil else { return }
                let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                process.waitUntilExit()
                var owner = TrafficOwner(app: "?", process: "?", pid: 0)
                var batch: [(TrafficOwner, ObservedFlow)] = []
                let now = Date()
                for line in output.components(separatedBy: "\n") {
                    if let row = ObservedFlow.process(line) {
                        owner = TrafficOwner.resolve(name: row.name, pid: row.pid)
                        continue
                    }
                    guard let flow = ObservedFlow.parse(line) else { continue }
                    let key = "\(owner.pid)|\(flow.proto)|\(flow.address)|\(flow.port)|\(flow.interface)"
                    // A long-lived connection is in every sample; it is news the first
                    // time, and again only after five quiet minutes.
                    let seen = lastSeen[key]
                    lastSeen[key] = now
                    if let seen, now.timeIntervalSince(seen) < 300 { continue }
                    batch.append((owner, flow))
                }
                if lastSeen.count > 10_000 { lastSeen = lastSeen.filter { now.timeIntervalSince($0.value) < 300 } }
                if !batch.isEmpty { await self?.record(batch) }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func stop() {
        poller?.cancel()
        poller = nil
        tunnels.removeAll()
    }

    /// nettop gives some interfaces only their index, `idx-28` — our own tunnel
    /// among them, since it comes up after nettop starts. nil: it is gone.
    private static func interfaceName(_ raw: String) -> String? {
        guard raw.hasPrefix("idx-") else { return raw }
        guard let index = UInt32(raw.dropFirst(4)) else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        guard if_indextoname(index, &buffer) != nil else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private func record(_ batch: [(TrafficOwner, ObservedFlow)]) async {
        let now = Date()
        // Seen before the tunnel was up, it was opened before it could take it;
        // seen in the first sample, it was open before recording began.
        // ponytail: up to one poll late — a flow in the two seconds after the
        // tunnel comes up can still read «до VPN».
        let early: TrafficEntry.Early? = !ready ? .beforeTunnel : firstSample ? .beforeRecording : nil
        firstSample = false
        var fresh = batch.map { owner, raw in
            var flow = raw
            let name = Self.interfaceName(raw.interface)
            flow.interface = name ?? raw.interface
            let via = name.flatMap { tunnels[$0] }
                ?? (name == nil ? "Закрытый интерфейс (\(raw.interface))"
                    : flow.interface.hasPrefix("utun") ? "Чужой туннель (\(flow.interface))" : "Напрямую (\(flow.interface))")
            return TrafficEntry(time: now, owner: owner, flow: flow, via: via, early: via.hasPrefix("Напрямую") ? early : nil)
        }
        let names = await lookup(Array(Set(fresh.map(\.flow.address))))
        for index in fresh.indices {
            let address = fresh[index].flow.address
            if let name = names[address] {
                fresh[index].name = name
                fresh[index].nameSource = .dns
            } else if let name = reverse[address], !name.isEmpty {
                fresh[index].name = name
                fresh[index].nameSource = .reverse
            }
        }
        entries = Array((fresh + entries).prefix(limit))
        // The daemon never saw a DNS answer for connections opened before it
        // started, served from the system's cache, or to a built-in address;
        // their PTR name is the next best thing. On GCD, not the cooperative
        // pool: a lookup with no answer blocks for seconds.
        // ponytail: dropped wholesale at the cap, like the daemon's names.
        if reverse.count > 5000 { reverse.removeAll() }
        for address in Set(fresh.filter { $0.name == nil }.map(\.flow.address)) where reverse[address] == nil {
            reverse[address] = ""
            DispatchQueue.global().async {
                let name = HostResolver.name(address)
                Task { @MainActor [weak self] in self?.named(address, name) }
            }
        }
    }

    private func named(_ address: String, _ name: String?) {
        guard let name else { return }
        reverse[address] = name
        for index in entries.indices where entries[index].flow.address == address && entries[index].name == nil {
            entries[index].name = name
            entries[index].nameSource = .reverse
        }
    }
}
