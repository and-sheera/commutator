import Darwin
import Foundation
import Network
import VPNRouterCore

/// Runs any number of tunnels side by side, each under an id the coordinator
/// picks. Every callback names the tunnel it is about.
final class TunnelSupervisor: @unchecked Sendable {
    struct Callbacks: Sendable {
        let status: @Sendable (String, TunnelStatus) -> Void
        let pushedOptions: @Sendable (String, PushedOptions) -> Void
        let failed: @Sendable (String, RouterErrorInfo) -> Void
        let note: @Sendable (String) -> Void
    }

    struct Credentials: Sendable {
        var username: String?
        var password: String?
    }

    /// One engine and what watching it needs. Its fields are written from the
    /// pipe's queue, the management connection's queue and whichever thread
    /// calls stop(), hence the lock.
    private final class Tunnel: @unchecked Sendable {
        let id: String
        /// For messages: the names of the routes it carries.
        let title: String
        /// Tells its files, its log lines and an Xray TUN address apart.
        let slot: Int
        let lock = NSLock()
        private var lockedProcess: Process?
        private var lockedManagement: NWConnection?
        private var lockedInterface: String?
        private var lockedConnected = false
        private var lockedDeadline: Task<Void, Never>?
        private var lockedHealth: Task<Void, Never>?
        var credentials = Credentials()
        /// Only touched on the management connection's own queue.
        var managementBuffer = ""

        init(id: String, title: String, slot: Int) {
            self.id = id
            self.title = title
            self.slot = slot
        }

        var process: Process? {
            get { lock.withLock { lockedProcess } }
            set { lock.withLock { lockedProcess = newValue } }
        }
        var management: NWConnection? {
            get { lock.withLock { lockedManagement } }
            set { lock.withLock { lockedManagement = newValue } }
        }
        var interface: String? {
            get { lock.withLock { lockedInterface } }
            set { lock.withLock { lockedInterface = newValue } }
        }
        var connected: Bool {
            get { lock.withLock { lockedConnected } }
            set { lock.withLock { lockedConnected = newValue } }
        }
        var deadline: Task<Void, Never>? {
            get { lock.withLock { lockedDeadline } }
            set { lock.withLock { lockedDeadline = newValue } }
        }
        var health: Task<Void, Never>? {
            get { lock.withLock { lockedHealth } }
            set { lock.withLock { lockedHealth = newValue } }
        }
    }

    private let runner: CommandRunner
    private let callbacks: Callbacks
    private let lock = NSLock()
    private var tunnels: [String: Tunnel] = [:]
    /// TUN names handed to Xray but not yet showing in ifconfig: two starting
    /// at once would otherwise both pick the first free one.
    private var reservedUtuns: Set<String> = []

    private let runtimeDirectory = URL(fileURLWithPath: "/var/run/com.vpnrouter", isDirectory: true)

    init(runner: CommandRunner, callbacks: Callbacks) {
        self.runner = runner
        self.callbacks = callbacks
    }

    /// A fresh tunnel under `id`, replacing whatever ran there.
    private func begin(_ id: String, title: String) -> Tunnel {
        stop(id)
        return lock.withLock {
            let used = Set(tunnels.values.map(\.slot))
            let tunnel = Tunnel(id: id, title: title, slot: (0...).first { !used.contains($0) }!)
            tunnels[id] = tunnel
            return tunnel
        }
    }

    private func isCurrent(_ tunnel: Tunnel, _ process: Process) -> Bool {
        lock.withLock { tunnels[tunnel.id] === tunnel } && tunnel.process === process
    }

    func startOpenVPN(id: String, title: String, configuration: String, credentials: Credentials) throws {
        try prepareRuntimeDirectory()
        let tunnel = begin(id, title: title)
        tunnel.credentials = credentials
        let socket = runtimeDirectory.appendingPathComponent("openvpn-\(tunnel.slot).sock").path
        try? FileManager.default.removeItem(atPath: socket)
        let configURL = runtimeDirectory.appendingPathComponent("openvpn-\(tunnel.slot).conf")
        let managed = configuration + """
        management \(socket) unix
        management-hold
        management-query-passwords
        management-up-down
        verb 3
        """
        try writeSecret(managed, to: configURL)
        callbacks.status(id, .init(phase: .connecting))
        let source = "openvpn:\(tunnel.slot)"
        let process = try launch(
            tunnel, engine: "openvpn",
            executable: toolPath(environment: "VPNROUTER_OPENVPN", name: "openvpn"),
            arguments: ["--config", configURL.path],
            environment: [:]
        ) { [weak self, weak tunnel] line in
            TunnelLog.shared.write(source, line)
            if let tunnel { self?.parseOpenVPNLine(line, tunnel) }
        }
        connectManagement(tunnel, path: socket, attempt: 0, for: process)
        startOpenVPNDeadline(tunnel)
    }

    // Nothing else bounds the connecting phase: a handshake that never completes
    // produces no fatal line, and without this the status sits on «Подключение»
    // forever instead of falling into the retry backoff with a visible error.
    //
    // Re-armed on every soft restart too. openvpn answers a wake with one, and a
    // reconnect that never lands had nothing watching it: the status sat on
    // «Переподключение» for as long as the network stayed bad.
    private func startOpenVPNDeadline(_ tunnel: Tunnel, _ seconds: Int = 45, reconnect: Bool = false) {
        tunnel.connected = false
        tunnel.deadline?.cancel()
        tunnel.deadline = Task.detached { [weak self, weak tunnel] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, let self, let tunnel, !tunnel.connected else { return }
            self.callbacks.failed(tunnel.id, .init(
                .tunnelFailure,
                "«\(tunnel.title)»: VPN не \(reconnect ? "переподключился" : "подключился") за \(seconds) секунд",
                recoverable: true
            ))
        }
    }

    func startAmneziaWG(id: String, title: String, profile: AmneziaWGProfile) async throws -> String {
        try prepareRuntimeDirectory()
        let tunnel = begin(id, title: title)
        let nameFile = runtimeDirectory.appendingPathComponent("awg-\(tunnel.slot)-interface")
        let configURL = runtimeDirectory.appendingPathComponent("awg-\(tunnel.slot).conf")
        try? FileManager.default.removeItem(at: nameFile)
        try writeSecret(profile.setConf, to: configURL)
        callbacks.status(id, .init(phase: .connecting))
        let source = "amneziawg:\(tunnel.slot)"
        let process = try launch(
            tunnel, engine: "amneziawg-go",
            executable: toolPath(environment: "VPNROUTER_AWG_GO", name: "amneziawg-go"),
            arguments: ["-f", "utun"],
            // At its default level the engine says nothing at all, and its lines are
            // the only place that tells a handshake nobody answers from one our own
            // firewall never let out.
            environment: ["WG_TUN_NAME_FILE": nameFile.path, "LOG_LEVEL": "verbose"]
        ) { line in
            // Verbose repeats this per peer every twenty-five seconds and says nothing.
            guard !line.contains("keepalive") else { return }
            TunnelLog.shared.write(source, line)
        }

        var interface: String?
        for _ in 0..<100 {
            // Stopped while we waited: the name file that shows up next belongs to
            // whatever instance replaced this one, and configuring it is not ours.
            guard isCurrent(tunnel, process) else { throw CancellationError() }
            if let value = try? String(contentsOf: nameFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               value.range(of: "^utun[0-9]+$", options: .regularExpression) != nil {
                interface = value
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        guard let interface else {
            stop(id)
            throw RouterErrorInfo(.tunnelFailure, "«\(title)»: VPN не создал сетевой интерфейс", recoverable: true)
        }
        try runner.checked(toolPath(environment: "VPNROUTER_AWG_TOOL", name: "awg"), ["setconf", interface, configURL.path])
        if let mtu = profile.mtu { try runner.checked("/sbin/ifconfig", [interface, "mtu", String(mtu)]) }
        for address in profile.addresses {
            if address.contains(":") {
                try runner.checked("/sbin/ifconfig", [interface, "inet6", address, "alias"])
            } else {
                // The prefix has to go in: without it ifconfig falls back to the
                // classful mask, and a 10.x tunnel address would claim all of 10/8.
                let ip = address.split(separator: "/").first.map(String.init) ?? address
                try runner.checked("/sbin/ifconfig", [interface, "inet", address, ip, "alias"])
            }
        }
        startHealthMonitoring(tunnel, interface: interface, endpoint: profile.endpointHost)
        return interface
    }

    /// Xray's TUN inbound. Its health check goes through a loopback SOCKS door
    /// whose password only this process knows: the check then takes the very
    /// outbound the traffic does, and its test name resolves on the server's
    /// side, where neither the kill switch nor a missing route gets in the way.
    func startXray(id: String, title: String, server: XrayServer, physicalInterface: String) async throws -> String {
        try prepareRuntimeDirectory()
        let tunnel = begin(id, title: title)
        let interface = reserveUtun()
        defer { lock.withLock { _ = reservedUtuns.remove(interface) } }
        let probe = XrayProbe(port: Int.random(in: 20_000..<60_000), user: UUID().uuidString, password: UUID().uuidString)
        let configURL = runtimeDirectory.appendingPathComponent("xray-\(tunnel.slot).json")
        let probeURL = runtimeDirectory.appendingPathComponent("xray-\(tunnel.slot)-probe.curl")
        try writeSecret(
            try XrayProfileParser.configuration(for: server, interface: interface, physicalInterface: physicalInterface, probe: probe, slot: tunnel.slot),
            to: configURL
        )
        // In a file, not in curl's arguments: those show up in ps for every local user.
        try writeSecret("proxy = \"socks5h://\(probe.user):\(probe.password)@127.0.0.1:\(probe.port)\"\n", to: probeURL)
        callbacks.status(id, .init(phase: .connecting))
        let source = "xray:\(tunnel.slot)"
        let process = try launch(
            tunnel, engine: "xray",
            executable: toolPath(environment: "VPNROUTER_XRAY", name: "xray"),
            arguments: ["run", "-c", configURL.path],
            environment: [:]
        ) { line in TunnelLog.shared.write(source, line) }
        for _ in 0..<100 {
            guard isCurrent(tunnel, process) else { throw CancellationError() }
            if (try? runner.run("/sbin/ifconfig", [interface]))?.status == 0 {
                startXrayHealth(tunnel, interface: interface, probeConfig: probeURL.path, serverName: server.name)
                return interface
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        stop(id)
        throw RouterErrorInfo(.tunnelFailure, "«\(title)»: VPN не создал сетевой интерфейс \(interface)", recoverable: true)
    }

    /// Picked here rather than by Xray: the routes need the name up front.
    private func reserveUtun() -> String {
        let listed = Set(((try? runner.run("/sbin/ifconfig", ["-l"]))?.stdout ?? "").split(whereSeparator: \.isWhitespace).map(String.init))
        return lock.withLock {
            let name = (100..<200).lazy.map { "utun\($0)" }.first { !listed.contains($0) && !reservedUtuns.contains($0) } ?? "utun199"
            reservedUtuns.insert(name)
            return name
        }
    }

    private func startXrayHealth(_ tunnel: Tunnel, interface: String, probeConfig: String, serverName: String) {
        let started = Date()
        tunnel.health?.cancel()
        tunnel.health = Task.detached { [weak self, weak tunnel] in
            var seen = false
            var misses = 0
            while !Task.isCancelled {
                guard let self, let tunnel else { return }
                let code = (try? self.runner.run("/usr/bin/curl", [
                    "-K", probeConfig, "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5",
                    "http://cp.cloudflare.com/generate_204",
                ]))?.stdout
                if code == "204" {
                    seen = true
                    misses = 0
                    self.callbacks.status(tunnel.id, .init(phase: .connected, interfaceName: interface))
                } else if seen {
                    // One lost probe is noise: the routes move only after two, and
                    // the tunnel is given up after four, about forty seconds.
                    misses += 1
                    if misses >= 4 {
                        self.callbacks.failed(tunnel.id, .init(.tunnelFailure, "Сервер «\(serverName)» перестал отвечать", recoverable: true))
                        return
                    }
                    if misses >= 2 { self.callbacks.status(tunnel.id, .init(phase: .reconnecting, interfaceName: interface)) }
                } else if Date().timeIntervalSince(started) > 35 {
                    self.callbacks.failed(tunnel.id, .init(.tunnelFailure, "Сервер «\(serverName)» не ответил за 35 секунд", recoverable: true))
                    return
                }
                try? await Task.sleep(for: .seconds(seen ? 10 : 1))
            }
        }
    }

    func stopAll() {
        for id in lock.withLock({ Array(tunnels.keys) }) { stop(id) }
        try? FileManager.default.removeItem(at: runtimeDirectory)
    }

    func stop(_ id: String) {
        guard let tunnel = lock.withLock({ tunnels.removeValue(forKey: id) }) else { return }
        TunnelLog.shared.write("supervisor", "остановка «\(tunnel.title)»")
        tunnel.deadline?.cancel(); tunnel.deadline = nil
        tunnel.management?.cancel(); tunnel.management = nil
        tunnel.health?.cancel(); tunnel.health = nil
        if let process = tunnel.process, process.isRunning {
            process.terminate()
            for _ in 0..<20 where process.isRunning { usleep(50_000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
    }

    private func launch(
        _ tunnel: Tunnel,
        engine: String,
        executable: String,
        arguments: [String],
        environment: [String: String],
        onLine: @escaping @Sendable (String) -> Void
    ) throws -> Process {
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            throw RouterErrorInfo(.missingTool, "Не найден \(URL(fileURLWithPath: executable).lastPathComponent)")
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        process.standardOutput = pipe
        process.standardError = pipe
        let reader = LineAccumulator(onLine: onLine)
        pipe.fileHandleForReading.readabilityHandler = { handle in reader.append(handle.availableData) }
        TunnelLog.shared.write("supervisor", "запуск \(executable) \(arguments.joined(separator: " "))")
        process.terminationHandler = { [weak self, weak tunnel] process in
            pipe.fileHandleForReading.readabilityHandler = nil
            TunnelLog.shared.write("supervisor", "\(engine) завершился с кодом \(process.terminationStatus)")
            guard let self, let tunnel else { return }
            // Only the one still wanted: a stopped or replaced engine exits quietly.
            if self.lock.withLock({ self.tunnels[tunnel.id] === tunnel }), tunnel.process === process {
                self.callbacks.failed(tunnel.id, .init(.tunnelFailure, "\(engine) завершился с кодом \(process.terminationStatus)", recoverable: true))
            }
            _ = reader
        }
        tunnel.process = process
        try process.run()
        return process
    }

    /// Bound to one openvpn: a chain still retrying for an instance that was
    /// stopped would otherwise report its failure against the next, healthy one.
    private func connectManagement(_ tunnel: Tunnel, path: String, attempt: Int, for process: Process) {
        guard isCurrent(tunnel, process) else { return }
        guard attempt < 50 else {
            callbacks.failed(tunnel.id, .init(.tunnelFailure, "«\(tunnel.title)»: OpenVPN не запустился — его процесс не ответил", recoverable: true))
            return
        }
        guard FileManager.default.fileExists(atPath: path) else {
            retryManagement(tunnel, path: path, attempt: attempt, for: process)
            return
        }
        let connection = NWConnection(to: .unix(path: path), using: .tcp)
        connection.stateUpdateHandler = { [weak self, weak connection, weak tunnel] state in
            guard let self, let connection, let tunnel else { return }
            TunnelLog.shared.write("mgmt:\(tunnel.slot)", "состояние соединения: \(state)")
            switch state {
            case .ready:
                // A half line left by the previous connection is not the start of this one's.
                tunnel.managementBuffer = ""
                self.send("state on\nlog on all\nhold release\n", to: connection)
                self.receiveManagement(tunnel, connection)
            // A socket that exists but is not accepting yet reports .waiting, not
            // .failed, and NWConnection then retries on its own schedule forever.
            // Without releasing the hold openvpn stays silent, so this is exactly
            // the hang that has to time out into our own bounded retry.
            case .failed, .waiting:
                connection.cancel()
                self.retryManagement(tunnel, path: path, attempt: attempt, for: process)
            default: break
            }
        }
        tunnel.management = connection
        connection.start(queue: DispatchQueue(label: "com.vpnrouter.openvpn.management.\(tunnel.slot)"))
    }

    private func retryManagement(_ tunnel: Tunnel, path: String, attempt: Int, for process: Process) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { [weak self, weak tunnel] in
            guard let tunnel else { return }
            self?.connectManagement(tunnel, path: path, attempt: attempt + 1, for: process)
        }
    }

    private func receiveManagement(_ tunnel: Tunnel, _ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self, weak connection, weak tunnel] data, _, complete, error in
            guard let self, let connection, let tunnel else { return }
            if let data {
                tunnel.managementBuffer += String(decoding: data, as: UTF8.self)
                for line in LineSplitter.take(from: &tunnel.managementBuffer) {
                    parseManagementLine(line, tunnel, connection: connection)
                }
            }
            if !complete && error == nil { receiveManagement(tunnel, connection) }
        }
    }

    private func parseManagementLine(_ line: String, _ tunnel: Tunnel, connection: NWConnection) {
        // ">LOG:" repeats what the process already printed on its pipe.
        if !line.hasPrefix(">LOG:") { TunnelLog.shared.write("mgmt:\(tunnel.slot)", line) }
        parseOpenVPNLine(line, tunnel)
        if line.hasPrefix(">PASSWORD:Need ") {
            answerPasswordRequest(line, tunnel, connection: connection)
        } else if line.hasPrefix(">HOLD:") {
            // management-hold holds again after every soft restart (ping-restart,
            // a network change), not only at start: unreleased, openvpn waits forever.
            // The number is openvpn's own back-off before the next attempt; releasing
            // at once spun a failing resolve many times a second. Capped so a network
            // that is back is not left waiting for minutes.
            let wait = min(Int(line.split(separator: ":").last ?? "") ?? 0, 30)
            DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(wait)) { [weak self, weak connection] in
                guard let self, let connection else { return }
                self.send("hold release\n", to: connection)
            }
        } else if line.hasPrefix(">PASSWORD:Verification Failed") || line.contains("AUTH_FAILED") {
            let realm = Self.realm(in: line) ?? "Auth"
            callbacks.failed(tunnel.id, .init(
                .authenticationRequired,
                "«\(tunnel.title)»: " + (realm == "Auth" ? "OpenVPN отклонил логин или пароль" : "OpenVPN отклонил пароль приватного ключа")
            ))
        }
    }

    private func answerPasswordRequest(_ line: String, _ tunnel: Tunnel, connection: NWConnection) {
        guard let realm = Self.realm(in: line) else { return }
        let credentials = tunnel.credentials
        // One password answers both "Auth" and "Private Key": a profile without
        // auth-user-pass has no other password at all, and official clients ask
        // for this one simply as «Пароль».
        guard let secret = credentials.password, !secret.isEmpty else {
            callbacks.failed(tunnel.id, .init(.authenticationRequired, realm == "Auth"
                ? "«\(tunnel.title)»: OpenVPN требует логин и пароль — укажите их на странице «VPN»"
                : "«\(tunnel.title)»: приватный ключ профиля зашифрован — впишите на странице «VPN» в поле «Пароль» тот, что спрашивает официальный клиент OpenVPN, и включите маршрутизацию снова"))
            return
        }
        var commands = ""
        if line.contains("username/password") {
            guard let username = credentials.username, !username.isEmpty else {
                callbacks.failed(tunnel.id, .init(.authenticationRequired, "«\(tunnel.title)»: OpenVPN требует логин и пароль — укажите их на странице «VPN»"))
                return
            }
            commands += "username \"\(escape(realm))\" \"\(escape(username))\"\n"
        }
        commands += "password \"\(escape(realm))\" \"\(escape(secret))\"\n"
        send(commands, to: connection)
    }

    /// The realm is the single-quoted name in a management password line.
    static func realm(in line: String) -> String? {
        guard let open = line.firstIndex(of: "'"),
              let close = line[line.index(after: open)...].firstIndex(of: "'")
        else { return nil }
        return String(line[line.index(after: open)..<close])
    }

    private func parseOpenVPNLine(_ line: String, _ tunnel: Tunnel) {
        if let match = line.range(of: "utun[0-9]+", options: .regularExpression) {
            tunnel.interface = String(line[match])
        }
        // ">STATE:1699,WAIT,,,,,," — the second field names the step and carries no
        // host or address, so journalling it says where a stall happened without
        // putting anything from the profile into diagnostics.
        if line.hasPrefix(">STATE:"), let step = line.dropFirst(7).split(separator: ",", omittingEmptySubsequences: false).dropFirst().first {
            callbacks.note("«\(tunnel.title)» OpenVPN state: \(step)")
        }
        if line.contains(",CONNECTED,SUCCESS") || line.contains("Initialization Sequence Completed") {
            tunnel.connected = true
            callbacks.status(tunnel.id, .init(phase: .connected, interfaceName: tunnel.interface))
        } else if line.contains("RECONNECTING") {
            callbacks.status(tunnel.id, .init(phase: .reconnecting, interfaceName: tunnel.interface))
            // Longer than a first connect: openvpn holds before each retry and the
            // hold is released after its own back-off, up to thirty seconds.
            startOpenVPNDeadline(tunnel, 90, reconnect: true)
        }
        if line.contains("PUSH_REPLY,") {
            let pushed = OpenVPNProfileParser.pushedOptions(from: line)
            callbacks.pushedOptions(tunnel.id, .init(routes: pushed.routes, dns: pushed.dns, domains: pushed.domains))
        }
    }

    private func startHealthMonitoring(_ tunnel: Tunnel, interface: String, endpoint: String) {
        tunnel.health?.cancel()
        tunnel.health = Task.detached { [weak self, weak tunnel] in
            // The grace period runs from when the handshake first looked stale, not
            // from the start. The clock keeps counting through sleep, so after every
            // wake the last handshake is always ancient: measured from the start, that
            // killed a healthy tunnel on each wake instead of giving WireGuard the few
            // seconds it needs to re-handshake by itself.
            var staleSince = Date()
            var seenHandshake = false
            var reportedStale = false
            while !Task.isCancelled {
                guard let self, let tunnel else { return }
                let source = "amneziawg:\(tunnel.slot)"
                let result = try? self.runner.run(self.toolPath(environment: "VPNROUTER_AWG_TOOL", name: "awg"), ["show", interface, "latest-handshakes"])
                let newest = result?.stdout.split(whereSeparator: \ .isWhitespace).compactMap { TimeInterval($0) }.max() ?? 0
                let age = Date().timeIntervalSince1970 - newest
                // Keepalive re-handshakes about every 120s, so anything past 165
                // is already a tunnel in trouble and must not read as "protected".
                if newest > 0, age <= 165 {
                    if reportedStale { TunnelLog.shared.write(source, "рукопожатие снова свежее: \(Int(age)) с") }
                    staleSince = Date()
                    seenHandshake = true
                    reportedStale = false
                    self.callbacks.status(tunnel.id, .init(phase: .connected, interfaceName: interface))
                } else {
                    if !reportedStale {
                        reportedStale = true
                        TunnelLog.shared.write(source, newest > 0
                            ? "рукопожатию \(Int(age)) с — жду, пока туннель восстановится сам"
                            : "рукопожатия ещё не было — жду")
                    }
                    if seenHandshake { self.callbacks.status(tunnel.id, .init(phase: .reconnecting, interfaceName: interface)) }
                    if Date().timeIntervalSince(staleSince) > 35 {
                        self.logDiagnostics(source: source, interface: interface, endpoint: endpoint)
                        self.callbacks.failed(tunnel.id, .init(
                            .tunnelFailure,
                            seenHandshake ? "«\(tunnel.title)»: сервер перестал отвечать" : "«\(tunnel.title)»: не достучались до сервера за 35 секунд",
                            recoverable: true
                        ))
                        return
                    }
                }
                // The first handshake lands within a second of setconf, and PF keeps
                // the tunnel shut until it is reported: a ten-second poll there was
                // up to ten seconds of «Подключение» for a tunnel already up.
                try? await Task.sleep(for: .seconds(seenHandshake ? 10 : 1))
            }
        }
    }

    /// Written when a tunnel gives up: where its packets would go, and whether
    /// our own firewall is what stops them. Addresses reach the log as
    /// aliases — TunnelLog redacts them.
    private func logDiagnostics(source: String, interface: String, endpoint: String) {
        let note = { TunnelLog.shared.write(source, $0) }
        guard let address = IPAddress(endpoint)?.description ?? HostResolver.addresses(endpoint).first else {
            note("адрес сервера не резолвится — рукопожатию некуда идти")
            return
        }
        let route = (try? runner.run("/sbin/route", ["-n", "get", address]))?.stdout ?? ""
        note("маршрут к серверу \(address): через \(Self.field("interface:", in: route)), шлюз \(Self.field("gateway:", in: route))")
        let table = address.contains(":") ? "control6" : "control4"
        let allowed = try? runner.run("/sbin/pfctl", ["-a", PFController.anchorName, "-t", table, "-T", "test", address])
        note("разрешён в PF (\(table)): \(allowed?.status == 0 ? "да" : "нет")")
        let counters = (try? runner.run("/usr/sbin/netstat", ["-ibn", "-I", interface]))?.stdout ?? ""
        if let line = counters.components(separatedBy: .newlines).dropFirst().first {
            note("счётчики \(interface): \(line.split(whereSeparator: \.isWhitespace).joined(separator: " "))")
        }
        let transfer = (try? runner.run(toolPath(environment: "VPNROUTER_AWG_TOOL", name: "awg"), ["show", interface, "transfer"]))?.stdout ?? ""
        note("обмен с сервером: \(transfer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "нет данных" : transfer.trimmingCharacters(in: .whitespacesAndNewlines))")
    }

    private static func field(_ key: String, in text: String) -> String {
        text.components(separatedBy: .newlines).first { $0.contains(key) }?
            .split(separator: ":", maxSplits: 1).dropFirst().first?
            .trimmingCharacters(in: .whitespaces) ?? "—"
    }

    private func send(_ string: String, to connection: NWConnection) {
        connection.send(content: Data(string.utf8), completion: .contentProcessed { _ in })
    }

    private func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }

    private func toolPath(environment key: String, name: String) -> String {
        if let override = ProcessInfo.processInfo.environment[key] { return override }
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
        let contents = executable.deletingLastPathComponent().deletingLastPathComponent()
        let bundlePath = contents.appendingPathComponent("Resources/VPNTools/\(name)").path
        if FileManager.default.fileExists(atPath: bundlePath) { return bundlePath }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Vendor/bin/arm64/\(name)").path
    }

    private func prepareRuntimeDirectory() throws {
        try FileManager.default.createDirectory(at: runtimeDirectory, withIntermediateDirectories: true)
        chmod(runtimeDirectory.path, S_IRUSR | S_IWUSR | S_IXUSR)
    }

    private func writeSecret(_ value: String, to url: URL) throws {
        try Data(value.utf8).write(to: url, options: .atomic)
        chmod(url.path, S_IRUSR | S_IWUSR)
    }
}

/// Takes the complete lines out of a growing buffer and leaves the tail.
///
/// The OpenVPN management protocol ends lines with CRLF, and Swift counts "\r\n"
/// as ONE Character: `firstIndex(of: "\n")` never matches it, so the buffer grew
/// without a single line ever being parsed — no state, no password query, no
/// answer, and a tunnel that sat in «Подключение» until it was killed.
enum LineSplitter {
    static func take(from buffer: inout String) -> [String] {
        var lines: [String] = []
        while let newline = buffer.firstIndex(where: \.isNewline) {
            lines.append(String(buffer[..<newline]).trimmingCharacters(in: .newlines))
            buffer.removeSubrange(...newline)
        }
        return lines
    }
}

private final class LineAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = ""
    private let onLine: @Sendable (String) -> Void

    init(onLine: @escaping @Sendable (String) -> Void) { self.onLine = onLine }

    func append(_ data: Data) {
        guard !data.isEmpty else { return }
        lock.lock()
        buffer += String(decoding: data, as: UTF8.self)
        let lines = LineSplitter.take(from: &buffer)
        lock.unlock()
        lines.forEach(onLine)
    }
}
