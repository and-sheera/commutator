import Darwin
import Foundation
import Network
import VPNRouterCore

final class TunnelSupervisor: @unchecked Sendable {
    struct Callbacks: Sendable {
        let status: @Sendable (VPNKind, TunnelStatus) -> Void
        let pushedOptions: @Sendable ([String], [String], [String]) -> Void
        let failed: @Sendable (VPNKind, RouterErrorInfo) -> Void
        let note: @Sendable (String) -> Void
    }

    struct Credentials: Sendable {
        var username: String?
        var password: String?
    }

    private let runner: CommandRunner
    private let callbacks: Callbacks
    private let lock = NSLock()
    private var processes: [VPNKind: Process] = [:]
    private var managementBuffer = ""
    private var healthTask: Task<Void, Never>?
    private var lockedManagement: NWConnection?
    private var lockedInterface: String?
    private var lockedOpenVPNConnected = false
    private var lockedCredentials = Credentials()
    private var lockedDeadline: Task<Void, Never>?

    // Armed from the actor, re-armed from the pipe's queue when openvpn announces
    // a soft restart, cancelled from whichever thread calls stop().
    private var openVPNDeadline: Task<Void, Never>? {
        get { lock.withLock { lockedDeadline } }
        set { lock.withLock { lockedDeadline = newValue } }
    }

    private var credentials: Credentials {
        get { lock.withLock { lockedCredentials } }
        set { lock.withLock { lockedCredentials = newValue } }
    }

    // Both are written from the pipe's readability queue and from the management
    // connection's queue, and read from whichever thread calls stop().
    private var management: NWConnection? {
        get { lock.withLock { lockedManagement } }
        set { lock.withLock { lockedManagement = newValue } }
    }

    private var openVPNInterface: String? {
        get { lock.withLock { lockedInterface } }
        set { lock.withLock { lockedInterface = newValue } }
    }

    private var openVPNConnected: Bool {
        get { lock.withLock { lockedOpenVPNConnected } }
        set { lock.withLock { lockedOpenVPNConnected = newValue } }
    }

    private let runtimeDirectory = URL(fileURLWithPath: "/var/run/com.vpnrouter", isDirectory: true)

    init(runner: CommandRunner, callbacks: Callbacks) {
        self.runner = runner
        self.callbacks = callbacks
    }

    func startOpenVPN(configuration: String, credentials: Credentials) throws {
        self.credentials = credentials
        try prepareRuntimeDirectory()
        stop(.openVPN)
        let socket = runtimeDirectory.appendingPathComponent("openvpn.sock").path
        try? FileManager.default.removeItem(atPath: socket)
        let configURL = runtimeDirectory.appendingPathComponent("openvpn.conf")
        let managed = configuration + """
        management \(socket) unix
        management-hold
        management-query-passwords
        management-up-down
        verb 3
        """
        try writeSecret(managed, to: configURL)
        callbacks.status(.openVPN, .init(phase: .connecting))
        let process = try launch(
            kind: .openVPN,
            executable: toolPath(environment: "VPNROUTER_OPENVPN", name: "openvpn"),
            arguments: ["--config", configURL.path],
            environment: [:]
        ) { [weak self] line in
            TunnelLog.shared.write("openvpn", line)
            self?.parseOpenVPNLine(line)
        }
        connectManagement(path: socket, attempt: 0, for: process)
        startOpenVPNDeadline()
    }

    // Nothing else bounds the connecting phase: a handshake that never completes
    // produces no fatal line, and without this the status sits on «Подключение»
    // forever instead of falling into the retry backoff with a visible error.
    //
    // Re-armed on every soft restart too. openvpn answers a wake with one, and a
    // reconnect that never lands had nothing watching it: the status sat on
    // «Переподключение» for as long as the network stayed bad.
    private func startOpenVPNDeadline(_ seconds: Int = 45, reconnect: Bool = false) {
        openVPNConnected = false
        openVPNDeadline?.cancel()
        openVPNDeadline = Task.detached { [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled, let self, !self.openVPNConnected else { return }
            self.callbacks.failed(.openVPN, .init(
                .tunnelFailure,
                "Рабочий VPN не \(reconnect ? "переподключился" : "подключился") за \(seconds) секунд",
                recoverable: true
            ))
        }
    }

    func startAmneziaWG(profile: AmneziaWGProfile) async throws -> String {
        try prepareRuntimeDirectory()
        stop(.amneziaWG)
        let nameFile = runtimeDirectory.appendingPathComponent("awg-interface")
        let configURL = runtimeDirectory.appendingPathComponent("awg.conf")
        try? FileManager.default.removeItem(at: nameFile)
        try writeSecret(profile.setConf, to: configURL)
        callbacks.status(.amneziaWG, .init(phase: .connecting))
        let process = try launch(
            kind: .amneziaWG,
            executable: toolPath(environment: "VPNROUTER_AWG_GO", name: "amneziawg-go"),
            arguments: ["-f", "utun"],
            // At its default level the engine says nothing at all, and its lines are
            // the only place that tells a handshake nobody answers from one our own
            // firewall never let out.
            environment: ["WG_TUN_NAME_FILE": nameFile.path, "LOG_LEVEL": "verbose"]
        ) { line in
            // Verbose repeats this per peer every twenty-five seconds and says nothing.
            guard !line.contains("keepalive") else { return }
            TunnelLog.shared.write("amneziawg", line)
        }

        var interface: String?
        for _ in 0..<100 {
            // Stopped while we waited: the name file that shows up next belongs to
            // whatever instance replaced this one, and configuring it is not ours.
            guard isCurrent(process, .amneziaWG) else { throw CancellationError() }
            if let value = try? String(contentsOf: nameFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               value.range(of: "^utun[0-9]+$", options: .regularExpression) != nil {
                interface = value
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        guard let interface else {
            stop(.amneziaWG)
            throw RouterErrorInfo(.tunnelFailure, "Личный VPN не создал сетевой интерфейс", recoverable: true)
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
        startHealthMonitoring(interface: interface, endpoint: profile.endpointHost)
        return interface
    }

    /// Xray's TUN inbound. Its health check goes through a loopback SOCKS door
    /// whose password only this process knows: the check then takes the very
    /// outbound the traffic does, and its test name resolves on the server's
    /// side, where neither the kill switch nor a missing route gets in the way.
    func startXray(server: XrayServer, physicalInterface: String) async throws -> String {
        try prepareRuntimeDirectory()
        stop(.amneziaWG)
        let interface = freeUtun()
        let probe = XrayProbe(port: Int.random(in: 20_000..<60_000), user: UUID().uuidString, password: UUID().uuidString)
        let configURL = runtimeDirectory.appendingPathComponent("xray.json")
        let probeURL = runtimeDirectory.appendingPathComponent("xray-probe.curl")
        try writeSecret(
            try XrayProfileParser.configuration(for: server, interface: interface, physicalInterface: physicalInterface, probe: probe),
            to: configURL
        )
        // In a file, not in curl's arguments: those show up in ps for every local user.
        try writeSecret("proxy = \"socks5h://\(probe.user):\(probe.password)@127.0.0.1:\(probe.port)\"\n", to: probeURL)
        callbacks.status(.amneziaWG, .init(phase: .connecting))
        let process = try launch(
            kind: .amneziaWG,
            executable: toolPath(environment: "VPNROUTER_XRAY", name: "xray"),
            arguments: ["run", "-c", configURL.path],
            environment: [:]
        ) { line in TunnelLog.shared.write("xray", line) }
        for _ in 0..<100 {
            guard isCurrent(process, .amneziaWG) else { throw CancellationError() }
            if (try? runner.run("/sbin/ifconfig", [interface]))?.status == 0 {
                startXrayHealth(interface: interface, probeConfig: probeURL.path)
                return interface
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        stop(.amneziaWG)
        throw RouterErrorInfo(.tunnelFailure, "Личный VPN не создал сетевой интерфейс \(interface)", recoverable: true)
    }

    /// Picked here rather than by Xray: the routes need the name up front.
    private func freeUtun() -> String {
        let taken = Set(((try? runner.run("/sbin/ifconfig", ["-l"]))?.stdout ?? "").split(whereSeparator: \.isWhitespace).map(String.init))
        return (100..<200).lazy.map { "utun\($0)" }.first { !taken.contains($0) } ?? "utun199"
    }

    private func startXrayHealth(interface: String, probeConfig: String) {
        let started = Date()
        healthTask?.cancel()
        healthTask = Task.detached { [weak self] in
            var seen = false
            var misses = 0
            while !Task.isCancelled {
                guard let self else { return }
                let code = (try? self.runner.run("/usr/bin/curl", [
                    "-K", probeConfig, "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5",
                    "http://cp.cloudflare.com/generate_204",
                ]))?.stdout
                if code == "204" {
                    seen = true
                    misses = 0
                    self.callbacks.status(.amneziaWG, .init(phase: .connected, interfaceName: interface))
                } else if seen {
                    // One lost probe is noise: the routes move only after two, and
                    // the tunnel is given up after four, about forty seconds.
                    misses += 1
                    if misses >= 4 {
                        self.callbacks.failed(.amneziaWG, .init(.tunnelFailure, "Сервер личного VPN перестал отвечать", recoverable: true))
                        return
                    }
                    if misses >= 2 { self.callbacks.status(.amneziaWG, .init(phase: .reconnecting, interfaceName: interface)) }
                } else if Date().timeIntervalSince(started) > 35 {
                    self.callbacks.failed(.amneziaWG, .init(.tunnelFailure, "Личный VPN не достучался до сервера за 35 секунд", recoverable: true))
                    return
                }
                try? await Task.sleep(for: .seconds(seen ? 10 : 1))
            }
        }
    }

    func stopAll() {
        stop(.openVPN)
        stop(.amneziaWG)
        try? FileManager.default.removeItem(at: runtimeDirectory)
    }

    func stop(_ kind: VPNKind) {
        TunnelLog.shared.write("supervisor", "остановка \(kind.title)")
        lock.lock()
        let process = processes.removeValue(forKey: kind)
        lock.unlock()
        if kind == .openVPN {
            openVPNDeadline?.cancel(); openVPNDeadline = nil
            management?.cancel(); management = nil; openVPNInterface = nil
        }
        if kind == .amneziaWG { healthTask?.cancel(); healthTask = nil }
        if let process, process.isRunning {
            process.terminate()
            for _ in 0..<20 where process.isRunning { usleep(50_000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
    }

    private func launch(
        kind: VPNKind,
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
        process.terminationHandler = { [weak self] process in
            pipe.fileHandleForReading.readabilityHandler = nil
            TunnelLog.shared.write("supervisor", "\(kind.title) завершился с кодом \(process.terminationStatus)")
            guard let self else { return }
            self.lock.lock()
            let tracked = self.processes[kind] === process
            if tracked { self.processes.removeValue(forKey: kind) }
            self.lock.unlock()
            if tracked {
                self.callbacks.failed(kind, .init(.tunnelFailure, "\(kind.title) завершился с кодом \(process.terminationStatus)", recoverable: true))
            }
            _ = reader
        }
        setProcess(process, for: kind)
        do { try process.run() }
        catch {
            lock.lock()
            if processes[kind] === process { processes.removeValue(forKey: kind) }
            lock.unlock()
            throw error
        }
        return process
    }

    private func setProcess(_ process: Process, for kind: VPNKind) {
        lock.lock(); processes[kind] = process; lock.unlock()
    }

    /// Bound to one openvpn: a chain still retrying for an instance that was
    /// stopped would otherwise report its failure against the next, healthy one.
    private func connectManagement(path: String, attempt: Int, for process: Process) {
        guard isCurrent(process, .openVPN) else { return }
        guard attempt < 50 else {
            callbacks.failed(.openVPN, .init(.tunnelFailure, "Рабочий VPN не запустился: его процесс не ответил", recoverable: true))
            return
        }
        guard FileManager.default.fileExists(atPath: path) else {
            retryManagement(path: path, attempt: attempt, for: process)
            return
        }
        let connection = NWConnection(to: .unix(path: path), using: .tcp)
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self, let connection else { return }
            TunnelLog.shared.write("mgmt", "состояние соединения: \(state)")
            switch state {
            case .ready:
                // A half line left by the previous connection is not the start of this one's.
                self.managementBuffer = ""
                self.send("state on\nlog on all\nhold release\n", to: connection)
                self.receiveManagement(connection)
            // A socket that exists but is not accepting yet reports .waiting, not
            // .failed, and NWConnection then retries on its own schedule forever.
            // Without releasing the hold openvpn stays silent, so this is exactly
            // the hang that has to time out into our own bounded retry.
            case .failed, .waiting:
                connection.cancel()
                self.retryManagement(path: path, attempt: attempt, for: process)
            default: break
            }
        }
        management = connection
        connection.start(queue: DispatchQueue(label: "com.vpnrouter.openvpn.management"))
    }

    private func retryManagement(path: String, attempt: Int, for process: Process) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.connectManagement(path: path, attempt: attempt + 1, for: process)
        }
    }

    private func isCurrent(_ process: Process, _ kind: VPNKind) -> Bool {
        lock.withLock { processes[kind] === process }
    }

    private func receiveManagement(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self, weak connection] data, _, complete, error in
            guard let self, let connection else { return }
            if let data {
                managementBuffer += String(decoding: data, as: UTF8.self)
                for line in LineSplitter.take(from: &managementBuffer) {
                    parseManagementLine(line, connection: connection)
                }
            }
            if !complete && error == nil { receiveManagement(connection) }
        }
    }

    private func parseManagementLine(_ line: String, connection: NWConnection) {
        // ">LOG:" repeats what the process already printed on its pipe.
        if !line.hasPrefix(">LOG:") { TunnelLog.shared.write("mgmt", line) }
        parseOpenVPNLine(line)
        if line.hasPrefix(">PASSWORD:Need ") {
            answerPasswordRequest(line, connection: connection)
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
            callbacks.failed(.openVPN, .init(
                .authenticationRequired,
                realm == "Auth" ? "OpenVPN отклонил логин или пароль" : "OpenVPN отклонил пароль приватного ключа"
            ))
        }
    }

    private func answerPasswordRequest(_ line: String, connection: NWConnection) {
        guard let realm = Self.realm(in: line) else { return }
        let credentials = credentials
        // One password answers both "Auth" and "Private Key": a profile without
        // auth-user-pass has no other password at all, and official clients ask
        // for this one simply as «Пароль».
        guard let secret = credentials.password, !secret.isEmpty else {
            callbacks.failed(.openVPN, .init(.authenticationRequired, realm == "Auth"
                ? "Рабочий VPN требует логин и пароль: укажите их в «Профилях»"
                : "Приватный ключ профиля зашифрован: впишите в поле «Пароль» тот, что спрашивает официальный клиент OpenVPN, и включите маршрутизацию снова"))
            return
        }
        var commands = ""
        if line.contains("username/password") {
            guard let username = credentials.username, !username.isEmpty else {
                callbacks.failed(.openVPN, .init(.authenticationRequired, "Рабочий VPN требует логин и пароль: укажите их в «Профилях»"))
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

    private func parseOpenVPNLine(_ line: String) {
        if let match = line.range(of: "utun[0-9]+", options: .regularExpression) {
            openVPNInterface = String(line[match])
        }
        // ">STATE:1699,WAIT,,,,,," — the second field names the step and carries no
        // host or address, so journalling it says where a stall happened without
        // putting anything from the profile into diagnostics.
        if line.hasPrefix(">STATE:"), let step = line.dropFirst(7).split(separator: ",", omittingEmptySubsequences: false).dropFirst().first {
            callbacks.note("OpenVPN state: \(step)")
        }
        if line.contains(",CONNECTED,SUCCESS") || line.contains("Initialization Sequence Completed") {
            openVPNConnected = true
            callbacks.status(.openVPN, .init(phase: .connected, interfaceName: openVPNInterface))
        } else if line.contains("RECONNECTING") {
            callbacks.status(.openVPN, .init(phase: .reconnecting, interfaceName: openVPNInterface))
            // Longer than a first connect: openvpn holds before each retry and the
            // hold is released after its own back-off, up to thirty seconds.
            startOpenVPNDeadline(90, reconnect: true)
        }
        let pushed = OpenVPNProfileParser.pushedOptions(from: line)
        if line.contains("PUSH_REPLY,") {
            callbacks.pushedOptions(pushed.routes, pushed.dns, pushed.domains)
        }
    }

    private func startHealthMonitoring(interface: String, endpoint: String) {
        healthTask?.cancel()
        healthTask = Task.detached { [weak self] in
            // The grace period runs from when the handshake first looked stale, not
            // from the start. The clock keeps counting through sleep, so after every
            // wake the last handshake is always ancient: measured from the start, that
            // killed a healthy tunnel on each wake instead of giving WireGuard the few
            // seconds it needs to re-handshake by itself.
            var staleSince = Date()
            var seenHandshake = false
            var reportedStale = false
            while !Task.isCancelled {
                guard let self else { return }
                let result = try? self.runner.run(self.toolPath(environment: "VPNROUTER_AWG_TOOL", name: "awg"), ["show", interface, "latest-handshakes"])
                let newest = result?.stdout.split(whereSeparator: \ .isWhitespace).compactMap { TimeInterval($0) }.max() ?? 0
                let age = Date().timeIntervalSince1970 - newest
                // Keepalive re-handshakes about every 120s, so anything past 165
                // is already a tunnel in trouble and must not read as "protected".
                if newest > 0, age <= 165 {
                    if reportedStale { TunnelLog.shared.write("amneziawg", "рукопожатие снова свежее: \(Int(age)) с") }
                    staleSince = Date()
                    seenHandshake = true
                    reportedStale = false
                    self.callbacks.status(.amneziaWG, .init(phase: .connected, interfaceName: interface))
                } else {
                    if !reportedStale {
                        reportedStale = true
                        TunnelLog.shared.write("amneziawg", newest > 0
                            ? "рукопожатию \(Int(age)) с — жду, пока туннель восстановится сам"
                            : "рукопожатия ещё не было — жду")
                    }
                    if seenHandshake { self.callbacks.status(.amneziaWG, .init(phase: .reconnecting, interfaceName: interface)) }
                    if Date().timeIntervalSince(staleSince) > 35 {
                        self.logDiagnostics(interface: interface, endpoint: endpoint)
                        self.callbacks.failed(.amneziaWG, .init(
                            .tunnelFailure,
                            seenHandshake ? "Сервер личного VPN перестал отвечать" : "Личный VPN не достучался до сервера за 35 секунд",
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

    /// Written when the personal tunnel gives up: where its packets would go, and
    /// whether our own firewall is what stops them. Addresses reach the log as
    /// aliases — TunnelLog redacts them.
    private func logDiagnostics(interface: String, endpoint: String) {
        let note = { TunnelLog.shared.write("amneziawg", $0) }
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
