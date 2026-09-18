import Darwin
import Foundation
import VPNRouterCore

struct CommandResult: Sendable {
    let status: Int32
    let stdout: String
    let stderr: String
}

struct CommandRunner: Sendable {
    var run: @Sendable (_ executable: String, _ arguments: [String]) throws -> CommandResult

    static let live = CommandRunner { executable, arguments in
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        try process.run()
        // Both pipes are drained before the wait: a child that fills one blocks until
        // it is read, and scutil --dns passes 64 KB at a few hundred /etc/resolver files.
        nonisolated(unsafe) var errorData = Data()
        let drainError = DispatchWorkItem { errorData = error.fileHandleForReading.readDataToEndOfFile() }
        DispatchQueue.global().async(execute: drainError)
        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        drainError.wait()
        process.waitUntilExit()
        return CommandResult(
            status: process.terminationStatus,
            stdout: String(decoding: outputData, as: UTF8.self),
            stderr: String(decoding: errorData, as: UTF8.self)
        )
    }

    @discardableResult
    func checked(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        let result = try run(executable, arguments)
        guard result.status == 0 else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw RouterErrorInfo(.routingFailure, "\(URL(fileURLWithPath: executable).lastPathComponent): \(detail)")
        }
        return result
    }
}

struct NetworkSnapshot: Codable, Equatable, Sendable {
    let physicalInterface: String
    let ipv4Gateway: String?
    let ipv6Gateway: String?
    let dnsServers: [String]
    let lanNetworks: [String]

    /// What the tunnels are actually pinned to, for deciding whether the network
    /// moved under us. DNS is deliberately excluded: the daemon writes
    /// /etc/resolver entries and points the system resolver at its own proxy, and
    /// both show up in `scutil --dns`, so comparing DNS would make the daemon
    /// restart in reaction to its own work — forever.
    var routingIdentity: [String] {
        [physicalInterface, ipv4Gateway ?? "-", ipv6Gateway ?? "-"] + lanNetworks
    }

    static func capture(using runner: CommandRunner) throws -> NetworkSnapshot {
        let v4 = try runner.checked("/sbin/route", ["-n", "get", "default"]).stdout
        guard let interface = value(after: "interface:", in: v4) else {
            throw RouterErrorInfo(.routingFailure, "Не найден физический интерфейс по умолчанию")
        }
        let gateway4 = value(after: "gateway:", in: v4)
        let v6Result = try? runner.run("/sbin/route", ["-n", "get", "-inet6", "default"])
        let gateway6 = v6Result.flatMap { $0.status == 0 ? value(after: "gateway:", in: $0.stdout) : nil }
        let dnsOutput = try runner.checked("/usr/sbin/scutil", ["--dns"]).stdout
        let dns = dnsOutput.components(separatedBy: .newlines).compactMap { line -> String? in
            guard line.contains("nameserver[") else { return nil }
            let raw = line.split(separator: ":", maxSplits: 1).dropFirst().first?.trimmingCharacters(in: .whitespaces)
            return raw.flatMap { IPAddress($0.split(separator: "%").first.map(String.init) ?? $0)?.description }
        }
        // Our own proxy listens on loopback and would forward a query to itself
        // forever; a leftover entry from an interrupted run must not be upstream.
        // A link-local server loses its zone above and is then unreachable, so
        // keeping it would only burn one of the two failover attempts.
        .filter { $0 != "::1" && !$0.hasPrefix("127.") && !$0.lowercased().hasPrefix("fe80:") }
        let ifconfig = try runner.checked("/sbin/ifconfig", [interface]).stdout
        return .init(
            physicalInterface: interface,
            ipv4Gateway: gateway4,
            ipv6Gateway: gateway6,
            dnsServers: Array(NSOrderedSet(array: dns)) as? [String] ?? dns,
            lanNetworks: parseLAN(ifconfig)
        )
    }

    static func hasConflictingVPN(using runner: CommandRunner) -> Bool {
        guard let result = try? runner.run("/usr/sbin/scutil", ["--nc", "list"]), result.status == 0 else { return false }
        return result.stdout.components(separatedBy: .newlines).contains { $0.contains("(Connected)") }
    }

    private static func value(after key: String, in text: String) -> String? {
        text.components(separatedBy: .newlines).first { $0.contains(key) }?
            .split(separator: ":", maxSplits: 1).dropFirst().first?
            .trimmingCharacters(in: .whitespaces)
    }

    private static func parseLAN(_ text: String) -> [String] {
        var result = ["169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8"]
        for line in text.components(separatedBy: .newlines) {
            let fields = line.split(whereSeparator: \ .isWhitespace).map(String.init)
            guard fields.first == "inet", fields.count >= 4,
                  let address = IPAddress(fields[1]),
                  let maskIndex = fields.firstIndex(of: "netmask"), maskIndex + 1 < fields.count,
                  let rawMask = UInt32(fields[maskIndex + 1].replacingOccurrences(of: "0x", with: ""), radix: 16)
            else { continue }
            let prefix = rawMask.nonzeroBitCount
            let networkBytes = zip(address.bytes, [24, 16, 8, 0].map { UInt8((rawMask >> $0) & 0xff) }).map(&)
            let network = networkBytes.map(String.init).joined(separator: ".")
            result.append("\(network)/\(prefix)")
            continue
        }
        for line in text.components(separatedBy: .newlines) {
            let fields = line.split(whereSeparator: \ .isWhitespace).map(String.init)
            guard fields.first == "inet6", fields.count >= 2,
                  let prefixIndex = fields.firstIndex(of: "prefixlen"), prefixIndex + 1 < fields.count,
                  let prefix = Int(fields[prefixIndex + 1]),
                  let cidr = CIDR("\(fields[1].split(separator: "%").first.map(String.init) ?? fields[1])/\(prefix)")
            else { continue }
            result.append(cidr.description)
        }
        return Array(Set(result)).sorted()
    }
}

struct PolicyState: Equatable, Sendable {
    var snapshot: NetworkSnapshot
    var openVPNInterface: String?
    var amneziaWGInterface: String?
    var amneziaWGSupportsIPv6 = false
    var directByDefault = false
    var corporate: Set<String> = []
    var direct: Set<String> = []
    var control: Set<String> = []

    var corporate4: [String] { corporate.filter { !$0.contains(":") }.sorted() }
    var corporate6: [String] { corporate.filter { $0.contains(":") }.sorted() }
    var direct4: [String] { direct.filter { !$0.contains(":") }.sorted() }
    var direct6: [String] { direct.filter { $0.contains(":") }.sorted() }
    var control4: [String] { control.filter { !$0.contains(":") }.sorted() }
    var control6: [String] { control.filter { $0.contains(":") }.sorted() }
}

final class PFController {
    static let anchorName = "com.apple/vpn-router"

    private let runner: CommandRunner
    private var token: String?
    private let anchor = PFController.anchorName

    init(runner: CommandRunner) { self.runner = runner }

    func apply(_ state: PolicyState) throws {
        if token == nil {
            let enabled = try runner.checked("/sbin/pfctl", ["-E"])
            token = (enabled.stdout + " " + enabled.stderr).components(separatedBy: .whitespacesAndNewlines)
                .first { $0.count >= 8 && $0.allSatisfy(\.isHexDigit) }
            guard token != nil else { throw RouterErrorInfo(.firewallFailure, "PF не вернул enable-token") }
        }
        let configuration = try FirewallPolicyRenderer.render(.init(
            physicalInterface: state.snapshot.physicalInterface,
            openVPNInterface: state.openVPNInterface,
            amneziaWGInterface: state.amneziaWGInterface,
            corporate: Array(state.corporate),
            direct: Array(state.direct),
            control: Array(state.control),
            lan: state.snapshot.lanNetworks,
            directByDefault: state.directByDefault
        ))
        let path = "/var/run/vpn-router-pf.conf"
        try configuration.write(toFile: path, atomically: true, encoding: .utf8)
        chmod(path, S_IRUSR | S_IWUSR)
        // No cleanup() here: flushing the anchor would drop protection entirely.
        // rebuildPolicy already rolls back to the previous policy on failure.
        do { try runner.checked("/sbin/pfctl", ["-a", anchor, "-f", path]) }
        catch { throw RouterErrorInfo(.firewallFailure, "Не удалось применить PF anchor: \(error.localizedDescription)") }
    }

    func cleanup() {
        _ = try? runner.run("/sbin/pfctl", ["-a", anchor, "-F", "all"])
        if let token { _ = try? runner.run("/sbin/pfctl", ["-X", token]) }
        token = nil
        try? FileManager.default.removeItem(atPath: "/var/run/vpn-router-pf.conf")
    }

}

final class RouteController {
    private let runner: CommandRunner
    private var installed = Set<Route>()

    init(runner: CommandRunner) { self.runner = runner }

    func reconcile(_ state: PolicyState) throws {
        var desired = Set<Route>()
        for address in state.control.union(state.direct) {
            if let route = Route.physical(address, snapshot: state.snapshot) { desired.insert(route) }
        }
        if let interface = state.openVPNInterface {
            desired.formUnion(state.corporate.compactMap { Route.tunnel($0, interface: interface) })
        }
        if let interface = state.amneziaWGInterface {
            desired.insert(.init(family: .v4, destination: "0.0.0.0/1", gateway: nil, interface: interface))
            desired.insert(.init(family: .v4, destination: "128.0.0.0/1", gateway: nil, interface: interface))
            if state.amneziaWGSupportsIPv6 {
                desired.insert(.init(family: .v6, destination: "::/1", gateway: nil, interface: interface))
                desired.insert(.init(family: .v6, destination: "8000::/1", gateway: nil, interface: interface))
            }
        }
        let original = installed
        var added: [Route] = []
        do {
            for route in desired.subtracting(original) {
                try add(route)
                added.append(route)
            }
            // A route we no longer want that the kernel already dropped with its
            // interface is the outcome we were after, so removal never fails.
            for route in original.subtracting(desired) { remove(route) }
            installed = desired
        } catch {
            for route in added { remove(route) }
            installed = original
            throw error
        }
    }

    func cleanup() {
        for route in installed { remove(route) }
        installed.removeAll()
    }

    private func add(_ route: Route) throws {
        var args = ["-n", "add"] + route.familyArguments + ["-net", route.destination]
        if let gateway = route.gateway { args.append(gateway) }
        else if let interface = route.interface { args += ["-interface", interface] }
        let result: CommandResult
        do { result = try runner.run("/sbin/route", args) }
        catch { throw RouterErrorInfo(.routingFailure, "Не удалось запустить route: \(error.localizedDescription)") }
        // A stale route left behind by a crashed run is already the state we want.
        if result.status == 0 || result.stderr.contains("File exists") { return }
        throw RouterErrorInfo(
            .routingFailure,
            "Не удалось добавить маршрут \(route.destination): \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        )
    }

    private func remove(_ route: Route) {
        _ = try? runner.run("/sbin/route", ["-n", "delete"] + route.familyArguments + ["-net", route.destination])
    }
}

private struct Route: Hashable {
    let family: IPFamily
    let destination: String
    let gateway: String?
    let interface: String?

    var familyArguments: [String] { family == .v6 ? ["-inet6"] : [] }

    static func physical(_ destination: String, snapshot: NetworkSnapshot) -> Route? {
        let parsedAddress = IPAddress(destination) ?? CIDR(destination)?.address
        let destinationPrefix = CIDR(destination)?.prefixLength ?? (parsedAddress?.family == .v6 ? 128 : 32)
        if let parsedAddress,
           snapshot.lanNetworks.compactMap(CIDR.init).contains(where: {
               $0.prefixLength <= destinationPrefix && $0.contains(parsedAddress)
           }) {
            return nil
        }
        let family: IPFamily = destination.contains(":") ? .v6 : .v4
        let gateway = family == .v4 ? snapshot.ipv4Gateway : snapshot.ipv6Gateway
        guard let gateway else { return nil }
        return .init(family: family, destination: normalizedDestination(destination), gateway: gateway, interface: nil)
    }

    static func tunnel(_ destination: String, interface: String) -> Route? {
        guard IPAddress(destination) != nil || CIDR(destination) != nil else { return nil }
        return .init(
            family: destination.contains(":") ? .v6 : .v4,
            destination: normalizedDestination(destination), gateway: nil, interface: interface
        )
    }

    private static func normalizedDestination(_ value: String) -> String {
        if value.contains("/") { return value }
        return value + (value.contains(":") ? "/128" : "/32")
    }
}

final class ResolverController {
    private let directory = URL(fileURLWithPath: "/etc/resolver", isDirectory: true)
    private let backupURL = URL(fileURLWithPath: "/var/db/com.vpnrouter.resolver-backup.json")
    private let missing = "__VPN_ROUTER_MISSING__"
    // "/" cannot occur in a domain, so this never collides with a resolver file
    // and rides the same backup file and crash recovery as the resolver entries.
    private let systemKey = "system-dns/"
    private var backups: [String: String] = [:]
    private var active = Set<String>()

    /// "en0" -> "Wi-Fi" from `networksetup -listnetworkserviceorder`, whose
    /// listing pairs a "(1) Name" line with a following "(... Device: en0)" line.
    static func serviceName(forInterface interface: String, in listing: String) -> String? {
        var name: String?
        for line in listing.components(separatedBy: .newlines) {
            if line.contains("Device: \(interface))") { return name }
            if line.hasPrefix("("), let separator = line.range(of: ") ") {
                name = String(line[separator.upperBound...]).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    func apply(suffixes: [String], port: UInt16, systemDNSService: String? = nil) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let desired = Set(suffixes.filter { RuleSet.normalizeDomain($0) == $0 })
        for suffix in active.subtracting(desired) { restore(suffix) }
        for suffix in desired where backups[suffix] == nil {
            backups[suffix] = (try? String(contentsOf: directory.appendingPathComponent(suffix), encoding: .utf8)) ?? missing
        }
        // On disk before any file changes: after a crash cleanup() only undoes what
        // the backup names, and a resolver file it misses points at a dead 127.0.0.1.
        try saveBackups()
        for suffix in desired {
            let file = directory.appendingPathComponent(suffix)
            let content = "# managed by Commutator\ndomain \(suffix)\nnameserver 127.0.0.1\nport \(port)\ntimeout 2\n"
            try content.write(to: file, atomically: true, encoding: .utf8)
            chmod(file.path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
        }
        active = desired
        if let systemDNSService { try captureAndOverrideSystemDNS(service: systemDNSService) }
        else if backups[systemKey] != nil { restore(systemKey) }
        try saveBackups()
        flushCaches()
    }

    private func saveBackups() throws {
        try JSONEncoder().encode(backups).write(to: backupURL, options: .atomic)
        chmod(backupURL.path, S_IRUSR | S_IWUSR)
    }

    func cleanup() {
        if backups.isEmpty,
           let data = try? Data(contentsOf: backupURL),
           let persisted = try? JSONDecoder().decode([String: String].self, from: data) {
            backups = persisted
        }
        for suffix in backups.keys { restore(suffix) }
        backups.removeAll()
        active.removeAll()
        try? FileManager.default.removeItem(at: backupURL)
        flushCaches()
    }

    // Sends every system query to the proxy so the AmneziaWG class can use the
    // resolver named in its profile. If the daemon dies the machine is left
    // pointing at a dead 127.0.0.1 until launchd restarts it and cleanup() runs.
    private func captureAndOverrideSystemDNS(service: String) throws {
        if backups[systemKey] == nil {
            let current = (try? CommandRunner.live.run("/usr/sbin/networksetup", ["-getdnsservers", service]))?.stdout ?? ""
            backups[systemKey] = ([service] + Self.parseServers(current)).joined(separator: "\n")
            try saveBackups()
        }
        // Silently losing this leaves the status at "Работает" while every system
        // query keeps going to the network's resolver — a DNS leak, not an outage,
        // which is exactly the kind that goes unnoticed.
        let result = try? CommandRunner.live.run("/usr/sbin/networksetup", ["-setdnsservers", service, "127.0.0.1"])
        guard let result, !Self.failed(result) else {
            throw RouterErrorInfo(.dnsFailure, "Не удалось переключить системный DNS сервиса «\(service)» на локальный прокси")
        }
    }

    // networksetup happily exits 0 while printing "** Error: ...", so the status
    // code alone does not tell us whether the change took.
    static func failed(_ result: CommandResult) -> Bool {
        result.status != 0 || result.stdout.contains("Error") || result.stderr.contains("Error")
    }

    private func restoreSystemDNS(_ stored: String) {
        var parts = stored.components(separatedBy: "\n")
        guard !parts.isEmpty else { return }
        let service = parts.removeFirst()
        let servers = parts.filter { !$0.isEmpty }
        _ = try? CommandRunner.live.run(
            "/usr/sbin/networksetup",
            ["-setdnsservers", service] + (servers.isEmpty ? ["Empty"] : servers)
        )
    }

    // "There aren't any DNS Servers set on Wi-Fi." must not survive as a server.
    // A scoped address is validated without its zone but stored with it: dropping
    // "fe80::1%en0" here would quietly shorten the list we restore on shutdown.
    static func parseServers(_ output: String) -> [String] {
        output.components(separatedBy: .newlines).compactMap { line -> String? in
            let value = line.trimmingCharacters(in: .whitespaces)
            let unscoped = value.split(separator: "%").first.map(String.init) ?? value
            return IPAddress(unscoped) == nil ? nil : value
        }
    }

    private func restore(_ suffix: String) {
        guard let oldContent = backups[suffix] else { return }
        if suffix == systemKey {
            restoreSystemDNS(oldContent)
            backups[systemKey] = nil
            return
        }
        let file = directory.appendingPathComponent(suffix)
        if oldContent == missing { try? FileManager.default.removeItem(at: file) }
        else { try? oldContent.write(to: file, atomically: true, encoding: .utf8) }
        active.remove(suffix)
    }

    private func flushCaches() {
        _ = try? CommandRunner.live.run("/usr/bin/dscacheutil", ["-flushcache"])
        _ = try? CommandRunner.live.run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }
}
