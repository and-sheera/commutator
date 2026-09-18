import Foundation

/// Makes a log line safe to hand to whoever helps with a problem.
///
/// The log has to name what it talks about: a handshake that never completes is
/// only explainable if the same server stays recognisable across the route, the
/// firewall and the engine's own lines. So identities are not dropped but given
/// stable aliases — one address is always the same «адрес#2».
///
/// Names are replaced only where they were registered (the work servers, the
/// personal VPN endpoint, the subscription host). Guessing at hostnames by shape
/// would rename our own identifiers — "com.vpnrouter", "openvpn.conf" — and make
/// the log unreadable for the sake of nothing.
///
/// What never reaches here, and must not start to: the names the user's own
/// machine resolves. Writing those would turn the log into a browsing history.
public final class LogRedactor: @unchecked Sendable {
    private let lock = NSLock()
    private var aliases: [String: String] = [:]
    private var counters: [String: Int] = [:]
    private var hosts: [String] = []

    public init() {}

    /// A name the daemon itself works with. Registered before it can show up in a
    /// line — a profile is loaded long before its server is contacted.
    public func register(host: String) {
        let value = host.lowercased().trimmingCharacters(in: .whitespaces)
        guard value.contains("."), IPAddress(value) == nil else { return }
        lock.lock()
        defer { lock.unlock() }
        guard !hosts.contains(value) else { return }
        hosts.append(value)
        // Longest first: a.b.example must not be half-replaced by b.example.
        hosts.sort { $0.count > $1.count }
    }

    public func redact(_ line: String) -> String {
        var result = Self.replace(Self.emailPattern, in: line) { _ in "<скрыто>" }
        result = Self.replace(Self.fieldPattern, in: result, group: 2) { _ in "<скрыто>" }
        result = maskHosts(in: result)
        result = Self.replace(Self.ipv6Pattern, in: result) { [weak self] in self?.maskAddress($0) }
        result = Self.replace(Self.ipv4Pattern, in: result) { [weak self] in self?.maskAddress($0) }
        return Self.replace(Self.keyPattern, in: result) { String($0.prefix(4)) + "…" }
    }

    private func maskHosts(in line: String) -> String {
        let known = lock.withLock { hosts }
        guard !known.isEmpty else { return line }
        var result = line
        for host in known where result.range(of: host, options: .caseInsensitive) != nil {
            result = result.replacingOccurrences(of: host, with: alias(for: host, kind: "хост"), options: .caseInsensitive)
        }
        return result
    }

    private func maskAddress(_ token: String) -> String? {
        guard let address = IPAddress(token), !Self.isKept(address) else { return nil }
        return alias(for: address.description, kind: "адрес")
    }

    private func alias(for value: String, kind: String) -> String {
        lock.lock()
        defer { lock.unlock() }
        if let existing = aliases[value] { return existing }
        let next = (counters[kind] ?? 0) + 1
        counters[kind] = next
        let alias = "\(kind)#\(next)"
        aliases[value] = alias
        return alias
    }

    /// Addresses that identify nobody and carry the diagnosis: the local network,
    /// the tunnels' own ends, loopback, and the netmasks OpenVPN prints next to
    /// every pushed route.
    private static func isKept(_ address: IPAddress) -> Bool {
        let bytes = address.bytes
        if address.family == .v4 {
            if isNetmask(bytes) { return true }
            switch (bytes[0], bytes[1]) {
            case (0, _), (10, _), (127, _), (169, 254), (192, 168): return true
            case (172, 16...31), (100, 64...127): return true
            case (224...255, _): return true
            default: return false
            }
        }
        if bytes.allSatisfy({ $0 == 0 }) { return true }
        if bytes.prefix(15).allSatisfy({ $0 == 0 }), bytes[15] == 1 { return true }
        // fe80::/10, fc00::/7, ff00::/8
        return bytes[0] == 0xff || bytes[0] & 0xfe == 0xfc || (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
    }

    /// A contiguous run of ones: "255.255.255.0" is a mask, "255.8.29.117" is a host.
    private static func isNetmask(_ bytes: [UInt8]) -> Bool {
        let value = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return value == 0 || (~value &+ 1) & ~value == 0
    }

    private static let emailPattern = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
    /// Certificate subjects and the identities OpenVPN echoes through its
    /// management channel: whose certificate it is, and which servers a profile names.
    private static let fieldPattern =
        "(?i)\\b(emailAddress|common_name|CN|OU|O|ST|L|name|tls_id_[0-9]+|tls_digest[A-Za-z0-9_]*|X509_[0-9]+_[A-Za-z]+|remote_[0-9]+)=([^,\\n]*)"
    private static let ipv4Pattern = "\\b[0-9]{1,3}(?:\\.[0-9]{1,3}){3}\\b"
    private static let ipv6Pattern = "(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])"
    /// A WireGuard or TLS key: base64 long enough that nothing else looks like it.
    private static let keyPattern = "\\b[A-Za-z0-9+/]{42,}={0,2}"

    /// Rewrites every match of `pattern`; a transform returning nil leaves that
    /// match as it was.
    private static func replace(
        _ pattern: String,
        in line: String,
        group: Int = 0,
        transform: (String) -> String?
    ) -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return line }
        var result = line
        let matches = regex.matches(in: line, range: NSRange(line.startIndex..., in: line))
        // Back to front: an earlier replacement would shift every later range.
        for match in matches.reversed() {
            guard let range = Range(match.range(at: group), in: result),
                  let replacement = transform(String(result[range]))
            else { continue }
            result.replaceSubrange(range, with: replacement)
        }
        return result
    }
}
