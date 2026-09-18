import Foundation

public enum TrafficClass: String, Codable, Sendable {
    case corporate, direct, amneziaWG
}

public struct RuleSet: Sendable {
    public let rules: [RoutingRule]
    private let domains: [(suffix: String, target: TrafficClass)]
    private let networks: [(cidr: CIDR, target: TrafficClass)]
    /// The VPN servers' own names. Direct even under a corporate suffix: the
    /// server pushes its domain, and a reconnect then looked its own name up
    /// through the very tunnel that was down.
    private let endpoints: Set<String>

    public init(rules: [RoutingRule], endpoints: [String] = []) throws {
        guard rules.count <= 500 else {
            throw RouterErrorInfo(.invalidConfiguration, "Разрешено не более 500 правил")
        }
        var normalized: [RoutingRule] = []
        var domains: [(String, TrafficClass)] = []
        var networks: [(CIDR, TrafficClass)] = []

        for var rule in rules where rule.enabled {
            let target: TrafficClass = rule.target == .corporate ? .corporate : .direct
            switch rule.kind {
            case .domain:
                guard let domain = Self.normalizeDomain(rule.value) else {
                    throw RouterErrorInfo(.invalidConfiguration, "Некорректный домен: \(rule.value)")
                }
                rule.value = domain
                domains.append((domain, target))
            case .ip:
                guard let address = IPAddress(rule.value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                    throw RouterErrorInfo(.invalidConfiguration, "Некорректный IP: \(rule.value)")
                }
                rule.value = address.description
                networks.append((CIDR(address: address, prefixLength: address.family == .v4 ? 32 : 128), target))
            case .cidr:
                guard let cidr = CIDR(rule.value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                    throw RouterErrorInfo(.invalidConfiguration, "Некорректная сеть: \(rule.value)")
                }
                guard !cidr.coversDefault else {
                    throw RouterErrorInfo(.invalidConfiguration, "Сеть \(rule.value) охватывает весь интернет: вместо неё выключите ненужный VPN")
                }
                rule.value = cidr.description
                networks.append((cidr, target))
            }
            normalized.append(rule)
        }

        // Corporate beats every other match regardless of length, so this order
        // only decides which direct rule wins among direct rules.
        self.domains = domains.sorted {
            $0.0.count == $1.0.count ? $0.1 == .corporate && $1.1 != .corporate : $0.0.count > $1.0.count
        }
        self.networks = networks.sorted {
            $0.0.prefixLength == $1.0.prefixLength
                ? $0.1 == .corporate && $1.1 != .corporate
                : $0.0.prefixLength > $1.0.prefixLength
        }
        self.rules = normalized
        self.endpoints = Set(endpoints.compactMap(Self.normalizeDomain))
    }

    public func classify(domain raw: String) -> TrafficClass {
        guard let domain = Self.normalizeDomain(raw) else { return .amneziaWG }
        if endpoints.contains(domain) { return .direct }
        let matches = domains.filter { domain == $0.suffix || domain.hasSuffix("." + $0.suffix) }
        if matches.contains(where: { $0.target == .corporate }) { return .corporate }
        return matches.first?.target ?? .amneziaWG
    }

    public func classify(ip raw: String) -> TrafficClass {
        guard let address = IPAddress(raw) else { return .amneziaWG }
        let matches = networks.filter { $0.cidr.contains(address) }
        if matches.contains(where: { $0.target == .corporate }) { return .corporate }
        if let longest = matches.first {
            return longest.target
        }
        return .amneziaWG
    }

    public var domainSuffixes: [String] {
        Array(Set(domains.map(\.suffix)).union(endpoints)).sorted()
    }

    public var explicitNetworks: [(CIDR, TrafficClass)] { networks }

    public static func normalizeDomain(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.hasPrefix("*.") { value.removeFirst(2) }
        while value.hasPrefix(".") { value.removeFirst() }
        while value.hasSuffix(".") { value.removeLast() }
        guard !value.isEmpty, value.count <= 253, !value.contains("/") else { return nil }

        var components = URLComponents()
        components.scheme = "https"
        components.host = value
        guard let encodedURL = components.string,
              let hostStart = encodedURL.range(of: "://")?.upperBound
        else { return nil }
        let encoded = String(encodedURL[hostStart...]).split(separator: "/").first.map(String.init) ?? value
        let labels = encoded.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 && $0.first != "-" && $0.last != "-" }) else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-.")
        guard encoded.unicodeScalars.allSatisfy(allowed.contains) else { return nil }
        return encoded
    }
}

/// The rules page as the user edits it, and the form it takes on the clipboard.
public struct RoutingText: Equatable, Sendable {
    public var corporate: String
    public var direct: String
    public var directRU: Bool
    public var directSU: Bool
    public var directRF: Bool

    public init(corporate: String = "", direct: String = "", directRU: Bool = true, directSU: Bool = true, directRF: Bool = true) {
        self.corporate = corporate
        self.direct = direct
        self.directRU = directRU
        self.directSU = directSU
        self.directRF = directRF
    }

    public init(settings: RouterSettings) {
        func text(_ target: RuleTarget) -> String {
            settings.rules.filter { $0.target == target }.map(\.value).joined(separator: "\n")
        }
        self.init(
            corporate: text(.corporate), direct: text(.direct),
            directRU: settings.directRU, directSU: settings.directSU, directRF: settings.directRF
        )
    }

    /// `settings` with these rules, or an error naming the first line that is
    /// not a site, an address or a range — in which case nothing changes.
    public func applied(to settings: RouterSettings) throws -> RouterSettings {
        var updated = settings
        updated.rules = try Self.rules(corporate, .corporate) + Self.rules(direct, .direct)
        updated.directRU = directRU
        updated.directSU = directSU
        updated.directRF = directRF
        _ = try RuleSet(rules: updated.effectiveRules)
        return updated
    }

    /// A link copied from the browser stands for its site:
    /// `https://cloudflare.com/cdn-cgi/trace` → `cloudflare.com`.
    public static func site(_ value: String) -> String {
        guard value.contains("://"), let host = URL(string: value)?.host(percentEncoded: false), !host.isEmpty else { return value }
        return host
    }

    static func rules(_ text: String, _ target: RuleTarget) throws -> [RoutingRule] {
        try text.components(separatedBy: .newlines).compactMap { raw in
            let value = site(raw.trimmingCharacters(in: .whitespacesAndNewlines))
            guard !value.isEmpty else { return nil }
            if value.contains("/"), CIDR(value) != nil { return .init(target: target, kind: .cidr, value: value) }
            if IPAddress(value) != nil { return .init(target: target, kind: .ip, value: value) }
            guard RuleSet.normalizeDomain(value) != nil else {
                throw RouterErrorInfo(.invalidConfiguration, "Не понимаю строку «\(value)»: нужен сайт (site.org), IP-адрес (192.168.1.10) или диапазон (10.0.0.0/8)")
            }
            return .init(target: target, kind: .domain, value: value)
        }
    }

    public var exported: String {
        let zones = [(directRU, ".ru"), (directSU, ".su"), (directRF, ".рф")].filter(\.0).map(\.1)
        return (["# Коммутатор: маршруты. Импорт — в разделе «Маршруты».", "[openvpn]"]
            + Self.entries(corporate) + ["[direct]"] + zones + Self.entries(direct))
            .joined(separator: "\n") + "\n"
    }

    /// nil unless the text is an export: pasting whatever happens to be on the
    /// clipboard must not wipe both lists.
    public init?(exported text: String) {
        var corporate: [String] = []
        var direct: [String] = []
        var zones: Set<String> = []
        var target: RuleTarget?
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            switch line.lowercased() {
            case "[openvpn]": target = .corporate
            case "[direct]": target = .direct
            default:
                switch target {
                case nil: return nil
                case .corporate?: corporate.append(line)
                case .direct?:
                    // The zone boxes travel as ordinary lines and come back as boxes.
                    if let zone = RuleSet.normalizeDomain(line), ["ru", "su", "xn--p1ai"].contains(zone) { zones.insert(zone) }
                    else { direct.append(line) }
                }
            }
        }
        guard target != nil else { return nil }
        self.init(
            corporate: corporate.joined(separator: "\n"), direct: direct.joined(separator: "\n"),
            directRU: zones.contains("ru"), directSU: zones.contains("su"), directRF: zones.contains("xn--p1ai")
        )
    }

    private static func entries(_ text: String) -> [String] {
        text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
