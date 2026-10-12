import Foundation

public struct RuleSet: Sendable {
    public enum Match: Hashable, Sendable {
        /// A VPN server's own name: out through the network, whatever claims it.
        case endpoint
        case direction(UUID)
    }

    /// Rank is the route's place in the list: the lowest one matching wins,
    /// however much longer another route's match is.
    private let domains: [(suffix: String, rank: Int)]
    private let networks: [(cidr: CIDR, rank: Int)]
    private let order: [UUID]
    /// The VPN servers' own names. Direct even under a work suffix: the server
    /// pushes its domain, and a reconnect then looked its own name up through
    /// the very tunnel that was down.
    private let endpoints: Set<String>

    /// `lists` in priority order; the caller leaves out routes that are off.
    public init(lists: [(UUID, [RoutingRule])], endpoints: [String] = []) throws {
        guard lists.reduce(0, { $0 + $1.1.count }) <= 500 else {
            throw RouterErrorInfo(.invalidConfiguration, "Разрешено не более 500 правил")
        }
        var domains: [(String, Int)] = []
        var networks: [(CIDR, Int)] = []
        for (rank, list) in lists.enumerated() {
            for rule in list.1 where rule.enabled {
                switch rule.kind {
                case .domain:
                    guard let domain = Self.normalizeDomain(rule.value) else {
                        throw RouterErrorInfo(.invalidConfiguration, "Некорректный домен: \(rule.value)")
                    }
                    domains.append((domain, rank))
                case .ip:
                    guard let address = IPAddress(rule.value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                        throw RouterErrorInfo(.invalidConfiguration, "Некорректный IP: \(rule.value)")
                    }
                    networks.append((CIDR(address: address, prefixLength: address.family == .v4 ? 32 : 128), rank))
                case .cidr:
                    guard let cidr = CIDR(rule.value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                        throw RouterErrorInfo(.invalidConfiguration, "Некорректная сеть: \(rule.value)")
                    }
                    guard !cidr.coversDefault else {
                        throw RouterErrorInfo(.invalidConfiguration, "Сеть \(rule.value) охватывает весь интернет: вместо неё отметьте у направления «Для остального трафика»")
                    }
                    networks.append((cidr, rank))
                }
            }
        }
        self.domains = domains
        self.networks = networks
        self.order = lists.map(\.0)
        self.endpoints = Set(endpoints.compactMap(Self.normalizeDomain))
    }

    /// nil: no route claims it, so it goes wherever the rest goes.
    public func classify(domain raw: String) -> Match? {
        guard let domain = Self.normalizeDomain(raw) else { return nil }
        if endpoints.contains(domain) { return .endpoint }
        return domains.filter { domain == $0.suffix || domain.hasSuffix("." + $0.suffix) }
            .map(\.rank).min().map { .direction(order[$0]) }
    }

    public func classify(ip raw: String) -> UUID? {
        guard let address = IPAddress(raw) else { return nil }
        return networks.filter { $0.cidr.contains(address) }.map(\.rank).min().map { order[$0] }
    }

    /// Where a route stands in the list, for choosing between two that claim
    /// one address.
    public func rank(of direction: UUID) -> Int? { order.firstIndex(of: direction) }

    public var domainSuffixes: [String] {
        Array(Set(domains.map(\.suffix)).union(endpoints)).sorted()
    }

    public var explicitNetworks: [(CIDR, UUID)] { networks.map { ($0.cidr, order[$0.rank]) } }

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

/// «Маршруты» as the user edits them, and the form they take on the clipboard.
/// Rules are text here; only «Применить» turns them into settings.
public struct RoutingDraft: Equatable, Sendable {
    /// Their `rules` stay empty: the text in `texts` is what counts.
    public var directions: [Direction]
    public var texts: [UUID: String]
    public var defaultDirection: UUID?

    public init(settings: RouterSettings) {
        directions = settings.directions.map { var direction = $0; direction.rules = []; return direction }
        texts = Dictionary(settings.directions.map { ($0.id, $0.rules.map(\.value).joined(separator: "\n")) }) { first, _ in first }
        defaultDirection = settings.defaultDirection
    }

    /// The draft the applied settings read back as: the list of the route that
    /// takes the rest is not in the settings (that route has no rules), so it
    /// comes from what the app kept aside, by that route's id. Marking a route
    /// for the rest and back again then loses nothing.
    public init(settings: RouterSettings, parked: [UUID: String]) {
        self.init(settings: settings)
        if let id = settings.defaultDirection { texts[id] = parked[id] ?? "" }
    }

    /// `settings` with these routes, or an error naming the first line that is
    /// not a site, an address or a range — in which case nothing changes.
    public func applied(to settings: RouterSettings) throws -> RouterSettings {
        var updated = settings
        var names = Set<String>()
        updated.directions = try directions.map { direction in
            var direction = direction
            let name = direction.name.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { throw RouterErrorInfo(.invalidConfiguration, "У направления должно быть название") }
            // An export tells routes apart by name alone, case aside, as does the import.
            guard names.insert(name.lowercased()).inserted else {
                throw RouterErrorInfo(.invalidConfiguration, "Названия направлений должны различаться: «\(name)» повторяется")
            }
            direction.name = name
            // The rest's route takes no rules: they would only reorder what it
            // gets anyway, and the page does not show them.
            guard direction.id != defaultDirection else {
                direction.rules = []
                return direction
            }
            do { direction.rules = try Self.rules(texts[direction.id] ?? "") }
            catch let error as RouterErrorInfo { throw RouterErrorInfo(error.code, "«\(name)»: \(error.message)") }
            return direction
        }
        updated.defaultDirection = directions.contains { $0.id == defaultDirection } ? defaultDirection : nil
        _ = try RuleSet(lists: updated.directions.map { ($0.id, $0.rules) })
        return updated
    }

    /// A link copied from the browser stands for its site:
    /// `https://cloudflare.com/cdn-cgi/trace` → `cloudflare.com`.
    public static func site(_ value: String) -> String {
        guard value.contains("://"), let host = URL(string: value)?.host(percentEncoded: false), !host.isEmpty else { return value }
        return host
    }

    static func rules(_ text: String) throws -> [RoutingRule] {
        try text.components(separatedBy: .newlines).compactMap { raw in
            let value = site(raw.trimmingCharacters(in: .whitespacesAndNewlines))
            guard !value.isEmpty else { return nil }
            if value.contains("/"), CIDR(value) != nil { return .init(kind: .cidr, value: value) }
            if IPAddress(value) != nil { return .init(kind: .ip, value: value) }
            guard RuleSet.normalizeDomain(value) != nil else {
                throw RouterErrorInfo(.invalidConfiguration, "Не понимаю строку «\(value)»: нужен сайт (site.org), IP-адрес (192.168.1.10) или диапазон (10.0.0.0/8)")
            }
            return .init(kind: .domain, value: value)
        }
    }

    /// Names and rules only: which VPN a route uses means nothing on another Mac.
    public var exported: String {
        (["# Коммутатор: маршруты. Импорт — в разделе «Маршруты»."] + directions.flatMap { direction in
            ["[\(direction.name)]"] + Self.entries(texts[direction.id] ?? "")
        }).joined(separator: "\n") + "\n"
    }

    /// This draft with an export's lists put in, by route name. A route this
    /// Mac lacks is added off and without a VPN, until one is picked for it:
    /// run as "direct" it would send work sites out to the internet.
    /// nil unless the text is an export: pasting whatever happens to be on the
    /// clipboard must not wipe the lists.
    public func importing(_ text: String) -> RoutingDraft? {
        var sections: [(name: String, lines: [String])] = []
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("["), line.hasSuffix("]"), line.count > 2 {
                let name = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                // Exports from before routes named their two lists this way.
                sections.append((["openvpn": "Работа", "direct": "Напрямую"][name.lowercased()] ?? name, []))
            } else if sections.isEmpty {
                return nil
            } else {
                sections[sections.count - 1].lines.append(line)
            }
        }
        guard !sections.isEmpty else { return nil }
        var result = self
        for section in sections {
            let body = section.lines.joined(separator: "\n")
            if let existing = result.directions.first(where: { $0.name.compare(section.name, options: .caseInsensitive) == .orderedSame }) {
                result.texts[existing.id] = body
            } else {
                let added = Direction(name: section.name, path: .unset, enabled: false)
                result.directions.append(added)
                result.texts[added.id] = body
            }
        }
        return result
    }

    private static func entries(_ text: String) -> [String] {
        text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}
