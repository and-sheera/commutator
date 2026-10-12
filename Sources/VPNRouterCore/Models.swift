import Foundation

/// The two kinds a profile file or pasted text can be; Xray arrives as links
/// through `XrayUpdate` instead.
public enum VPNKind: String, Codable, CaseIterable, Sendable {
    case openVPN
    case amneziaWG

    public var title: String { self == .openVPN ? "OpenVPN" : "AmneziaWG" }
}

/// The engine a pasted personal profile is for, so nobody has to pick a type
/// before adding one.
public enum ExitEngine: String, Codable, CaseIterable, Sendable {
    case amneziaWG, xray

    public var title: String { self == .amneziaWG ? "AmneziaWG" : "Xray" }

    /// Amnezia's vpn:// link and a WireGuard-style config are AmneziaWG,
    /// anything else is a share link or a subscription address.
    public init(profile text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        self = trimmed.lowercased().hasPrefix("vpn://") || trimmed.contains("[Interface]") ? .amneziaWG : .xray
    }
}

public enum TunnelPhase: String, Codable, Sendable {
    case disconnected, connecting, connected, reconnecting, error

    public var russianTitle: String {
        switch self {
        case .disconnected: "Не подключён"
        case .connecting: "Подключение"
        case .connected: "Подключён"
        case .reconnecting: "Переподключение"
        case .error: "Ошибка"
        }
    }

    /// Deleting the profile behind a tunnel that is up, coming up or
    /// recovering would pull the rug out from under a live connection.
    public var blocksDeletion: Bool { self == .connected || self == .connecting || self == .reconnecting }
}

public enum ProtectionState: String, Codable, Sendable {
    case off, starting, protected, degraded, error

    public var russianTitle: String {
        switch self {
        // Short: they share a line with a switch. And no "protection": the app
        // routes traffic, it is no antivirus.
        case .off: "Выключен"
        case .starting: "Подключается"
        case .protected: "Работает"
        case .degraded: "Работает частично"
        case .error: "Ошибка"
        }
    }

    /// Over the tunnels of the routes that are on; none means only routes
    /// without a VPN, which have nothing to be down.
    public static func evaluate(desiredEnabled: Bool, tunnels: [TunnelStatus]) -> Self {
        guard desiredEnabled else { return .off }
        if tunnels.allSatisfy({ $0.phase == .connected && $0.interfaceName != nil }) { return .protected }
        // One tunnel up while another is still on its first attempt is a
        // normal start: calling it «Работает частично» read as a failure.
        let phases = tunnels.map(\.phase)
        if phases.contains(.connecting), phases.allSatisfy({ $0 == .connecting || $0 == .connected }) { return .starting }
        return .degraded
    }
}

/// What an OpenVPN server sent at connect: its networks, its DNS and its
/// domains, shown on «Маршруты» so nobody retypes them as rules.
public struct PushedOptions: Codable, Equatable, Sendable {
    public var routes: [String]
    public var dns: [String]
    public var domains: [String]
    /// When the server last sent them: kept and shown after the VPN is off.
    public var receivedAt: Date?

    public init(routes: [String] = [], dns: [String] = [], domains: [String] = [], receivedAt: Date? = nil) {
        self.routes = routes
        self.dns = dns
        self.domains = domains
        self.receivedAt = receivedAt
    }
}

public struct TunnelStatus: Codable, Equatable, Sendable {
    public var phase: TunnelPhase
    public var interfaceName: String?
    public var message: String?
    public var changedAt: Date
    /// An address behind the tunnel for the app to ping, filled in by the daemon:
    /// the corporate DNS, for OpenVPN only.
    public var probeAddress: String?

    public init(
        phase: TunnelPhase = .disconnected,
        interfaceName: String? = nil,
        message: String? = nil,
        changedAt: Date = Date()
    ) {
        self.phase = phase
        self.interfaceName = interfaceName
        self.message = message
        self.changedAt = changedAt
    }
}

/// A saved VPN as the app lists it on «VPN». Secrets stay in the daemon: the
/// password is only ever reported as there or not.
public struct ConnectionSummary: Codable, Equatable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case openVPN, amneziaWG, xray

        public var title: String {
            switch self {
            case .openVPN: "OpenVPN"
            case .amneziaWG: "AmneziaWG"
            case .xray: "Xray"
            }
        }
    }

    public var id: UUID
    public var kind: Kind
    public var title: String
    /// A non-secret second line: the server it dials.
    public var detail: String?
    /// A single, known protocol. Subscriptions with potentially mixed servers
    /// deliberately leave this empty.
    public var protocolTitle: String?
    /// OpenVPN: only a profile with `auth-user-pass` is ever asked for a login.
    public var needsLogin: Bool
    public var username: String?
    public var hasPassword: Bool
    /// OpenVPN: every server the profile names, and the one tried first.
    public var remotes: [OpenVPNRemote]?
    public var preferredRemote: OpenVPNRemote?
    /// OpenVPN: what its server last sent, and the `route` lines of the profile.
    public var pushed: PushedOptions?
    public var profileRoutes: [String]?
    public var xray: XraySummary?

    public init(
        id: UUID, kind: Kind, title: String, detail: String? = nil, protocolTitle: String? = nil,
        needsLogin: Bool = false, username: String? = nil, hasPassword: Bool = false,
        remotes: [OpenVPNRemote]? = nil, preferredRemote: OpenVPNRemote? = nil,
        pushed: PushedOptions? = nil, profileRoutes: [String]? = nil, xray: XraySummary? = nil
    ) {
        self.pushed = pushed
        self.profileRoutes = profileRoutes
        self.id = id
        self.kind = kind
        self.title = title
        self.detail = detail
        self.protocolTitle = protocolTitle
        self.needsLogin = needsLogin
        self.username = username
        self.hasPassword = hasPassword
        self.remotes = remotes
        self.preferredRemote = preferredRemote
        self.xray = xray
    }
}

public struct RouterStatus: Codable, Equatable, Sendable {
    public var protection: ProtectionState
    /// The tunnel of each route that is on and has a VPN, by route id.
    public var tunnels: [UUID: TunnelStatus]
    public var desiredEnabled: Bool
    public var lastError: RouterErrorInfo?
    public var connections: [ConnectionSummary]

    public init(
        protection: ProtectionState = .off,
        tunnels: [UUID: TunnelStatus] = [:],
        desiredEnabled: Bool = false,
        lastError: RouterErrorInfo? = nil,
        connections: [ConnectionSummary] = []
    ) {
        self.protection = protection
        self.tunnels = tunnels
        self.desiredEnabled = desiredEnabled
        self.lastError = lastError
        self.connections = connections
    }
}

/// Only for reading settings saved before routes: which list a rule was in.
public enum RuleTarget: String, Codable, CaseIterable, Sendable {
    case corporate, direct
}

public enum RuleKind: String, Codable, CaseIterable, Sendable {
    case domain, ip, cidr
}

public struct RoutingRule: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    /// Set only in settings from before routes; a route's own rules have none.
    public var target: RuleTarget?
    public var kind: RuleKind
    public var value: String
    public var enabled: Bool

    public init(
        id: UUID = UUID(),
        target: RuleTarget? = nil,
        kind: RuleKind,
        value: String,
        enabled: Bool = true
    ) {
        self.id = id
        self.target = target
        self.kind = kind
        self.value = value
        self.enabled = enabled
    }
}

/// A subscription server, by what survives a refresh: its index does not.
public struct ServerChoice: Codable, Hashable, Sendable {
    public var name: String
    public var host: String
    /// Optional so a pick saved before they were kept still decodes; one
    /// without them matches the first server of that name and host.
    public var port: Int?
    public var protocolName: String?

    public init(name: String, host: String, port: Int? = nil, protocolName: String? = nil) {
        self.name = name
        self.host = host
        self.port = port
        self.protocolName = protocolName
    }

    public init(_ server: XraySummary.Server) {
        self.init(name: server.name, host: server.host ?? "", port: server.port, protocolName: server.protocolName)
    }

    /// One rule for the app and the daemon: a subscription may list servers
    /// that differ only by port or protocol.
    public func matches(name: String, host: String?, port: Int?, protocolName: String) -> Bool {
        name == self.name && (host ?? "") == self.host
            && (self.port == nil || port == self.port)
            && (self.protocolName == nil || protocolName == self.protocolName)
    }
}

/// A named list of sites and the VPN they go through. Routes are ordered: when
/// two claim the same site, the one higher on the list wins.
public struct Direction: Codable, Hashable, Identifiable, Sendable {
    public enum Path: Codable, Hashable, Sendable {
        /// No VPN: straight out through the network.
        case direct
        case vpn(UUID)
        /// Imported, or left by a deleted VPN. Never runs as "direct": that
        /// would send work sites out to the internet.
        case unset
    }

    public var id: UUID
    public var name: String
    public var path: Path
    /// A subscription's server; nil runs the one the subscription starts with.
    public var server: ServerChoice?
    public var rules: [RoutingRule]
    public var enabled: Bool
    /// The kill switch: while its VPN is down, blocked, or straight out until
    /// it is back.
    public var blockWhenDown: Bool

    public init(
        id: UUID = UUID(), name: String, path: Path, server: ServerChoice? = nil, rules: [RoutingRule] = [],
        enabled: Bool = true, blockWhenDown: Bool = true
    ) {
        self.id = id
        self.name = name
        self.path = path
        self.server = server
        self.rules = rules
        self.enabled = enabled
        self.blockWhenDown = blockWhenDown
    }

    public var connection: UUID? {
        if case .vpn(let id) = path { return id }
        return nil
    }
}

/// Fixed ids for what settings from before routes become, so the app and the
/// daemon, migrating each its own copy, arrive at the same routes.
public enum LegacyIDs {
    public static let openVPN = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000001")!
    public static let amneziaWG = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000002")!
    public static let xray = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000003")!
    public static let work = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000011")!
    public static let direct = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000012")!
    public static let personal = UUID(uuidString: "C0DE0000-0000-4000-8000-000000000013")!
}

public struct RouterSettings: Codable, Equatable, Sendable {
    public var directions: [Direction]
    /// Takes what no rule claims. nil, or a route that is off, sends it
    /// straight out.
    public var defaultDirection: UUID?
    public var launchAtLogin: Bool
    /// The «Трафик» tab records only when asked: nettop costs CPU for as long
    /// as it runs, and most days no one looks.
    public var watchTraffic: Bool
    /// What every subscription is fetched with; nil is ours.
    public var subscriptionUserAgent: String?

    /// A fresh install: the same three routes settings from 1.0.7 become, so a
    /// newcomer starts where most end up. Work and personal wait, off, for a
    /// VPN: a route that is on yet cannot run would block «Включить». The
    /// personal one takes the rest; .ru and friends go direct.
    public init(
        directions: [Direction] = [
            .init(id: LegacyIDs.work, name: "Работа", path: .unset, enabled: false),
            .init(id: LegacyIDs.personal, name: "Личный", path: .unset, enabled: false),
            .init(id: LegacyIDs.direct, name: "Напрямую", path: .direct, rules: RouterSettings.zoneRules(ru: true, su: true, rf: true)),
        ],
        defaultDirection: UUID? = LegacyIDs.personal,
        launchAtLogin: Bool = false,
        watchTraffic: Bool = false,
        subscriptionUserAgent: String? = nil
    ) {
        self.directions = directions
        self.defaultDirection = defaultDirection
        self.launchAtLogin = launchAtLogin
        self.watchTraffic = watchTraffic
        self.subscriptionUserAgent = subscriptionUserAgent
    }

    /// Routes whose VPN the daemon does not have wait, off, for another. Settings
    /// from 1.0.7 point work and personal at fixed ids whether or not that profile
    /// was ever saved: only the daemon knows, so this is how they carry over as they
    /// were — one VPN stays one, two stay two — instead of blocking «Включить».
    public func droppingMissing(live: Set<UUID>) -> RouterSettings {
        var result = self
        for index in result.directions.indices {
            guard let id = result.directions[index].connection, !live.contains(id) else { continue }
            result.directions[index].path = .unset
            result.directions[index].enabled = false
            result.directions[index].server = nil
        }
        return result
    }

    private enum CodingKeys: String, CodingKey {
        case directions, defaultDirection, launchAtLogin, watchTraffic, subscriptionUserAgent
        // Before routes; read once, never written.
        case rules, directRU, directSU, directRF, useOpenVPN, useAmneziaWG, killSwitch, exitEngine
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        launchAtLogin = try values.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? false
        watchTraffic = try values.decodeIfPresent(Bool.self, forKey: .watchTraffic) ?? false
        subscriptionUserAgent = try values.decodeIfPresent(String.self, forKey: .subscriptionUserAgent)
        if let directions = try values.decodeIfPresent([Direction].self, forKey: .directions) {
            self.directions = directions
            defaultDirection = try values.decodeIfPresent(UUID.self, forKey: .defaultDirection)
            return
        }
        // The work list, the direct list and whatever carried the rest become
        // three routes, in the order that keeps the old precedence: work first.
        let rules = try values.decodeIfPresent([RoutingRule].self, forKey: .rules) ?? []
        func list(_ target: RuleTarget) -> [RoutingRule] {
            rules.filter { $0.target == target }.map { var rule = $0; rule.target = nil; return rule }
        }
        let exit = try values.decodeIfPresent(ExitEngine.self, forKey: .exitEngine) ?? .amneziaWG
        directions = [
            .init(
                id: LegacyIDs.work, name: "Работа", path: .vpn(LegacyIDs.openVPN), rules: list(.corporate),
                enabled: try values.decodeIfPresent(Bool.self, forKey: .useOpenVPN) ?? true
            ),
            .init(
                id: LegacyIDs.direct, name: "Напрямую", path: .direct,
                rules: Self.zoneRules(
                    ru: try values.decodeIfPresent(Bool.self, forKey: .directRU) ?? true,
                    su: try values.decodeIfPresent(Bool.self, forKey: .directSU) ?? true,
                    rf: try values.decodeIfPresent(Bool.self, forKey: .directRF) ?? true
                ) + list(.direct)
            ),
            .init(
                id: LegacyIDs.personal, name: "Личный", path: .vpn(exit == .xray ? LegacyIDs.xray : LegacyIDs.amneziaWG),
                enabled: try values.decodeIfPresent(Bool.self, forKey: .useAmneziaWG) ?? true,
                blockWhenDown: try values.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? true
            ),
        ]
        defaultDirection = LegacyIDs.personal
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(directions, forKey: .directions)
        try values.encodeIfPresent(defaultDirection, forKey: .defaultDirection)
        try values.encode(launchAtLogin, forKey: .launchAtLogin)
        try values.encode(watchTraffic, forKey: .watchTraffic)
        try values.encodeIfPresent(subscriptionUserAgent, forKey: .subscriptionUserAgent)
    }

    /// The zone boxes of old, as the lines they now are.
    public static func zoneRules(ru: Bool, su: Bool, rf: Bool) -> [RoutingRule] {
        [(ru, ".ru"), (su, ".su"), (rf, ".рф")].filter(\.0).map { .init(kind: .domain, value: $0.1) }
    }

    /// The routes that are on, in their order.
    public var activeDirections: [Direction] { directions.filter(\.enabled) }

    /// What carries the rest, if a route that is on does.
    public var activeDefault: Direction? {
        directions.first { $0.id == defaultDirection && $0.enabled }
    }
}

public struct ProfilePayload: Codable, Sendable {
    public var kind: VPNKind
    public var configuration: String
    public var username: String?
    public var password: String?
    public var unsafeAuthorization: Data?
    /// Which saved VPN this is. One the daemon does not have yet is added under
    /// it: the app picks the id, so it knows it without asking.
    public var connection: UUID?

    public init(
        kind: VPNKind,
        configuration: String,
        username: String? = nil,
        password: String? = nil,
        unsafeAuthorization: Data? = nil,
        connection: UUID? = nil
    ) {
        self.kind = kind
        self.configuration = configuration
        self.username = username
        self.password = password
        self.unsafeAuthorization = unsafeAuthorization
        self.connection = connection
    }
}

/// A nil password means "keep the stored one": the app cannot show it, so an
/// empty field must never wipe it.
public struct CredentialsUpdate: Codable, Sendable {
    public var connection: UUID
    public var username: String?
    public var password: String?

    public init(connection: UUID, username: String?, password: String?) {
        self.connection = connection
        self.username = username
        self.password = password
    }
}

/// The OpenVPN server to try first; the rest follow in the profile's order.
public struct RemotePreference: Codable, Sendable {
    public var connection: UUID
    public var remote: OpenVPNRemote

    public init(connection: UUID, remote: OpenVPNRemote) {
        self.connection = connection
        self.remote = remote
    }
}

public enum RouterErrorCode: String, Codable, Sendable {
    case invalidConfiguration
    case authenticationRequired
    case unsafeProfileNeedsApproval
    case helperUnavailable
    case permissionDenied
    case conflictingVPN
    case dnsFailure
    case routingFailure
    case firewallFailure
    case tunnelFailure
    case missingTool
    case internalError
}

public struct RouterErrorInfo: Error, LocalizedError, Codable, Equatable, Sendable {
    public var code: RouterErrorCode
    public var message: String
    public var recoverable: Bool

    public init(_ code: RouterErrorCode, _ message: String, recoverable: Bool = false) {
        self.code = code
        self.message = message
        self.recoverable = recoverable
    }

    public var errorDescription: String? { message }
}

public enum VPNRouterVersion {
    public static let current = "1.1.1"

    /// Numeric per component: "1.0.10" is newer than "1.0.9". A leading "v"
    /// is the release tag's, not the version's.
    public static func isNewer(_ candidate: String, than installed: String) -> Bool {
        func trimmed(_ version: String) -> String { version.hasPrefix("v") ? String(version.dropFirst()) : version }
        return trimmed(candidate).compare(trimmed(installed), options: .numeric) == .orderedDescending
    }
}

/// A release newer than the running copy, as GitHub's `releases/latest` names it.
public struct AppRelease: Codable, Sendable, Equatable {
    public var version: String
    public var notes: String
    public var packageURL: URL

    public init(version: String, notes: String, packageURL: URL) {
        self.version = version
        self.notes = notes
        self.packageURL = packageURL
    }

    public static let latestURL = URL(string: "https://api.github.com/repos/and-sheera/commutator/releases/latest")!

    /// Nil when the release is not newer or carries no package: a release
    /// published without its pkg has nothing to install yet.
    public static func parse(_ data: Data, installed: String) -> AppRelease? {
        struct Asset: Decodable { let name: String; let browser_download_url: URL }
        struct Latest: Decodable { let tag_name: String; let body: String?; let assets: [Asset] }
        guard let latest = try? JSONDecoder().decode(Latest.self, from: data),
              VPNRouterVersion.isNewer(latest.tag_name, than: installed),
              let package = latest.assets.first(where: { $0.name == "Commutator.pkg" })
        else { return nil }
        let version = latest.tag_name.hasPrefix("v") ? String(latest.tag_name.dropFirst()) : latest.tag_name
        return AppRelease(version: version, notes: latest.body ?? "", packageURL: package.browser_download_url)
    }
}

public struct Diagnostics: Codable, Sendable {
    public var appVersion: String
    public var daemonVersion: String
    public var status: RouterStatus
    public var physicalInterface: String?

    public init(
        appVersion: String = VPNRouterVersion.current,
        daemonVersion: String = VPNRouterVersion.current,
        status: RouterStatus,
        physicalInterface: String? = nil
    ) {
        self.appVersion = appVersion
        self.daemonVersion = daemonVersion
        self.status = status
        self.physicalInterface = physicalInterface
    }
}

/// The log lines after the app's cursor, and the cursor to ask with next.
public struct LogChunk: Codable, Sendable {
    public var lines: [String]
    public var next: Int

    public init(lines: [String], next: Int) {
        self.lines = lines
        self.next = next
    }
}

public enum IPCOperation: String, Codable, Sendable {
    case getStatus, replaceProfile, updateCredentials, updateRules, setEnabled, getDiagnostics, getLog, lookupNames, updateXray
    case getProfile
    /// Payload: the id of the saved VPN to forget.
    case deleteConnection
    /// Payload: a `RemotePreference`.
    case preferRemote
    /// Payload: the path of a downloaded Commutator.pkg.
    case installUpdate
    /// Payload: the app bundle's path, removed along with everything else.
    case uninstall
}

/// Asks for a stored profile's text, to edit it in the app. The authorization
/// is needed only where the daemon takes requests from unsigned clients.
public struct ProfileRequest: Codable, Sendable {
    public var connection: UUID
    public var authorization: Data?

    public init(connection: UUID, authorization: Data? = nil) {
        self.connection = connection
        self.authorization = authorization
    }
}

public struct IPCRequest: Codable, Sendable {
    public var operation: IPCOperation
    public var payload: Data?

    public init(_ operation: IPCOperation, payload: Data? = nil) {
        self.operation = operation
        self.payload = payload
    }
}

public struct IPCResponse: Codable, Sendable {
    public var payload: Data?
    public var error: RouterErrorInfo?

    public init(payload: Data? = nil, error: RouterErrorInfo? = nil) {
        self.payload = payload
        self.error = error
    }
}

@objc public protocol VPNRouterDaemonXPC {
    func request(_ data: Data, withReply reply: @escaping (Data) -> Void)
}

public enum IPCCodec {
    public static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
