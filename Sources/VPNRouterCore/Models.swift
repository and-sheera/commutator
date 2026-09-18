import Foundation

public enum VPNKind: String, Codable, CaseIterable, Sendable {
    case openVPN
    case amneziaWG

    public var title: String { self == .openVPN ? "OpenVPN" : "AmneziaWG" }
}

/// What carries the traffic no rule claims. Both fill the same slot: the
/// `.amneziaWG` kind, class and status stand for that slot, whichever it is.
public enum ExitEngine: String, Codable, CaseIterable, Sendable {
    case amneziaWG, xray

    public var title: String { self == .amneziaWG ? "AmneziaWG" : "Xray" }

    /// The engine a pasted profile is for, so nobody has to pick a type before
    /// adding one: Amnezia's vpn:// link and a WireGuard-style config are
    /// AmneziaWG, anything else is a share link or a subscription address.
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

    /// A tunnel passed as nil is not in use and counts neither way.
    public static func evaluate(desiredEnabled: Bool, openVPN: TunnelStatus?, amneziaWG: TunnelStatus?) -> Self {
        let used = [openVPN, amneziaWG].compactMap { $0 }
        guard desiredEnabled, !used.isEmpty else { return .off }
        if used.allSatisfy({ $0.phase == .connected && $0.interfaceName != nil }) { return .protected }
        // One tunnel up while the other is still on its first attempt is a
        // normal start: calling it «Работает частично» read as a failure.
        let phases = used.map(\.phase)
        if phases.contains(.connecting), phases.allSatisfy({ $0 == .connecting || $0 == .connected }) { return .starting }
        return .degraded
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

/// What the daemon holds, reported so the app never reads it back out of
/// Keychain. The password itself never crosses XPC in this direction.
public struct ProfileSummary: Codable, Equatable, Sendable {
    public var hasOpenVPN: Bool
    public var hasAmneziaWG: Bool
    /// Only a profile with `auth-user-pass` is ever asked for a login.
    public var openVPNNeedsLogin: Bool
    public var openVPNUsername: String?
    public var openVPNHasPassword: Bool
    public var xray: XraySummary?
    /// Which server each profile dials, so «Сохранён» says which one. Optional:
    /// a daemon from before they were sent reports neither.
    public var openVPNServer: String?
    public var amneziaWGServer: String?
    /// Every server the work profile names, to pick the one tried first.
    public var openVPNRemotes: [OpenVPNRemote]?
    /// Every saved personal profile, the ones in use and the spares.
    public var exits: [ExitItem]?

    public init(
        hasOpenVPN: Bool = false,
        hasAmneziaWG: Bool = false,
        openVPNNeedsLogin: Bool = false,
        openVPNUsername: String? = nil,
        openVPNHasPassword: Bool = false,
        xray: XraySummary? = nil,
        openVPNServer: String? = nil,
        amneziaWGServer: String? = nil,
        openVPNRemotes: [OpenVPNRemote]? = nil,
        exits: [ExitItem]? = nil
    ) {
        self.openVPNRemotes = openVPNRemotes
        self.exits = exits
        self.hasOpenVPN = hasOpenVPN
        self.hasAmneziaWG = hasAmneziaWG
        self.openVPNNeedsLogin = openVPNNeedsLogin
        self.openVPNUsername = openVPNUsername
        self.openVPNHasPassword = openVPNHasPassword
        self.xray = xray
        self.openVPNServer = openVPNServer
        self.amneziaWGServer = amneziaWGServer
    }
}

/// A saved personal profile. The daemon runs one per engine; the rest are
/// spares, kept whole until chosen. `spare` nil is the engine's current one.
public struct ExitItem: Codable, Hashable, Identifiable, Sendable {
    public var engine: ExitEngine
    public var spare: UUID?
    public var title: String

    public var id: String { spare?.uuidString ?? engine.rawValue }

    public init(engine: ExitEngine, spare: UUID? = nil, title: String) {
        self.engine = engine
        self.spare = spare
        self.title = title
    }
}

public struct RouterStatus: Codable, Equatable, Sendable {
    public var protection: ProtectionState
    public var openVPN: TunnelStatus
    public var amneziaWG: TunnelStatus
    public var desiredEnabled: Bool
    public var lastError: RouterErrorInfo?
    public var profiles: ProfileSummary

    public init(
        protection: ProtectionState = .off,
        openVPN: TunnelStatus = .init(),
        amneziaWG: TunnelStatus = .init(),
        desiredEnabled: Bool = false,
        lastError: RouterErrorInfo? = nil,
        profiles: ProfileSummary = .init()
    ) {
        self.protection = protection
        self.openVPN = openVPN
        self.amneziaWG = amneziaWG
        self.desiredEnabled = desiredEnabled
        self.lastError = lastError
        self.profiles = profiles
    }
}

public enum RuleTarget: String, Codable, CaseIterable, Sendable {
    case corporate, direct
}

public enum RuleKind: String, Codable, CaseIterable, Sendable {
    case domain, ip, cidr
}

public struct RoutingRule: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var target: RuleTarget
    public var kind: RuleKind
    public var value: String
    public var enabled: Bool

    public init(
        id: UUID = UUID(),
        target: RuleTarget,
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

public struct RouterSettings: Codable, Equatable, Sendable {
    public var rules: [RoutingRule]
    public var directRU: Bool
    public var directSU: Bool
    public var directRF: Bool
    public var corporateDNSFallbackToCurrent: Bool
    public var launchAtLogin: Bool
    /// Either VPN can sit out. Without OpenVPN the corporate rules do not apply;
    /// without AmneziaWG whatever no rule claims goes out directly.
    public var useOpenVPN: Bool
    public var useAmneziaWG: Bool
    /// While AmneziaWG is down, what no rule claims is blocked along with its
    /// DNS; switched off, it goes out directly until the tunnel is back.
    public var killSwitch: Bool
    public var exitEngine: ExitEngine
    /// The work server openvpn tries first; nil keeps the profile's order.
    public var preferredOpenVPNRemote: OpenVPNRemote?
    /// The «Трафик» tab records only when asked: nettop costs CPU for as long
    /// as it runs, and most days no one looks.
    public var watchTraffic: Bool

    public init(
        rules: [RoutingRule] = [],
        directRU: Bool = true,
        directSU: Bool = true,
        directRF: Bool = true,
        corporateDNSFallbackToCurrent: Bool = true,
        launchAtLogin: Bool = false,
        useOpenVPN: Bool = true,
        useAmneziaWG: Bool = true,
        killSwitch: Bool = true,
        exitEngine: ExitEngine = .amneziaWG,
        preferredOpenVPNRemote: OpenVPNRemote? = nil,
        watchTraffic: Bool = false
    ) {
        self.preferredOpenVPNRemote = preferredOpenVPNRemote
        self.watchTraffic = watchTraffic
        self.killSwitch = killSwitch
        self.exitEngine = exitEngine
        self.rules = rules
        self.directRU = directRU
        self.directSU = directSU
        self.directRF = directRF
        self.corporateDNSFallbackToCurrent = corporateDNSFallbackToCurrent
        self.launchAtLogin = launchAtLogin
        self.useOpenVPN = useOpenVPN
        self.useAmneziaWG = useAmneziaWG
    }

    private enum CodingKeys: String, CodingKey {
        case rules, directRU, directSU, directRF, corporateDNSFallbackToCurrent, launchAtLogin, useOpenVPN, useAmneziaWG, killSwitch, exitEngine
        case preferredOpenVPNRemote, watchTraffic
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        rules = try values.decodeIfPresent([RoutingRule].self, forKey: .rules) ?? []
        directRU = try values.decodeIfPresent(Bool.self, forKey: .directRU) ?? true
        directSU = try values.decodeIfPresent(Bool.self, forKey: .directSU) ?? true
        directRF = try values.decodeIfPresent(Bool.self, forKey: .directRF) ?? true
        corporateDNSFallbackToCurrent = try values.decodeIfPresent(Bool.self, forKey: .corporateDNSFallbackToCurrent) ?? true
        launchAtLogin = try values.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? false
        useOpenVPN = try values.decodeIfPresent(Bool.self, forKey: .useOpenVPN) ?? true
        useAmneziaWG = try values.decodeIfPresent(Bool.self, forKey: .useAmneziaWG) ?? true
        killSwitch = try values.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? true
        exitEngine = try values.decodeIfPresent(ExitEngine.self, forKey: .exitEngine) ?? .amneziaWG
        preferredOpenVPNRemote = try values.decodeIfPresent(OpenVPNRemote.self, forKey: .preferredOpenVPNRemote)
        watchTraffic = try values.decodeIfPresent(Bool.self, forKey: .watchTraffic) ?? false
    }

    /// What no rule claims leaves on the physical interface: always without
    /// AmneziaWG, and while it is down if the kill switch is off.
    public func directByDefault(amneziaWGUp: Bool) -> Bool {
        !useAmneziaWG || (!killSwitch && !amneziaWGUp)
    }

    public var effectiveRules: [RoutingRule] {
        var result = rules
        if directRU { result.append(.init(target: .direct, kind: .domain, value: "ru")) }
        if directSU { result.append(.init(target: .direct, kind: .domain, value: "su")) }
        if directRF { result.append(.init(target: .direct, kind: .domain, value: "xn--p1ai")) }
        return result
    }
}

public struct ProfilePayload: Codable, Sendable {
    public var kind: VPNKind
    public var configuration: String
    public var username: String?
    public var password: String?
    public var unsafeAuthorization: Data?
    /// A newly added personal profile: the current one is kept as a spare
    /// instead of replaced, as «Изменить…» does. Never stored.
    public var keepPrevious: Bool?

    public init(
        kind: VPNKind,
        configuration: String,
        username: String? = nil,
        password: String? = nil,
        unsafeAuthorization: Data? = nil
    ) {
        self.kind = kind
        self.configuration = configuration
        self.username = username
        self.password = password
        self.unsafeAuthorization = unsafeAuthorization
    }
}

/// A nil password means "keep the stored one": the app cannot show it, so an
/// empty field must never wipe it.
public struct CredentialsUpdate: Codable, Sendable {
    public var username: String?
    public var password: String?

    public init(username: String?, password: String?) {
        self.username = username
        self.password = password
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
    public static let current = "1.0.6"
}

public struct Diagnostics: Codable, Sendable {
    public var appVersion: String
    public var daemonVersion: String
    public var status: RouterStatus
    public var physicalInterface: String?
    public var openVPNInterface: String?
    public var amneziaWGInterface: String?

    public init(
        appVersion: String = VPNRouterVersion.current,
        daemonVersion: String = VPNRouterVersion.current,
        status: RouterStatus,
        physicalInterface: String? = nil,
        openVPNInterface: String? = nil,
        amneziaWGInterface: String? = nil
    ) {
        self.appVersion = appVersion
        self.daemonVersion = daemonVersion
        self.status = status
        self.physicalInterface = physicalInterface
        self.openVPNInterface = openVPNInterface
        self.amneziaWGInterface = amneziaWGInterface
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
    /// Payload: the `ExitItem` to run, or to forget.
    case selectExit, deleteExit
}

/// Asks for a stored profile's text, to edit it in the app. The authorization
/// is needed only where the daemon takes requests from unsigned clients.
public struct ProfileRequest: Codable, Sendable {
    public var kind: VPNKind
    public var authorization: Data?

    public init(kind: VPNKind, authorization: Data? = nil) {
        self.kind = kind
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
