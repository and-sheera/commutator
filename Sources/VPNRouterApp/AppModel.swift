import AppKit
import Foundation
import Security
import ServiceManagement
import UserNotifications
import VPNRouterCore

struct PendingUnsafeProfile: Identifiable {
    let id = UUID()
    let configuration: String
    let directives: [String]
    let connection: UUID
}

@MainActor
final class AppModel: ObservableObject {
    @Published var status = RouterStatus() {
        didSet { statusLoaded = true }
    }
    /// The daemon has answered at least once. Until then the VPN list is just
    /// empty, not known to be: every route read «VPN удалён» and the window
    /// asked to add a VPN that was there all along.
    @Published private(set) var statusLoaded = false
    @Published var settings: RouterSettings
    /// «Маршруты» as edited; only «Применить» turns it into settings.
    @Published var routing: RoutingDraft
    /// The list of the route that takes the rest: not applied (that route has
    /// no rules), but kept, so marking another route for the rest brings it back.
    private var parked: [UUID: String]
    /// The route whose «Добавить новый VPN…» opened the add sheet; nil lets
    /// the new VPN find a route waiting for one.
    var adoptSlot: UUID?
    /// Only ever what the user is typing, by OpenVPN connection: the stored
    /// password stays in the daemon.
    @Published var usernames: [UUID: String] = [:]
    @Published var passwords: [UUID: String] = [:]
    var connections: [ConnectionSummary] { status.connections }

    func connection(_ id: UUID?) -> ConnectionSummary? { id.flatMap { id in connections.first { $0.id == id } } }

    /// The window's page, here so the menu and other pages can send you to one.
    /// Remembered, so the window reopens where it was left.
    /// Leaving «Маршруты» with edits asks first: the sidebar, the menu and every
    /// «go there» link all land here. Setting it back inside didSet calls no observers.
    @Published var page: Page? = UserDefaults.standard.string(forKey: "page").flatMap(Page.init(rawValue:)) ?? .overview {
        didSet {
            if oldValue == .rules, page != .rules, !settleRuleEdits() {
                page = oldValue
                return
            }
            UserDefaults.standard.set(page?.rawValue, forKey: "page")
        }
    }
    /// The route open in the editor on «Маршруты».
    @Published var selectedDirection: UUID?
    /// Kept in the model so the native «Маршруты» menu can open the same help
    /// that is available from the page toolbar.
    @Published var showsRuleFormat = false
    /// The sheet that takes a VPN profile, here so «Обзор» can open it.
    @Published var addingConnection = false
    /// The target of an on/off request still in flight. The daemon answers only
    /// once the tunnels are launched, and until then the switch snapped back
    /// and looked as if the click did nothing.
    @Published private(set) var pendingEnabled: Bool?
    var displayedEnabled: Bool { pendingEnabled ?? status.desiredEnabled }
    /// A new failure of the user's own action shows even when it reads like one
    /// they hid before: remembered by text alone, the second try said nothing.
    @Published var errorMessage: String? {
        didSet { if errorMessage != nil { dismissedError = nil } }
    }
    @Published var systemComponentMessage: String?
    @Published var pendingUnsafe: PendingUnsafeProfile?
    @Published private(set) var diagnosticsInfo: Diagnostics?
    /// Ping by server endpoint, so a refreshed list keeps what was measured.
    @Published private(set) var pings: [String: PingState] = [:]
    /// The subscription whose servers are being pinged.
    @Published private(set) var pingingServers: UUID?
    /// Hosts pinged right now, so their rows can say so.
    @Published private(set) var pinging: Set<String> = []
    @Published private(set) var pingedServerCount = 0
    @Published private(set) var pingableServerCount = 0
    /// The connection an operation runs for, so only its controls wait.
    @Published private(set) var busyConnection: UUID?
    /// An operation's failure, next to the connection it was for.
    @Published private(set) var connectionErrors: [UUID: String] = [:]
    @Published private var dismissedError: String?
    @Published private(set) var logLines: [String] = []
    private var logCursor = 0
    @Published private(set) var report: ConnectionReport?
    @Published private(set) var checking = false
    private var checkAgain = false
    @Published private(set) var routeCheck: RouteCheck?
    @Published private(set) var checkingRoute = false

    /// Each step is the user's own click: found, then downloaded, then installed.
    enum UpdateState: Equatable {
        case available(AppRelease), downloading(AppRelease), ready(AppRelease), installing(AppRelease)
        var release: AppRelease {
            switch self { case .available(let r), .downloading(let r), .ready(let r), .installing(let r): r }
        }
    }
    @Published private(set) var update: UpdateState?
    @Published private(set) var checkingUpdate = false
    @Published private(set) var updateCheckResult: String?

    /// The daemon keeps reporting `lastError` until its next successful operation,
    /// so dismissal is remembered by message: hiding one does not hide the next.
    var visibleError: String? {
        let current = currentError
        // A connection's failure shows next to it. The daemon records the same
        // text in its status; repeating it in an alert gives one failure two messages.
        return current == dismissedError || connectionErrors.values.contains { $0 == current } ? nil : current
    }

    /// What the user did that failed, or routing as a whole that did. A tunnel's
    /// own failure is in its route's row, and the daemon re-reports it on every
    /// retry: as an alert it would pop up again and again.
    private var currentError: String? {
        errorMessage ?? (status.protection == .error ? status.lastError?.message : nil)
    }

    func dismissError() { dismissedError = currentError }

    private let client = XPCClient()
    private(set) lazy var traffic = TrafficMonitor { [client] addresses in
        (try? await client.request(.lookupNames, payload: addresses, as: [String: String].self)) ?? [:]
    }
    private var pollTask: Task<Void, Never>?
    private var previousStatus: RouterStatus?
    private var syncedToDaemon = false
    private let settingsKey = "router-settings"
    private var unsafeImportContinuation: CheckedContinuation<String?, Never>?
    private var settingsPushPending = false
    private var settingsPushRunning = false

    init() {
        // VPNROUTER_DEMO=1: made-up data for README screenshots. The daemon is
        // never contacted, so nothing real is shown or changed.
        if XPCClient.isDemo {
            settings = RouterSettings()
            routing = RoutingDraft(settings: RouterSettings())
            parked = [:]
            fillDemo()
            return
        }
        let defaults = UserDefaults.standard
        // Left by development builds that had a simple and an advanced mode.
        defaults.removeObject(forKey: "simple-mode")
        defaults.removeObject(forKey: "router-settings-other")
        let stored = Self.loadSettings()
        let kept = defaults.data(forKey: Self.parkedKey).flatMap { try? IPCCodec.decoder.decode([UUID: String].self, from: $0) } ?? [:]
        settings = stored
        parked = kept
        routing = RoutingDraft(settings: stored, parked: kept)
        Task { await bootstrap() }
    }

    private static let parkedKey = "simple-parked"

    /// The draft the applied settings read back as, the rest's list from what was kept aside.
    private func freshDraft() -> RoutingDraft { RoutingDraft(settings: settings, parked: parked) }

    private func fillDemo() {
        let since = Calendar.current.date(bySettingHour: 9, minute: 12, second: 0, of: Date()) ?? Date()
        let work = UUID(), subscription = UUID()
        settings = RouterSettings(directions: [
            .init(id: LegacyIDs.work, name: "Работа", path: .vpn(work), rules: [.init(kind: .domain, value: "corp.example.com"), .init(kind: .cidr, value: "10.0.0.0/8")]),
            .init(id: LegacyIDs.direct, name: "Напрямую", path: .direct, rules: RouterSettings.zoneRules(ru: true, su: true, rf: true)),
            .init(id: LegacyIDs.personal, name: "Личный", path: .vpn(subscription), server: .init(name: "Германия", host: "de.example", port: 443, protocolName: "vless")),
        ], defaultDirection: LegacyIDs.personal)
        routing = freshDraft()
        var workStatus = TunnelStatus(phase: .connected, interfaceName: "utun4", changedAt: since)
        workStatus.probeAddress = "10.0.0.53"
        status = RouterStatus(
            protection: .protected,
            tunnels: [
                LegacyIDs.work: workStatus,
                LegacyIDs.personal: .init(phase: .connected, interfaceName: "utun5", changedAt: since),
            ],
            desiredEnabled: true,
            connections: [
                .init(id: work, kind: .openVPN, title: "vpn.company.example", protocolTitle: "OpenVPN"),
                .init(id: subscription, kind: .xray, title: "Подписка «Пример»", xray: .init(
                    servers: [.init(name: "США", protocolName: "vless", host: "us.example", port: 443), .init(name: "Германия", protocolName: "vless", host: "de.example", port: 443)],
                    selected: 0, title: "Пример", fromSubscription: true, updatedAt: since, usedBytes: nil, totalBytes: nil, expiresAt: nil
                )),
            ]
        )
        report = ConnectionReport(
            cloudflare: .init(ip: "203.0.113.24", country: "NL", city: "Amsterdam", org: "AS64500 Example Hosting", interface: "utun5", milliseconds: 48),
            yandex: .init(ip: "198.51.100.17", country: "RU", city: "Москва", org: "AS64501 Домашний провайдер", interface: "en0", milliseconds: 12)
        )
    }

    deinit { pollTask?.cancel() }

    // MARK: - Routes and their state

    /// Routes that are on but could not run: no VPN picked, or its profile gone.
    var brokenDirections: [Direction] { settings.activeDirections.filter(isBroken) }

    func tunnel(of direction: Direction) -> TunnelStatus? { status.tunnels[direction.id] }

    /// «Нейросети» for the rest, when the rest is no route's.
    var defaultName: String? { settings.activeDefault?.name }

    /// What a route runs, as its row names it: the VPN and, for a
    /// subscription, the server.
    func vpnTitle(_ direction: Direction) -> String {
        switch direction.path {
        case .direct: return "Без VPN"
        case .unset: return "VPN не выбран"
        case .vpn(let id):
            guard let connection = connection(id) else { return statusLoaded ? "VPN удалён" : "…" }
            guard let xray = connection.xray, xray.fromSubscription, xray.servers.count > 1 else { return connection.title }
            return "\(connection.title) · \(serverName(direction, xray) ?? "—")"
        }
    }

    /// The subscription server a route runs: its pick while the list has it,
    /// else the one the subscription starts at.
    func serverName(_ direction: Direction, _ xray: XraySummary) -> String? {
        let index = serverIndex(direction, xray)
        return xray.servers.indices.contains(index) ? xray.servers[index].name : nil
    }

    func serverIndex(_ direction: Direction, _ xray: XraySummary) -> Int {
        direction.server.flatMap { choice in xray.servers.firstIndex { choice.matches(name: $0.name, host: $0.host, port: $0.port, protocolName: $0.protocolName) } } ?? xray.selected
    }

    func setRouting(_ enabled: Bool) {
        // The daemon in place during an install is about to be replaced.
        guard !installingUpdate, pendingEnabled == nil, enabled != status.desiredEnabled else { return }
        if enabled, let broken = brokenDirections.first {
            errorMessage = "Направлению «\(broken.name)» не выбран VPN: выберите его на странице «Маршруты» или выключите направление"
            return
        }
        pendingEnabled = enabled
        Task {
            defer { pendingEnabled = nil }
            if enabled {
                for id in credentialEdits {
                    if let message = await pushCredentials(id) {
                        errorMessage = message
                        return
                    }
                }
            }
            await setEnabled(enabled)
        }
    }

    /// Quitting takes protection down with it. false: the daemon did not confirm,
    /// and the app stays open rather than leave VPN on behind the user's back.
    func turnOffForQuit() async -> Bool {
        await setEnabled(false)
        return !status.desiredEnabled
    }

    /// A route on or off right away, from «Обзоре» or the menu: the switch is
    /// the decision. Edits still being made on «Маршрутах» stay as they are.
    func setDirection(_ id: UUID, enabled: Bool) {
        guard let index = settings.directions.firstIndex(where: { $0.id == id }) else { return }
        if enabled, isBroken(settings.directions[index]) {
            errorMessage = "Сначала выберите VPN для «\(settings.directions[index].name)» на странице «Маршруты»"
            return
        }
        let hadEdits = rulesChanged
        settings.directions[index].enabled = enabled
        if hadEdits {
            if let draftIndex = routing.directions.firstIndex(where: { $0.id == id }) { routing.directions[draftIndex].enabled = enabled }
        } else {
            routing = freshDraft()
        }
        applySettings()
    }

    // MARK: - Profiles

    /// Shows the system picker without ever reading a profile until the person chose it.
    func chooseProfileFile(_ kind: VPNKind?) -> URL? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = (kind.map { [$0] } ?? VPNKind.allCases).map { .init(filenameExtension: $0 == .openVPN ? "ovpn" : "conf")! }
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    /// Dropped files pick their kind by extension, the way the official clients take them.
    static func kind(of url: URL) -> VPNKind? {
        switch url.pathExtension.lowercased() {
        case "ovpn": .openVPN
        case "conf": .amneziaWG
        default: nil
        }
    }

    /// A new VPN from a file. nil means the daemon stored it.
    func addProfile(at url: URL) async -> String? {
        guard let kind = Self.kind(of: url) else { return "Подходят файлы .ovpn и .conf" }
        do { return await addConfiguration(try String(contentsOf: url, encoding: .utf8), as: kind) }
        catch { return error.localizedDescription }
    }

    /// Whatever was pasted — Amnezia's «Поделиться VPN» link, a share link or a
    /// subscription — goes to the engine it is for.
    func addLink(_ text: String) async -> String? {
        switch ExitEngine(profile: text) {
        case .amneziaWG: return await addConfiguration(text, as: .amneziaWG)
        case .xray:
            let id = UUID()
            if let message = await xrayRequest(.init(connection: id, source: text)) { return message }
            lastAdded = id
            adopt(id, openVPN: false)
            return nil
        }
    }

    private func addConfiguration(_ text: String, as kind: VPNKind) async -> String? {
        let id = UUID()
        if let message = await importConfiguration(text, as: kind, connection: id) { return message }
        lastAdded = id
        adopt(id, openVPN: kind == .openVPN)
        return nil
    }

    /// The VPN the add sheet just stored, so it can ask for its login at once.
    private(set) var lastAdded: UUID?

    /// An OpenVPN profile that asks for a login none was given for yet.
    func needsCredentials(_ id: UUID) -> Bool {
        guard let item = connection(id) else { return false }
        return item.kind == .openVPN && item.needsLogin && !item.hasPassword
    }

    /// The add sheet waits for the answer, unlike the page's «Сохранить».
    func storeCredentials(_ id: UUID) async -> String? { await pushCredentials(id) }

    /// A new VPN goes where one is missing, or it would sit unused until
    /// someone found the route waiting for it. A personal one takes the rest if
    /// that has none; a work one gets a route of its own on top, where the
    /// networks its server sends work without a single rule.
    private func adopt(_ connection: UUID, openVPN: Bool) {
        if let slot = adoptSlot {
            adopt(connection, into: slot)
            return
        }
        let hadEdits = rulesChanged
        let waiting = openVPN
            ? settings.directions.first { $0.path == .unset && $0.id != settings.defaultDirection }
            : settings.directions.first { $0.path == .unset && $0.id == settings.defaultDirection }
                ?? settings.directions.first { $0.path == .unset }
        if let waiting, let index = settings.directions.firstIndex(where: { $0.id == waiting.id }) {
            settings.directions[index].path = .vpn(connection)
            settings.directions[index].enabled = true
            if hadEdits, let draft = routing.directions.firstIndex(where: { $0.id == waiting.id }) { routing.directions[draft].path = .vpn(connection) }
        } else if openVPN, !settings.directions.contains(where: { self.connection($0.connection)?.kind == .openVPN }) {
            let work = Direction(name: "Работа", path: .vpn(connection))
            settings.directions.insert(work, at: 0)
            if hadEdits {
                routing.directions.insert(work, at: 0)
                routing.texts[work.id] = ""
            }
        } else {
            return
        }
        if !hadEdits { routing = freshDraft() }
        applySettings()
    }

    /// On but unable to run: no VPN picked, or its profile gone.
    func isBroken(_ direction: Direction) -> Bool {
        switch direction.path {
        case .direct: false
        case .unset: true
        case .vpn(let id): statusLoaded && connection(id) == nil
        }
    }

    /// AmneziaWG accepts either a `.conf` text or Amnezia's «Поделиться VPN» link.
    private func normalizedAmneziaWG(_ text: String) throws -> String {
        guard text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("vpn://") else { return text }
        return try AmneziaWGProfileParser.nativeConfig(fromVpnLink: text)
    }

    /// A picked file and an edited profile share validation and wait for the daemon.
    private func importConfiguration(_ configuration: String, as kind: VPNKind, connection: UUID) async -> String? {
        do {
            var configuration = configuration
            if kind == .amneziaWG {
                configuration = try normalizedAmneziaWG(configuration)
                _ = try AmneziaWGProfileParser.parse(configuration)
            } else {
                let inspected = try OpenVPNProfileParser.parse(configuration)
                if !inspected.dangerousDirectives.isEmpty {
                    guard unsafeImportContinuation == nil else { return "Другой профиль уже ждёт подтверждения" }
                    pendingUnsafe = .init(configuration: configuration, directives: inspected.dangerousDirectives, connection: connection)
                    return await withCheckedContinuation { unsafeImportContinuation = $0 }
                }
            }
            return await storeAndSend(kind, configuration: configuration, authorization: nil, connection: connection)
        } catch {
            return error.localizedDescription
        }
    }

    func confirmUnsafeImport() {
        guard let pending = pendingUnsafe, let continuation = unsafeImportContinuation else { return }
        unsafeImportContinuation = nil
        do {
            let authorization = try AdminAuthorization.request()
            pendingUnsafe = nil
            Task { continuation.resume(returning: await storeAndSend(.openVPN, configuration: pending.configuration, authorization: authorization, connection: pending.connection)) }
        } catch {
            pendingUnsafe = nil
            continuation.resume(returning: error.localizedDescription)
        }
    }

    func cancelUnsafeImport() {
        pendingUnsafe = nil
        let continuation = unsafeImportContinuation
        unsafeImportContinuation = nil
        continuation?.resume(returning: "Импорт профиля отменён")
    }

    /// The stored profile as text, to edit in place. Where the daemon takes
    /// unsigned clients it asks for an administrator first: keys ride inline.
    func profileText(_ connection: UUID) async -> String? {
        do {
            return try await client.request(.getProfile, payload: ProfileRequest(connection: connection), as: String.self)
        } catch let refused as RouterErrorInfo where refused.code == .permissionDenied {
            do {
                let authorization = try AdminAuthorization.request()
                return try await client.request(.getProfile, payload: ProfileRequest(connection: connection, authorization: authorization), as: String.self)
            } catch { errorMessage = error.localizedDescription }
        } catch { errorMessage = error.localizedDescription }
        return nil
    }

    /// Keeps the editor open until the daemon accepts the replacement.
    func saveProfile(_ text: String, as kind: VPNKind, connection: UUID) async -> String? {
        await importConfiguration(text, as: kind, connection: connection)
    }

    /// Out of every route first, so no route that is on still needs it, then
    /// forgotten. Those routes wait, off, for another VPN to be picked.
    func deleteConnection(_ item: ConnectionSummary) {
        let users = settings.directions.filter { $0.connection == item.id }
        let alert = NSAlert()
        alert.messageText = "Удалить VPN «\(item.title)»?"
        alert.informativeText = (users.isEmpty ? "" : "Через него идут: \(users.map { "«\($0.name)»" }.joined(separator: ", ")). Они выключатся, пока вы не выберете им другой VPN. ")
            + "Вернуть профиль можно, только добавив заново."
        alert.addButton(withTitle: "Удалить").hasDestructiveAction = true
        alert.addButton(withTitle: "Отмена")
        guard alert.runModal() == .alertFirstButtonReturn, busyConnection == nil else { return }
        busyConnection = item.id
        connectionErrors[item.id] = nil
        Task {
            defer { busyConnection = nil }
            if !users.isEmpty {
                let hadEdits = rulesChanged
                for index in settings.directions.indices where settings.directions[index].connection == item.id {
                    settings.directions[index].path = .unset
                    settings.directions[index].enabled = false
                    settings.directions[index].server = nil
                }
                for index in routing.directions.indices where routing.directions[index].connection == item.id {
                    routing.directions[index].path = .unset
                    routing.directions[index].enabled = false
                }
                if !hadEdits { routing = freshDraft() }
                try? persistSettings()
                guard await sendSettings() else { return }
            }
            do {
                status = try await client.request(.deleteConnection, payload: item.id, as: RouterStatus.self)
            } catch { connectionErrors[item.id] = error.localizedDescription }
        }
    }

    /// The work server tried first; the rest follow in the profile's order.
    func preferRemote(_ remote: OpenVPNRemote, for connection: UUID) {
        guard busyConnection == nil else { return }
        busyConnection = connection
        Task {
            defer { busyConnection = nil }
            do {
                status = try await client.request(.preferRemote, payload: RemotePreference(connection: connection, remote: remote), as: RouterStatus.self)
                connectionErrors[connection] = nil
            } catch { connectionErrors[connection] = error.localizedDescription }
        }
    }

    // MARK: - OpenVPN login

    /// Whether the fields hold something the daemon does not have yet.
    func credentialsChanged(_ id: UUID) -> Bool {
        let typed = usernames[id] ?? connection(id)?.username ?? ""
        return !(passwords[id] ?? "").isEmpty || (typed.isEmpty ? nil : typed) != connection(id)?.username
    }

    private var credentialEdits: [UUID] {
        connections.filter { $0.kind == .openVPN && credentialsChanged($0.id) }.map(\.id)
    }

    func saveCredentials(_ id: UUID) {
        guard busyConnection == nil else { return }
        busyConnection = id
        connectionErrors[id] = nil
        Task {
            defer { busyConnection = nil }
            connectionErrors[id] = await pushCredentials(id)
        }
    }

    /// What the fields show is what gets used, so «Включить» never runs with an
    /// older password than the one just typed. An empty password field means
    /// "keep the stored one": the daemon never sends it back to fill the field.
    private func pushCredentials(_ id: UUID) async -> String? {
        guard credentialsChanged(id) else { return nil }
        let username = usernames[id] ?? connection(id)?.username ?? ""
        let password = passwords[id] ?? ""
        do {
            let update = CredentialsUpdate(connection: id, username: username.isEmpty ? nil : username, password: password.isEmpty ? nil : password)
            status = try await client.request(.updateCredentials, payload: update, as: RouterStatus.self)
            passwords[id] = nil
            usernames[id] = nil
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    // MARK: - Xray

    private func xrayRequest(_ update: XrayUpdate) async -> String? {
        do {
            status = try await client.request(.updateXray, payload: update, as: RouterStatus.self)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    func updateXray(_ update: XrayUpdate) {
        guard busyConnection == nil else { return }
        busyConnection = update.connection
        Task {
            defer { busyConnection = nil }
            connectionErrors[update.connection] = await xrayRequest(update)
        }
    }

    func ping(of server: XraySummary.Server) -> PingState? { server.endpoint.flatMap { pings[$0] } }
    func ping(host: String) -> PingState? { pings[host] }

    /// A subscription can list many servers, so a small batch at a time.
    func pingServers(_ connection: UUID) {
        guard pingingServers == nil, let servers = self.connection(connection)?.xray?.servers else { return }
        let jobs = servers.compactMap { server -> (String, String, Int, Bool)? in
            guard let endpoint = server.endpoint, let host = server.host, let port = server.port else { return nil }
            return (endpoint, host, port, server.protocolName == "hysteria")
        }
        for job in jobs { pings[job.0] = nil }
        pingedServerCount = 0
        pingableServerCount = jobs.count
        guard !jobs.isEmpty else { return }
        pingingServers = connection
        Task {
            defer { pingingServers = nil }
            await withTaskGroup(of: (String, PingState).self) { group in
                var next = 0
                while next < min(jobs.count, 5) {
                    let job = jobs[next]
                    next += 1
                    group.addTask { (job.0, await NetworkProbes.serverPing(host: job.1, port: job.2, udp: job.3)) }
                }
                while let (endpoint, result) = await group.next() {
                    pings[endpoint] = result
                    pingedServerCount += 1
                    guard next < jobs.count else { continue }
                    let job = jobs[next]
                    next += 1
                    group.addTask { (job.0, await NetworkProbes.serverPing(host: job.1, port: job.2, udp: job.3)) }
                }
            }
        }
    }

    /// One server, on request: the one a route uses.
    func pingServer(_ server: XraySummary.Server) {
        guard let endpoint = server.endpoint, let host = server.host, let port = server.port, !pinging.contains(endpoint) else { return }
        pinging.insert(endpoint)
        Task {
            defer { pinging.remove(endpoint) }
            pings[endpoint] = await NetworkProbes.serverPing(host: host, port: port, udp: server.protocolName == "hysteria")
        }
    }

    /// The tunnel of a route on this VPN, while it is up.
    func connectedInterface(of connection: UUID) -> String? {
        settings.activeDirections.lazy
            .filter { $0.connection == connection }
            .compactMap { self.status.tunnels[$0.id] }
            .first { $0.phase == .connected }?.interfaceName
    }

    /// Only on request. ICMP to the server, which many servers never answer;
    /// with the VPN up, through the tunnel to 1.1.1.1, which answers — so the
    /// time is what traffic through it actually takes.
    func pingHost(_ host: String, through interface: String?) {
        guard !pinging.contains(host) else { return }
        pinging.insert(host)
        Task {
            defer { pinging.remove(host) }
            if let interface {
                pings[host] = await NetworkProbes.ping(interface: interface, target: "1.1.1.1") ?? .noReply
            } else {
                pings[host] = await NetworkProbes.serverPing(host: host, port: 0, udp: true)
            }
        }
    }

    // MARK: - Rules

    func saveRules() {
        do {
            settings = try routing.applied(to: settings)
            if let id = settings.defaultDirection { parked[id] = routing.texts[id] ?? "" }
            // Read back the way it was stored, so an applied edit shows no changes.
            routing = freshDraft()
            applySettings()
        } catch { errorMessage = error.localizedDescription }
    }

    /// Compared with what the applied settings read back as.
    var rulesChanged: Bool { routing != freshDraft() }

    /// Edits about to be left behind are applied or dropped, as a document asks
    /// on close: unapplied, they would sit there while traffic goes the old way.
    /// false: stay — «Отмена», or «Применить» refused the lists.
    func settleRuleEdits() -> Bool {
        guard rulesChanged else { return true }
        let alert = NSAlert()
        alert.messageText = "Применить изменения маршрутов?"
        alert.informativeText = "Пока они не применены, трафик идёт по-старому. Если не применить, правки пропадут."
        alert.addButton(withTitle: "Применить")
        alert.addButton(withTitle: "Не применять")
        alert.addButton(withTitle: "Отмена")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            saveRules()
            return !rulesChanged
        case .alertSecondButtonReturn:
            revertRules()
            return true
        default:
            return false
        }
    }

    /// Why «Применить» would fail, said while the lists are still being typed.
    var rulesError: String? {
        guard rulesChanged else { return nil }
        do { _ = try routing.applied(to: settings); return nil } catch { return error.localizedDescription }
    }

    /// A site from «Трафик» or the route check, applied at once: the click is
    /// the decision. Edits still being typed stay unapplied, with it added.
    func addRule(_ host: String, to direction: UUID) {
        func adding(_ draft: RoutingDraft) -> RoutingDraft {
            var draft = draft
            draft.texts[direction] = Self.appending(host, to: draft.texts[direction] ?? "")
            return draft
        }
        let hadEdits = rulesChanged
        let edited = adding(routing)
        do {
            settings = try adding(freshDraft()).applied(to: settings)
            routing = hadEdits ? edited : freshDraft()
            applySettings()
        } catch { errorMessage = error.localizedDescription }
    }

    private static func appending(_ line: String, to text: String) -> String {
        guard !text.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == line }) else { return text }
        return text.isEmpty || text.hasSuffix("\n") ? text + line : text + "\n" + line
    }

    func revertRules() {
        routing = freshDraft()
        if let selected = selectedDirection, !routing.directions.contains(where: { $0.id == selected }) { selectedDirection = nil }
    }

    /// A new route at the bottom of the list, selected for editing. Only
    /// «Применить» brings it into effect.
    func addDirection() {
        // Names must differ, and a second tap on «+» should not land on an error.
        let taken = Set(routing.directions.map { $0.name.trimmingCharacters(in: .whitespaces).lowercased() })
        let base = "Новое направление"
        let name = (1...).lazy.map { $0 == 1 ? base : "\(base) \($0)" }.first { !taken.contains($0.lowercased()) }!
        let direction = Direction(name: name, path: connections.isEmpty ? .direct : .vpn(connections[0].id))
        routing.directions.append(direction)
        routing.texts[direction.id] = ""
        selectedDirection = direction.id
    }

    /// Gone at once, after a confirmation, rather than left as an edit waiting
    /// for «Применить»: a route removed from the list must not keep running.
    func deleteDirection(_ id: UUID) {
        guard let direction = routing.directions.first(where: { $0.id == id }) else { return }
        let alert = NSAlert()
        alert.messageText = "Удалить направление «\(direction.name)»?"
        alert.informativeText = "Его сайты пойдут туда же, куда остальной трафик. Правила направления удалятся."
        alert.addButton(withTitle: "Удалить").hasDestructiveAction = true
        alert.addButton(withTitle: "Отмена")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        routing.directions.removeAll { $0.id == id }
        routing.texts[id] = nil
        if routing.defaultDirection == id { routing.defaultDirection = nil }
        if selectedDirection == id { selectedDirection = routing.directions.first?.id }
        guard settings.directions.contains(where: { $0.id == id }) else { return }
        let hadEdits = rulesChanged
        settings.directions.removeAll { $0.id == id }
        if settings.defaultDirection == id { settings.defaultDirection = nil }
        if !hadEdits { routing = freshDraft() }
        applySettings()
    }

    func moveDirections(from source: IndexSet, to destination: Int) {
        routing.directions.move(fromOffsets: source, toOffset: destination)
    }

    func exportRules() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(routing.exported, forType: .string)
    }

    /// Fills the page rather than applying: the lists stay to be looked over,
    /// and «Отменить» still brings the old ones back.
    func importRules() {
        let text = NSPasteboard.general.string(forType: .string) ?? ""
        guard let imported = routing.importing(text) else {
            errorMessage = "В буфере обмена нет маршрутов Коммутатора: сначала скопируйте их кнопкой «Скопировать маршруты»"
            return
        }
        routing = imported
    }

    /// «Добавить новый VPN…» of a route: the VPN then goes to that route.
    func addVPN(for slot: UUID) {
        adoptSlot = slot
        addingConnection = true
    }

    /// A new VPN into the route it was added for, the route's old one
    /// forgotten if nothing else uses it.
    private func adopt(_ connection: UUID, into slot: UUID) {
        adoptSlot = nil
        // A route added but not applied yet: the VPN waits in the draft with it.
        guard let index = settings.directions.firstIndex(where: { $0.id == slot }) else {
            guard let draft = routing.directions.firstIndex(where: { $0.id == slot }) else { return }
            routing.directions[draft].path = .vpn(connection)
            routing.directions[draft].server = nil
            routing.directions[draft].enabled = true
            return
        }
        let hadEdits = rulesChanged
        let old = settings.directions[index].connection
        settings.directions[index].path = .vpn(connection)
        settings.directions[index].server = nil
        settings.directions[index].enabled = true
        if hadEdits, let draft = routing.directions.firstIndex(where: { $0.id == slot }) {
            routing.directions[draft].path = .vpn(connection)
            routing.directions[draft].server = nil
            routing.directions[draft].enabled = true
        } else if !hadEdits {
            routing = freshDraft()
        }
        applySettings()
        if let old { retire(old) }
    }

    /// Forgets a VPN that no route uses any more. After the
    /// daemon has the new settings: it refuses to drop a VPN a route still names.
    private func retire(_ id: UUID) {
        guard !settings.directions.contains(where: { $0.connection == id }), let old = self.connection(id), !XPCClient.isDemo else { return }
        // The profile and its saved password cannot be brought back, and the new
        // one may be the wrong file: so the old one goes only when asked.
        let alert = NSAlert()
        alert.messageText = "Удалить прежний VPN «\(old.title)»?"
        alert.informativeText = "Он больше нигде не используется. Профиль и сохранённый пароль вернуть нельзя, только добавив VPN заново. Если оставить, его можно удалить на странице «VPN»."
        alert.addButton(withTitle: "Оставить")
        alert.addButton(withTitle: "Удалить").hasDestructiveAction = true
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        Task {
            guard await sendSettings() else { return }
            do { status = try await client.request(.deleteConnection, payload: id, as: RouterStatus.self) }
            catch { connectionErrors[id] = error.localizedDescription }
        }
    }

    func updateGeneralSettings() {
        do {
            try persistSettings()
            configureLoginItem()
            queueSettingsPush()
        } catch { errorMessage = error.localizedDescription }
    }

    private func applySettings() {
        do {
            try persistSettings()
            queueSettingsPush()
        } catch { errorMessage = error.localizedDescription }
    }

    // MARK: - Diagnostics and checks

    /// Polled every second while the page is open, so a failure stays quiet:
    /// the status banner already says when the daemon is gone.
    func refreshDiagnostics() async {
        guard var value = try? await client.request(.getDiagnostics, as: Diagnostics.self) else { return }
        // Only the app knows its own bundle version; the daemon reports its own.
        value.appVersion = appVersion
        diagnosticsInfo = value
    }

    /// The lines over the log, and the head of what «Скопировать» copies.
    /// Protocols are named here: this text is for whoever helps with a problem.
    var diagnostics: String {
        guard let value = diagnosticsInfo else { return "Диагностика ещё не загружена" }
        let routes = settings.activeDirections.map { direction -> String in
            guard direction.path != .direct else { return "«\(direction.name)»: без VPN" }
            let kind = connection(direction.connection)?.kind.title ?? "—"
            let tunnel = value.status.tunnels[direction.id]
            return "«\(direction.name)» (\(kind)): \(tunnel?.phase.russianTitle ?? "—") (\(tunnel?.interfaceName ?? "—"))"
        }
        return "Коммутатор \(value.appVersion), компонент \(value.daemonVersion) · \(value.status.protection.russianTitle) · сеть: \(value.physicalInterface ?? "—")\n"
            + routes.joined(separator: " · ")
    }

    func refreshLog() async {
        guard let chunk = try? await client.request(.getLog, payload: logCursor, as: LogChunk.self) else { return }
        // A restarted daemon counts from zero again and sends everything it kept.
        if chunk.next < logCursor { logLines.removeAll() }
        logCursor = chunk.next
        guard !chunk.lines.isEmpty else { return }
        logLines = Array((logLines + chunk.lines).suffix(10_000))
    }

    /// The lines shown, plus what whoever reads them needs and the page does not:
    /// the Mac and which VPN kinds are set up. No names: those can be servers.
    func copyDiagnostics(_ lines: [String]) {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var hardware = [UInt8](repeating: 0, count: max(size, 1))
        sysctlbyname("hw.model", &hardware, &size, nil, 0)
        let kinds = connections.map { $0.protocolTitle ?? $0.kind.title }
        let system = "macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion) · \(String(decoding: hardware.prefix { $0 != 0 }, as: UTF8.self)) · "
            + "VPN: \(kinds.isEmpty ? "нет" : kinds.joined(separator: ", ")) · "
            + "скопировано \(Date().formatted(.iso8601.year().month().day().time(includingFractionalSeconds: false).timeZone(separator: .colon)))"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(diagnostics + "\n" + system + "\n\n" + lines.joined(separator: "\n"), forType: .string)
    }

    /// Where foreign and Russian sites see you from, by an ordinary request
    /// each, routed as a browser's would be. Works with VPN off too. Runs at
    /// launch and whenever VPN comes up or goes off, otherwise on request.
    func runChecks() {
        // VPN going on or off mid-check: the running one answers for the old path,
        // so one more follows it instead of the request being dropped.
        guard !checking else { checkAgain = true; return }
        checking = true
        Task {
            async let cloudflare = NetworkProbes.echo(NetworkProbes.cloudflareCheck)
            async let yandex = NetworkProbes.echo(NetworkProbes.yandexCheck)
            report = await ConnectionReport(cloudflare: cloudflare, yandex: yandex)
            checking = false
            if checkAgain {
                checkAgain = false
                runChecks()
            }
        }
    }

    func checkRoute(_ input: String) {
        let host = RoutingDraft.site(input.trimmingCharacters(in: .whitespaces))
        guard !host.isEmpty, !checkingRoute else { return }
        checkingRoute = true
        Task {
            defer { checkingRoute = false }
            do {
                var check = try await NetworkProbes.checkRoute(host)
                // The name the daemon last resolved to this address: another site
                // there means a shared CDN address, and the route is that site's.
                if let named = try? await client.request(.lookupNames, payload: [check.address], as: [String: String].self)[check.address],
                   RuleSet.normalizeDomain(named) != RuleSet.normalizeDomain(host) {
                    check.sharedWith = named
                }
                routeCheck = check
            }
            catch { errorMessage = error.localizedDescription }
        }
    }

    /// The routes whose tunnel is this interface, by name.
    func directions(on interface: String) -> [Direction] {
        settings.activeDirections.filter { status.tunnels[$0.id]?.interfaceName == interface }
    }

    /// An interface as the user knows it.
    func via(_ interface: String?) -> String {
        guard let interface else { return "через неизвестный интерфейс" }
        let names = directions(on: interface).map { "«\($0.name)»" }
        if !names.isEmpty { return "через \(names.joined(separator: ", ")) (\(interface))" }
        return interface.hasPrefix("utun") ? "через чужой туннель (\(interface))" : "напрямую (\(interface))"
    }

    /// What the banner offers for the component problem it names.
    enum ComponentFix { case install, approve }
    @Published private(set) var componentFix: ComponentFix?

    func fixSystemComponent() {
        guard componentFix != .approve else { return SMAppService.openSystemSettingsLoginItems() }
        Task {
            if await prepareSystemComponent(install: true) { await syncConfiguration() }
        }
    }

    /// Removes everything the installer put down, profiles and their keys
    /// included. The daemon puts DNS, PF and routes back itself when stopped.
    func uninstall() {
        // The demo has nothing installed to remove, and its data is made up.
        guard !XPCClient.isDemo else { return }
        let alert = NSAlert()
        alert.messageText = "Удалить Коммутатор?"
        alert.informativeText = "VPN выключится, сеть вернётся в состояние до установки. Удалятся приложение, системный компонент, профили и настройки."
        alert.addButton(withTitle: "Удалить").hasDestructiveAction = true
        alert.addButton(withTitle: "Отмена")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            // Off through the daemon first, as for an update: its teardown on
            // SIGTERM has twenty seconds before launchd kills it, and anything
            // left then (PF, DNS) would have nobody to put it back.
            if status.desiredEnabled {
                guard await turnOffForQuit() else { return }
            }
            // The daemon removes everything without a password. An ad-hoc build,
            // a component too old for it or none at all: the script, with one.
            do { _ = try await client.request(.uninstall, payload: Bundle.main.bundlePath, as: RouterStatus.self) }
            catch {
                do { try await PrivilegedScript.run("uninstall") }
                catch { errorMessage = "Не удалось удалить: \(error.localizedDescription)"; return }
            }
            // After the request: unregistering a daemon stops it, and it had to answer first.
            for service in [SMAppService.mainApp, SMAppService.daemon(plistName: "com.vpnrouter.daemon.plist")] where service.status == .enabled {
                try? await service.unregister()
            }
            try? FileManager.default.removeItem(at: Self.updateDirectory.deletingLastPathComponent())
            if let domain = Bundle.main.bundleIdentifier { UserDefaults.standard.removePersistentDomain(forName: domain) }
            // Not NSApp.terminate: its quit dialog would try to turn VPN off
            // through a daemon that is already gone.
            exit(0)
        }
    }

    // MARK: Updates

    /// Kept in Caches, so a download waits for its install across app restarts.
    private static let updateDirectory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        .appending(path: Bundle.main.bundleIdentifier ?? "com.vpnrouter.app").appending(path: "Update")
    private var updatePackage: URL { Self.updateDirectory.appending(path: "Commutator.pkg") }
    private var updateRelease: URL { Self.updateDirectory.appending(path: "release.json") }
    /// Set by the copy that installs an update: the new copy turns VPN back on.
    private let resumeAfterUpdateKey = "resume-after-update"

    private func watchUpdates() {
        if let data = try? Data(contentsOf: updateRelease),
           let release = try? IPCCodec.decoder.decode(AppRelease.self, from: data),
           VPNRouterVersion.isNewer(release.version, than: appVersion),
           FileManager.default.fileExists(atPath: updatePackage.path) {
            update = .ready(release)
        } else {
            // Installed already, or never finished downloading.
            try? FileManager.default.removeItem(at: Self.updateDirectory)
        }
        Task { [weak self] in
            while !Task.isCancelled {
                await self?.checkForUpdate()
                try? await Task.sleep(for: .seconds(6 * 3600))
            }
        }
    }

    func checkForUpdate() async {
        // The demo neither reaches out nor stores what it was told.
        guard !checkingUpdate, !XPCClient.isDemo else { return }
        checkingUpdate = true
        defer { checkingUpdate = false }
        // Silent on failure: no network, or kill switch holding GitHub back.
        guard let (data, response) = try? await URLSession.shared.data(from: AppRelease.latestURL),
              (response as? HTTPURLResponse)?.statusCode == 200
        else {
            updateCheckResult = "Не удалось проверить: GitHub недоступен"
            return
        }
        guard let release = AppRelease.parse(data, installed: appVersion) else {
            updateCheckResult = "Установлена последняя версия"
            return
        }
        updateCheckResult = nil
        if let current = update {
            // A download or install under way, or a pkg for this very release, stays.
            if case .downloading = current { return }
            if case .installing = current { return }
            if current.release.version == release.version { return }
            try? FileManager.default.removeItem(at: Self.updateDirectory)
        }
        update = .available(release)
        if UserDefaults.standard.string(forKey: "notified-update") != release.version {
            UserDefaults.standard.set(release.version, forKey: "notified-update")
            notify("Вышел Коммутатор \(release.version)", "Скачать обновление можно в окне Коммутатора.")
        }
    }

    func showReleaseNotes() {
        guard let release = update?.release else { return }
        let alert = NSAlert()
        alert.messageText = "Что нового в версии \(release.version)"
        alert.informativeText = release.notes.isEmpty ? "Описания нет." : release.notes
        alert.runModal()
    }

    /// The update lands there, the only place the daemon installs to: a copy
    /// elsewhere would stay behind, older than its daemon.
    private var canInstallUpdate: Bool {
        guard Bundle.main.bundlePath == "/Applications/Commutator.app" else {
            errorMessage = "Обновить из приложения можно только копию в «Программах». Скачайте Commutator.pkg по ссылке на странице проекта и установите его"
            return false
        }
        return true
    }

    private var installingUpdate: Bool {
        if case .installing = update { return true }
        return false
    }

    func downloadUpdate() {
        guard case .available(let release) = update, canInstallUpdate else { return }
        update = .downloading(release)
        Task {
            do {
                let (temporary, response) = try await URLSession.shared.download(from: release.packageURL)
                defer { try? FileManager.default.removeItem(at: temporary) }
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
                try? FileManager.default.removeItem(at: Self.updateDirectory)
                try FileManager.default.createDirectory(at: Self.updateDirectory, withIntermediateDirectories: true)
                try FileManager.default.moveItem(at: temporary, to: updatePackage)
                try IPCCodec.encoder.encode(release).write(to: updateRelease)
                update = .ready(release)
            } catch {
                update = .available(release)
                errorMessage = "Не удалось скачать обновление: \(error.localizedDescription)"
            }
        }
    }

    /// VPN goes off through the daemon that runs it, before the update
    /// replaces that daemon: its own teardown is not cut short by launchd.
    /// The daemon installs without a password, see `RouterDaemon.installUpdate`.
    func installUpdate() {
        guard case .ready(let release) = update, canInstallUpdate else { return }
        let wasOn = status.desiredEnabled
        if wasOn {
            // From the menu bar panel the alert would open behind other windows.
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Выключить VPN и обновить?"
            alert.informativeText = "На время обновления трафик пойдёт без туннелей, обычно это до минуты. После перезапуска Коммутатор включит VPN снова."
            alert.addButton(withTitle: "Выключить VPN и обновить")
            alert.addButton(withTitle: "Отмена")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        update = .installing(release)
        Task {
            if wasOn {
                guard await turnOffForQuit() else { update = .ready(release); return }
                UserDefaults.standard.set(true, forKey: resumeAfterUpdateKey)
            }
            // The old copy must not sync its settings into the new daemon.
            pollTask?.cancel()
            do {
                _ = try await client.request(.installUpdate, payload: updatePackage.path, as: RouterStatus.self)
                // The daemon only starts the install; it is done once the new
                // daemon answers. Three minutes is far past a slow disk.
                for _ in 0..<90 {
                    try? await Task.sleep(for: .seconds(2))
                    // Newer than this copy rather than equal to the tag: a tag and
                    // a bundle version that differ must not read as a failure.
                    if let running = try? await client.request(.getDiagnostics, as: Diagnostics.self),
                       VPNRouterVersion.isNewer(running.daemonVersion, than: appVersion) {
                        try? FileManager.default.removeItem(at: Self.updateDirectory)
                        // Not NSApp.terminate: VPN is already off, its quit dialog
                        // has nothing to ask. The new copy starts once this one is gone.
                        let relaunch = Process()
                        relaunch.executableURL = URL(fileURLWithPath: "/bin/sh")
                        relaunch.arguments = ["-c", "sleep 1; /usr/bin/open /Applications/Commutator.app"]
                        try? relaunch.run()
                        exit(0)
                    }
                }
                throw RouterErrorInfo(.internalError, "новая версия не ответила за три минуты")
            } catch {
                update = .ready(release)
                UserDefaults.standard.removeObject(forKey: resumeAfterUpdateKey)
                startPolling()
                if wasOn { setRouting(true) }
                errorMessage = "Не удалось установить обновление: \(error.localizedDescription). Скачайте Commutator.pkg по ссылке на странице проекта и установите вручную."
            }
        }
    }

    private func resumeAfterUpdate() {
        // A poll already under way when the install cancelled it lands here too.
        guard !installingUpdate, UserDefaults.standard.bool(forKey: resumeAfterUpdateKey) else { return }
        UserDefaults.standard.removeObject(forKey: resumeAfterUpdateKey)
        setRouting(true)
    }

    private func markNeedsInstall() {
        systemComponentMessage = "Локальной сборке нужна однократная установка встроенного системного компонента."
        componentFix = .install
    }

    private func bootstrap() async {
        runChecks()
        configureLoginItem()
        startPolling()
        watchUpdates()
        // A component installed by an earlier run already answers, and polling
        // syncs to it; touching it further would only interrupt something that
        // already works. Otherwise install it now — the app does nothing without
        // it, so making the user hunt for a button first only adds a step.
        guard let running = try? await client.request(.getDiagnostics, as: Diagnostics.self) else {
            if await prepareSystemComponent(install: true) { await syncConfiguration() }
            return
        }
        // An app copied over an older one, past the installer, leaves the older
        // component running. It is replaced here, once, rather than from a
        // button one has to know about.
        guard running.daemonVersion != appVersion else { return }
        if await updateSystemComponent(from: running.daemonVersion) { await syncConfiguration() }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? VPNRouterVersion.current
    }

    private func updateSystemComponent(from version: String) async -> Bool {
        guard isInApplications else { return false }
        // Registered through SMAppService, it runs from this very bundle: the new
        // binary is already in place, and launchd starts it on the next boot.
        guard SMAppService.daemon(plistName: "com.vpnrouter.daemon.plist").status != .enabled else {
            systemComponentMessage = "Системный компонент версии \(version) обновится до \(appVersion) после перезагрузки Mac."
            componentFix = nil
            return false
        }
        return await installLocalSystemComponent()
    }

    // SMAppService only registers daemons from a protected location; the exact
    // bundle name is not part of that requirement, so a renamed copy still works.
    private var isInApplications: Bool {
        Bundle.main.bundleURL.standardizedFileURL.path.hasPrefix("/Applications/")
    }

    /// `install: false` only reports what state the component is in; `true` also
    /// registers it, which may put an authorization dialog in front of the user.
    private func prepareSystemComponent(install: Bool) async -> Bool {
        componentFix = nil
        guard isInApplications else {
            systemComponentMessage = "Чтобы macOS разрешила встроенный системный компонент, переместите Коммутатор в папку «Программы» и запустите приложение оттуда."
            return false
        }
        let service = SMAppService.daemon(plistName: "com.vpnrouter.daemon.plist")
        if service.status == .notRegistered {
            do { try service.register() }
            catch {
                guard install else {
                    markNeedsInstall()
                    return false
                }
                return await installLocalSystemComponent()
            }
        }
        switch service.status {
        case .enabled:
            systemComponentMessage = nil
            return true
        case .requiresApproval:
            systemComponentMessage = "Разрешите встроенный системный компонент Коммутатора в настройках macOS. Он входит в приложение и нужен для маршрутов, DNS и PF."
            componentFix = .approve
            if install { SMAppService.openSystemSettingsLoginItems() }
        case .notFound:
            if install { return await installLocalSystemComponent() }
            markNeedsInstall()
        case .notRegistered:
            systemComponentMessage = "Встроенный системный компонент Коммутатора ещё не зарегистрирован."
            componentFix = .install
        @unknown default:
            systemComponentMessage = "macOS сообщает непонятное состояние системного компонента Коммутатора. Установите Коммутатор заново из последнего пакета .pkg."
        }
        return false
    }

    private func installLocalSystemComponent() async -> Bool {
        systemComponentMessage = "Устанавливается встроенный системный компонент. macOS запросит пароль администратора."
        componentFix = nil
        do {
            try await PrivilegedScript.run("install-system-component")
            systemComponentMessage = nil
            syncedToDaemon = false
            return true
        } catch {
            systemComponentMessage = "Не удалось установить встроенный системный компонент: \(error.localizedDescription)"
            componentFix = .install
            return false
        }
    }

    /// The daemon keeps the profiles and whether routing is on, so there is
    /// nothing to replay here beyond the routes shown in this window.
    /// Before the first sync: a route at a VPN the daemon does not have would
    /// make it refuse the whole settings. See `RouterSettings.droppingMissing`.
    private func dropMissingVPNs(_ live: [ConnectionSummary]) {
        let cleaned = settings.droppingMissing(live: Set(live.map(\.id)))
        guard cleaned != settings else { return }
        let hadEdits = rulesChanged
        settings = cleaned
        if !hadEdits { routing = freshDraft() }
        try? persistSettings()
    }

    private func syncConfiguration() async {
        syncedToDaemon = await sendSettings()
    }

    /// nil means the daemon stored the configuration and returned fresh status.
    private func storeAndSend(_ kind: VPNKind, configuration: String, authorization: Data?, connection: UUID) async -> String? {
        var payload = ProfilePayload(kind: kind, configuration: configuration, unsafeAuthorization: authorization, connection: connection)
        if kind == .openVPN {
            let username = usernames[connection] ?? self.connection(connection)?.username ?? ""
            payload.username = username.isEmpty ? nil : username
            payload.password = (passwords[connection] ?? "").isEmpty ? nil : passwords[connection]
        }
        if installingUpdate { return "Обновление уже устанавливается" }
        do {
            status = try await client.request(.replaceProfile, payload: payload, as: RouterStatus.self)
        } catch {
            return error.localizedDescription
        }
        passwords[connection] = nil
        return nil
    }

    private func sendSettings() async -> Bool {
        // The old copy must not sync its settings into the new daemon.
        guard !installingUpdate else { return false }
        do {
            let current = settings
            status = try await client.request(.updateRules, payload: current, as: RouterStatus.self)
            errorMessage = nil
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// Controls on several pages can change the same settings in quick
    /// succession. Sending one request at a time makes the last visible value
    /// the last value received by the daemon as well.
    private func queueSettingsPush() {
        guard !installingUpdate else { return }
        settingsPushPending = true
        guard !settingsPushRunning else { return }
        settingsPushRunning = true
        Task { [weak self] in
            guard let self else { return }
            defer { settingsPushRunning = false }
            while settingsPushPending {
                settingsPushPending = false
                _ = await sendSettings()
            }
        }
    }

    private func setEnabled(_ enabled: Bool) async {
        do {
            status = try await client.request(.setEnabled, payload: enabled, as: RouterStatus.self)
            errorMessage = nil
        } catch { errorMessage = error.localizedDescription }
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do {
                    // Deliberately does not clear errorMessage: this loop runs every
                    // two seconds and never sets it, so clearing here only wiped
                    // the user's error before they could read it. Each action
                    // clears its own error when it next succeeds.
                    let latest: RouterStatus = try await client.request(.getStatus, as: RouterStatus.self)
                    if !syncedToDaemon {
                        systemComponentMessage = nil
                        componentFix = nil
                        dropMissingVPNs(latest.connections)
                        await syncConfiguration()
                        if syncedToDaemon { resumeAfterUpdate() }
                    } else {
                        notifyTransitions(from: previousStatus, to: latest)
                        // The path changed under both answers: up, or off altogether.
                        let pathChanged = latest.protection != previousStatus?.protection && (latest.protection == .protected || latest.protection == .off)
                        previousStatus = latest
                        status = latest
                        traffic.follow(latest, directions: settings.activeDirections, recording: settings.watchTraffic)
                        if pathChanged { runChecks() }
                    }
                } catch { syncedToDaemon = false /* Component may still be awaiting approval. */ }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func notifyTransitions(from old: RouterStatus?, to new: RouterStatus) {
        // One notice per change of protection, the reason in its body: a notice
        // per tunnel phase used to post five for a single «Включить».
        guard let old, old.protection != new.protection, new.protection != .starting else { return }
        notify("VPN: " + new.protection.russianTitle.lowercased(), new.summary(settings))
    }

    private func notify(_ title: String, _ body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        Task {
            // Asked at the first real transition, so opening the app never greets
            // the user with a permission dialog. macOS only ever prompts once.
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            try? await UNUserNotificationCenter.current().add(.init(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }

    private func configureLoginItem() {
        // The demo's settings are made up and never saved: neither is the real login item touched.
        guard isInApplications, !XPCClient.isDemo else { return }
        do {
            let service = SMAppService.mainApp
            if settings.launchAtLogin, service.status == .notRegistered { try service.register() }
            if settings.launchAtLogin, service.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
            if !settings.launchAtLogin, service.status == .enabled { try service.unregister() }
        } catch { errorMessage = "Автозапуск: \(error.localizedDescription)" }
    }

    private func persistSettings() throws {
        // Demo settings must not replace the real ones.
        guard !XPCClient.isDemo else { return }
        let defaults = UserDefaults.standard
        defaults.set(try IPCCodec.encoder.encode(settings), forKey: settingsKey)
        defaults.set(try IPCCodec.encoder.encode(parked), forKey: Self.parkedKey)
    }

    private static func loadSettings() -> RouterSettings {
        guard let data = UserDefaults.standard.data(forKey: "router-settings") else { return .init() }
        return (try? IPCCodec.decoder.decode(RouterSettings.self, from: data)) ?? .init()
    }
}

extension XraySummary.Server {
    /// What a ping is kept under: unlike the index, it survives a refresh.
    var endpoint: String? { host.flatMap { host in port.map { "\(host):\($0)" } } }
}

@MainActor
private enum AdminAuthorization {
    /// The daemon rebuilds the approval from its external form only once the
    /// request arrives, and freeing the last reference destroys it: freed on
    /// return, every approval reached the daemon dead and was refused. So the
    /// latest one is kept until the next replaces it.
    private static var current: AuthorizationRef?

    static func request() throws -> Data {
        if let current { AuthorizationFree(current, [.destroyRights]) }
        current = nil
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess, let authorization else {
            throw RouterErrorInfo(.permissionDenied, "Не удалось запросить разрешение администратора")
        }
        current = authorization
        let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
        let authorized = kAuthorizationRightExecute.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(authorization, &rights, nil, flags, nil) == errAuthorizationSuccess
            }
        }
        guard authorized else {
            throw RouterErrorInfo(.permissionDenied, "Запрос пароля администратора отменён")
        }
        var external = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else {
            throw RouterErrorInfo(.permissionDenied, "Не удалось получить разрешение администратора. Попробуйте ещё раз")
        }
        return withUnsafeBytes(of: external) { Data($0) }
    }
}

/// Runs one of the bundled scripts as root, after the administrator prompt.
private enum PrivilegedScript {
    static func run(_ name: String) async throws {
        guard let url = Bundle.main.url(forResource: name, withExtension: "sh") else {
            throw RouterErrorInfo(.helperUnavailable, "\(name).sh отсутствует внутри приложения")
        }
        let path = url.path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"/bin/zsh \" & quoted form of \"\(path)\" with administrator privileges"
        // The authorization dialog blocks until the user answers it. Kept in this
        // process so the prompt is attributed to Commutator rather than to
        // osascript, but off the main actor so the window still draws behind it.
        try await Task.detached {
            guard let script = NSAppleScript(source: source) else {
                throw RouterErrorInfo(.helperUnavailable, "Не удалось подготовить системный запрос")
            }
            var details: NSDictionary?
            script.executeAndReturnError(&details)
            if let details {
                let message = details["NSAppleScriptErrorMessage"] as? String ?? "Установка отменена"
                throw RouterErrorInfo(.permissionDenied, message)
            }
        }.value
    }
}
