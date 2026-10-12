import CryptoKit
import Foundation
import IOKit
import Network
import os
import Security
import SystemConfiguration
import VPNRouterCore

actor RouterCoordinator {
    private let runner = CommandRunner.live
    private let pf: PFController
    private let routes: RouteController
    private let resolvers = ResolverController()
    private var dnsProxy: DNSProxy?
    private var settings = RouterSettings()
    private var ruleSet = try! RuleSet(lists: [])
    /// Every saved VPN, secrets included, and what parsing them gave.
    private var connections: [StoredConnection] = []
    private var openProfiles: [UUID: OpenVPNProfile] = [:]
    private var awgProfiles: [UUID: AmneziaWGProfile] = [:]
    private var snapshot: NetworkSnapshot?
    private var policy: PolicyState?
    private var status = RouterStatus()
    /// What runs now, by tunnel id, and how each is doing.
    private var running: [String: TunnelPlan] = [:]
    private var tunnelStatus: [String: TunnelStatus] = [:]
    /// What each OpenVPN server sent, by tunnel id.
    private var pushed: [String: PushedOptions] = [:]
    private var dynamic: [String: [String: Date]] = [:]
    /// Peers of the sockets open at the last maintenance tick: a route stays
    /// bound to its address for as long as a connection still uses it.
    private var openAddresses: Set<String> = []
    /// Recent DNS answers, address → the name asked, so the app's traffic view
    /// can show names where it only sees addresses. Memory only.
    private var recentNames: [String: String] = [:]
    private var retries: [String: Task<Void, Never>] = [:]
    private var retryAttempt: [String: Int] = [:]
    /// Xray only: first try + this many retries, then the daemon stops and asks
    /// for another server; a dead subscription server would otherwise be retried
    /// forever. OpenVPN and AmneziaWG keep retrying: after a sleep or an outage
    /// at the provider giving up left the tunnel down until a manual toggle.
    private let maxXrayRetries = 2
    private var maintenance: Task<Void, Never>?
    private let upstreams = UpstreamTable()
    private var startingRuntime = false
    private var missedNetworkChange = false
    /// Bumped by every teardown. A start or a retry suspended across one finds out
    /// when it resumes and stops, instead of building on a runtime that is gone —
    /// XPC requests do run in the gaps of a start that is waiting on its tunnels.
    private var generation = 0
    /// How long an address stays bound to the name that classified it once no
    /// connection uses it. Short, so an address a CDN hands to another site
    /// soon stops going that site's way; the DNS proxy caps what it answers
    /// for such names to the same, so no cache outlives the binding.
    private static let bindingLifetime: TimeInterval = TimeInterval(DNSProxy.trackedTTL)
    /// How often maintenance runs, and so how stale `openAddresses` can be.
    private static let maintenanceInterval: TimeInterval = 30
    /// The user's «Включить», which outlives the daemon; `status.desiredEnabled`
    /// is only whether the runtime is up right now.
    private var enabledByUser = false
    private var lastResumeIdentity: [String]?
    private var subscriptionUpdates: Task<Void, Never>?

    private lazy var tunnels = TunnelSupervisor(runner: runner, callbacks: .init(
        status: { [weak self] id, tunnelStatus in Task { await self?.tunnelStatus(id, tunnelStatus) } },
        pushedOptions: { [weak self] id, options in Task { await self?.receivedPush(id, options) } },
        failed: { [weak self] id, error in Task { await self?.tunnelFailed(id, error) } },
        note: { [weak self] message in Task { await self?.record(message) } }
    ))

    init() {
        pf = PFController(runner: runner)
        routes = RouteController(runner: runner)
        // Recovers state left by a daemon crash. Without flushing the anchor its
        // "block drop out quick all" keeps the machine offline; the leaked pfctl
        // enable reference cannot be released without its token, but PF holding
        // only the system ruleset is harmless.
        resolvers.cleanup()
        pf.cleanup()
        // The profiles live here so the app never reads them out of Keychain —
        // on an ad-hoc build every such read is a login-keychain password prompt.
        let stored = StoredState.load()
        settings = stored.settings
        // A new boot, not a daemon restart: unless the app opens at login to show
        // it, VPN waits for the user's «Включить» rather than come up unseen.
        let boot = StoredState.currentBoot
        let newBoot = stored.bootTime.map { $0 != boot } ?? false
        let enabled = stored.enabled && !(newBoot && !stored.settings.launchAtLogin)
        enabledByUser = enabled
        connections = stored.connections
        if stored.bootTime != boot || stored.migrated {
            if stored.enabled, !enabled {
                TunnelLog.shared.write("router", "Новая загрузка macOS: VPN не включается сам — приложение не открывается при входе")
            }
            if stored.migrated { TunnelLog.shared.write("router", "Настройки перенесены в направления: \(stored.settings.directions.count)") }
            var stamped = stored
            stamped.enabled = enabled
            stamped.bootTime = boot
            try? stamped.save()
        }
        (openProfiles, awgProfiles) = Self.parsed(connections)
        Self.registerLogHosts(connections)
    }

    private static func parsed(_ connections: [StoredConnection]) -> ([UUID: OpenVPNProfile], [UUID: AmneziaWGProfile]) {
        var open: [UUID: OpenVPNProfile] = [:]
        var awg: [UUID: AmneziaWGProfile] = [:]
        for connection in connections {
            if let payload = connection.openVPN { open[connection.id] = try? parseOpenVPN(payload) }
            if let payload = connection.amneziaWG { awg[connection.id] = try? AmneziaWGProfileParser.parse(payload.configuration) }
        }
        return (open, awg)
    }

    /// The names this daemon works with, so the log can alias them instead of
    /// printing them. Everything else keeps its name: see `LogRedactor`.
    private static func registerLogHosts(_ connections: [StoredConnection]) {
        for connection in connections {
            if let text = connection.openVPN?.configuration, let profile = try? OpenVPNProfileParser.parse(text, allowUnsafe: true) {
                for remote in profile.remotes { TunnelLog.shared.register(host: remote.host) }
            }
            if let text = connection.amneziaWG?.configuration, let profile = try? AmneziaWGProfileParser.parse(text) {
                TunnelLog.shared.register(host: profile.endpointHost)
            }
            for server in connection.xray?.servers ?? [] { TunnelLog.shared.register(host: server.host) }
            if let host = connection.xray?.subscriptionURL.flatMap(URL.init(string:))?.host { TunnelLog.shared.register(host: host) }
        }
    }

    func handle(_ request: IPCRequest) async -> IPCResponse {
        do {
            switch request.operation {
            case .getStatus:
                return try response(reported())
            case .replaceProfile:
                let payload: ProfilePayload = try decodePayload(request)
                status.lastError = nil
                try await replace(payload)
                return try response(reported())
            case .updateRules:
                let value: RouterSettings = try decodePayload(request)
                status.lastError = nil
                try await update(value)
                return try response(reported())
            case .setEnabled:
                let enabled: Bool = try decodePayload(request)
                status.lastError = nil
                try await setEnabled(enabled)
                return try response(reported())
            case .updateCredentials:
                let update: CredentialsUpdate = try decodePayload(request)
                status.lastError = nil
                guard var payload = connection(update.connection)?.openVPN else {
                    throw RouterErrorInfo(.invalidConfiguration, "Такого профиля OpenVPN нет")
                }
                payload.username = update.username
                payload.password = update.password
                payload.connection = update.connection
                try await replace(payload)
                return try response(reported())
            case .preferRemote:
                let preference: RemotePreference = try decodePayload(request)
                status.lastError = nil
                try await preferRemote(preference)
                return try response(reported())
            case .deleteConnection:
                let id: UUID = try decodePayload(request)
                status.lastError = nil
                try deleteConnection(id)
                return try response(reported())
            case .getDiagnostics:
                return try response(Diagnostics(status: reported(), physicalInterface: snapshot?.physicalInterface))
            case .getProfile:
                let asked: ProfileRequest = try decodePayload(request)
                // Keys ride inline in a profile. Where unsigned clients are let in,
                // any local program could ask for them, so there it takes an
                // administrator, as a profile with scripts does.
                if ProcessInfo.processInfo.environment["VPNROUTER_ALLOW_UNSIGNED"] == "1" {
                    guard let authorization = asked.authorization, AdminAuthorization.validate(authorization) else {
                        throw RouterErrorInfo(.permissionDenied, "Показ профиля требует подтверждения администратора")
                    }
                }
                guard let stored = connection(asked.connection), let payload = stored.openVPN ?? stored.amneziaWG else {
                    throw RouterErrorInfo(.invalidConfiguration, "Профиль не загружен")
                }
                return try response(payload.configuration)
            case .getLog:
                let cursor: Int = try decodePayload(request)
                return try response(TunnelLog.shared.lines(after: cursor))
            case .lookupNames:
                let addresses: [String] = try decodePayload(request)
                return try response(addresses.reduce(into: [String: String]()) { $0[$1] = recentNames[$1] })
            case .updateXray:
                let update: XrayUpdate = try decodePayload(request)
                status.lastError = nil
                try await updateXray(update)
                return try response(reported())
            case .installUpdate:
                let package: String = try decodePayload(request)
                try installUpdate(package)
                return try response(reported())
            case .uninstall:
                let app: String = try decodePayload(request)
                try uninstall(app)
                return try response(reported())
            }
        } catch let error as RouterErrorInfo {
            status.lastError = error
            record("Ошибка \(error.code.rawValue)")
            return .init(error: error)
        } catch {
            let wrapped = RouterErrorInfo(.internalError, error.localizedDescription)
            status.lastError = wrapped
            return .init(error: wrapped)
        }
    }

    func networkChanged() async {
        // The first path update arrives right after launch: a fine moment to
        // start the subscription schedule, which needs no app either.
        if subscriptionUpdates == nil { startSubscriptionUpdates() }
        guard status.desiredEnabled else { await resumeIfWanted(); return }
        // startRuntime suspends while it waits for the tunnels, and the actor lets
        // this method run in that gap. Tearing the runtime down there is what
        // produced "interface utunN does not exist" in the middle of setup.
        guard !startingRuntime else { missedNetworkChange = true; return }
        try? await Task.sleep(for: .seconds(1))
        guard status.desiredEnabled else { return }
        guard !startingRuntime else { missedNetworkChange = true; return }
        // Bringing up our own tunnels changes the path too, so an unchanged
        // snapshot means we are hearing our own startup and must not restart.
        let current = try? NetworkSnapshot.capture(using: runner)
        if let current, current.routingIdentity == snapshot?.routingIdentity {
            record("Сеть та же (\(current.physicalInterface)): перезапуск не нужен")
            return
        }
        record("Изменилась сеть: \(Self.describeChange(from: snapshot, to: current))")
        await stopRuntime(preserveDesiredState: true)
        do { try await startRuntimeOrRollBack() }
        catch {
            status.lastError = error as? RouterErrorInfo ?? .init(.routingFailure, error.localizedDescription)
            status.protection = .error
        }
    }

    /// What moved under us, for the log. Addresses of a home or office gateway are
    /// private ones and stay readable; a public one the log aliases.
    private static func describeChange(from previous: NetworkSnapshot?, to current: NetworkSnapshot?) -> String {
        guard let current else { return "снимок не снялся — сети сейчас нет" }
        guard let previous else { return "\(current.physicalInterface), шлюз \(current.ipv4Gateway ?? "—")" }
        var changes: [String] = []
        if previous.physicalInterface != current.physicalInterface {
            changes.append("интерфейс \(previous.physicalInterface) → \(current.physicalInterface)")
        }
        if previous.ipv4Gateway != current.ipv4Gateway {
            changes.append("шлюз \(previous.ipv4Gateway ?? "—") → \(current.ipv4Gateway ?? "—")")
        }
        if previous.ipv6Gateway != current.ipv6Gateway {
            changes.append("IPv6-шлюз \(previous.ipv6Gateway ?? "—") → \(current.ipv6Gateway ?? "—")")
        }
        if previous.lanNetworks != current.lanNetworks { changes.append("локальные сети") }
        if previous.dnsServers != current.dnsServers { changes.append("DNS-серверы") }
        return changes.isEmpty ? "состав тот же" : changes.joined(separator: ", ")
    }

    /// launchd's SIGTERM: without this the PF anchor's final block rule and the
    /// resolver pointed at 127.0.0.1 outlive the process. The wish stays on disk,
    /// so the next start brings protection back.
    func shutdown() async {
        await stopRuntime(preserveDesiredState: false)
    }

    /// Half an applied runtime is worse than none: the system resolver already
    /// points at a proxy with no upstream for the routes, while PF and the routes
    /// that would make it work are not in place yet.
    private func startRuntimeOrRollBack() async throws {
        do {
            try await startRuntime()
            lastResumeIdentity = nil
        } catch is CancellationError {
            // Superseded by a stop or a newer start, which owns the runtime now.
        } catch {
            await stopRuntime(preserveDesiredState: false)
            record("Откат: рантайм не запустился — \((error as? RouterErrorInfo)?.message ?? error.localizedDescription)")
            throw error
        }
    }

    // MARK: - Saved VPNs

    private func connection(_ id: UUID) -> StoredConnection? { connections.first { $0.id == id } }

    /// Saved before it takes effect: the app keeps no copy, so a profile that
    /// only ever lived in memory is one restart from being lost.
    private func store(_ updated: [StoredConnection]) throws {
        var next = storedState()
        next.connections = updated
        try next.save()
        connections = updated
        (openProfiles, awgProfiles) = Self.parsed(connections)
        Self.registerLogHosts(connections)
    }

    private func replace(_ incoming: ProfilePayload) async throws {
        guard let id = incoming.connection else { throw RouterErrorInfo(.invalidConfiguration, "Не указан профиль") }
        let existing = connection(id)
        var payload = Self.carryingCredentials(incoming, from: existing?.openVPN)
        // The app re-sends a profile it edits unchanged, and an unchanged
        // profile must not cost a working tunnel its connection.
        if let stored = existing?.openVPN ?? existing?.amneziaWG, stored.kind == payload.kind,
           stored.configuration == payload.configuration, stored.username == payload.username, stored.password == payload.password {
            return
        }
        switch payload.kind {
        case .openVPN:
            _ = try Self.parseOpenVPN(payload)
            // A one-time approval, already turned into a remembered digest above.
            payload.unsafeAuthorization = nil
        case .amneziaWG:
            _ = try AmneziaWGProfileParser.parse(payload.configuration)
        }
        payload.connection = nil
        var saved = existing ?? StoredConnection(id: id)
        saved.openVPN = payload.kind == .openVPN ? payload : nil
        saved.amneziaWG = payload.kind == .amneziaWG ? payload : nil
        saved.xray = nil
        var updated = connections
        if let index = updated.firstIndex(where: { $0.id == id }) { updated[index] = saved } else { updated.append(saved) }
        try store(updated)
        record("\(existing == nil ? "Добавлен" : "Обновлён") профиль \(payload.kind.title)")
        await reconcileIfRunning()
    }

    private func preferRemote(_ preference: RemotePreference) async throws {
        guard let index = connections.firstIndex(where: { $0.id == preference.connection }), connections[index].openVPN != nil else {
            throw RouterErrorInfo(.invalidConfiguration, "Такого профиля OpenVPN нет")
        }
        guard connections[index].preferredRemote != preference.remote else { return }
        var updated = connections
        updated[index].preferredRemote = preference.remote
        try store(updated)
        record("OpenVPN: выбран другой первый сервер")
        // Only its own tunnel restarts, the way a retry does: see reconcileTunnels.
        await reconcileIfRunning()
    }

    /// A VPN goes only once no route that is on uses it: the app takes it out
    /// of its routes first, so the tunnel is already down by now.
    private func deleteConnection(_ id: UUID) throws {
        guard !(status.desiredEnabled && settings.activeDirections.contains { $0.connection == id }) else {
            throw RouterErrorInfo(.invalidConfiguration, "Этот VPN используется включённым направлением. Выключите направление или выберите ему другой VPN")
        }
        try store(connections.filter { $0.id != id })
        record("Удалён профиль VPN")
    }

    private func updateXray(_ update: XrayUpdate) async throws {
        let id = update.connection
        var state = connection(id)?.xray ?? XrayState()
        if let source = update.source?.trimmingCharacters(in: .whitespacesAndNewlines), !source.isEmpty {
            let lowered = source.lowercased()
            if lowered.hasPrefix("https://") {
                let fetched = try await fetchSubscription(source, userAgent: userAgent(state))
                var subscription = XrayState(subscriptionURL: source)
                subscription.apply(fetched, keeping: nil)
                state = subscription
            } else if lowered.hasPrefix("http://") {
                throw RouterErrorInfo(.invalidConfiguration, "Подписка должна открываться по https://: по http её адрес и серверы видит любая сеть по пути")
            } else {
                state = XrayState(servers: try XrayProfileParser.servers(from: source))
            }
            record("Xray: серверов — \(state.servers.count)")
        }
        if update.refresh, let source = state.subscriptionURL {
            let fetched = try await fetchSubscription(source, userAgent: userAgent(state))
            state.apply(fetched, keeping: state.server)
        }
        guard !state.servers.isEmpty else { throw RouterErrorInfo(.invalidConfiguration, "Нет серверов Xray") }
        // Re-read after the fetch: the list may have changed while it ran.
        var updated = connections
        if let index = updated.firstIndex(where: { $0.id == id }) {
            updated[index].xray = state
            updated[index].openVPN = nil
            updated[index].amneziaWG = nil
        } else {
            updated.append(.init(id: id, xray: state))
        }
        try store(updated)
        await reconcileIfRunning()
    }

    /// Checked every ten minutes and fetched once the subscription's own interval
    /// is up: the daemon keeps it fresh without the app, as it keeps protection on.
    private func startSubscriptionUpdates() {
        subscriptionUpdates = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshSubscriptionsIfDue()
                try? await Task.sleep(for: .seconds(600))
            }
        }
    }

    /// The one set in «Общих»; a subscription added before there was one keeps
    /// what it was given then.
    private func userAgent(_ state: XrayState) -> String? { settings.subscriptionUserAgent ?? state.userAgent }

    /// Only subscriptions some route uses: one merely kept is refreshed when a
    /// route picks it, by the app's first look at it. `force`: whatever their
    /// interval says, as after a new User-Agent.
    private func refreshSubscriptionsIfDue(force: Bool = false) async {
        let used = Set(settings.directions.compactMap(\.connection))
        var changed = false
        for candidate in connections where used.contains(candidate.id) {
            guard let state = candidate.xray, let source = state.subscriptionURL,
                  force || Date().timeIntervalSince(state.updatedAt ?? .distantPast) >= state.updateInterval
            else { continue }
            do {
                let fetched = try await fetchSubscription(source, userAgent: userAgent(state))
                // Replaced or removed by the user while this was in flight: theirs wins.
                guard let index = connections.firstIndex(where: { $0.id == candidate.id }),
                      var current = connections[index].xray, current.subscriptionURL == source
                else { continue }
                current.apply(fetched, keeping: current.server)
                var updated = connections
                updated[index].xray = current
                try store(updated)
                changed = true
            } catch {
                record("Подписка Xray не обновилась: \((error as? RouterErrorInfo)?.message ?? error.localizedDescription)")
            }
        }
        // A server that left the list moves its routes to the subscription's first.
        if changed { await reconcileIfRunning() }
    }

    // MARK: - Settings

    private func update(_ newSettings: RouterSettings) async throws {
        // Checked before anything is kept: a rule that cannot be read must not
        // reach the disk.
        _ = try ruleSetFor(newSettings)
        var newSettings = newSettings
        newSettings.subscriptionUserAgent = try newSettings.subscriptionUserAgent.flatMap(XrayProfileParser.userAgent)
        var next = storedState()
        next.settings = newSettings
        try next.save()
        let changed = newSettings != settings
        let agentChanged = newSettings.subscriptionUserAgent != settings.subscriptionUserAgent
        settings = newSettings
        // A provider may hand out another list for another client.
        if agentChanged { Task { await refreshSubscriptionsIfDue(force: true) } }
        guard changed else {
            // The app re-sends its settings on each launch: nothing to redo.
            refreshEndpointRuleSet()
            return
        }
        record("Изменены направления")
        await reconcileIfRunning()
    }

    private func setEnabled(_ enabled: Bool) async throws {
        // «Выключить» must also disarm the wish a failed automatic start left behind.
        if enabled ? status.desiredEnabled : (!status.desiredEnabled && !enabledByUser) { return }
        if enabled {
            status.desiredEnabled = true
            try await startRuntimeOrRollBack()
        } else {
            await stopRuntime(preserveDesiredState: false)
        }
        // Remembered only once it took effect: a failed «Включить» must not arm
        // a start later, on some network where nobody expects it.
        enabledByUser = enabled
        do { try storedState().save() }
        catch { record("Не удалось сохранить состояние: включение не переживёт перезапуск демона") }
    }

    /// «Включить» outlives the daemon: after a crash or a reboot the first path
    /// update brings protection back without the app. A start that failed is
    /// retried only on a genuinely different network — our own DNS and PF changes
    /// produce path updates too, and retrying on those would never stop.
    private func resumeIfWanted() async {
        guard enabledByUser, !startingRuntime,
              let identity = (try? NetworkSnapshot.capture(using: runner))?.routingIdentity,
              identity != lastResumeIdentity
        else { return }
        lastResumeIdentity = identity
        record("Восстановление включённой маршрутизации")
        status.desiredEnabled = true
        do { try await startRuntimeOrRollBack() }
        catch {
            status.lastError = error as? RouterErrorInfo ?? .init(.routingFailure, error.localizedDescription)
            status.protection = .error
        }
    }

    // MARK: - Tunnels

    /// What each route that is on and has a VPN runs, by tunnel id. Routes on
    /// one VPN and server share one tunnel.
    private func desiredTunnels() -> [String: TunnelPlan] {
        var plans: [String: TunnelPlan] = [:]
        for direction in settings.activeDirections {
            guard let plan = plan(for: direction) else { continue }
            if let known = plans[plan.id] { plans[plan.id]?.title = known.title + ", " + direction.name }
            else { plans[plan.id] = plan }
        }
        return plans
    }

    private func plan(for direction: Direction) -> TunnelPlan? {
        guard let id = direction.connection, let stored = connection(id) else { return nil }
        if let payload = stored.openVPN, let profile = openProfiles[id] {
            let configuration = profile.configuration(preferring: stored.preferredRemote)
            return .init(
                id: id.uuidString, connection: id, title: direction.name,
                engine: .openVPN(configuration, .init(username: payload.username, password: payload.password)),
                hosts: profile.remoteHosts, dnsServers: [], supportsIPv6: false,
                fingerprint: [configuration, payload.username ?? "", payload.password ?? ""].joined(separator: "\u{0}"),
                staticRoutes: profile.staticRoutes
            )
        }
        if let payload = stored.amneziaWG, let profile = awgProfiles[id] {
            return .init(
                id: id.uuidString, connection: id, title: direction.name, engine: .amneziaWG(profile),
                hosts: [profile.endpointHost], dnsServers: profile.dnsServers, supportsIPv6: profile.supportsIPv6,
                fingerprint: payload.configuration
            )
        }
        if let state = stored.xray, let server = state.server(for: direction.server) {
            // Every server of the subscription is direct, not only this one: the
            // app pings them all, and through the tunnel that would time the tunnel.
            return .init(
                id: "\(id.uuidString)|\(server.host)|\(server.port)|\(server.protocolName)|\(server.name)", connection: id, title: direction.name,
                engine: .xray(server), hosts: state.servers.map(\.host),
                // Xray brings no resolver of its own, so it gets the two public ones.
                dnsServers: ["1.1.1.1", "8.8.8.8"], supportsIPv6: false,
                fingerprint: server.outbounds, subscriptionHost: state.subscriptionURL.flatMap(URL.init(string:))?.host
            )
        }
        return nil
    }

    private func title(_ id: String) -> String { running[id].map { "«\($0.title)»" } ?? "Туннель" }

    private func start(_ plan: TunnelPlan) async throws {
        running[plan.id] = plan
        let title = plan.title
        switch plan.engine {
        case .openVPN(let configuration, let credentials):
            try tunnels.startOpenVPN(id: plan.id, title: title, configuration: configuration, credentials: credentials)
        case .amneziaWG(let profile):
            _ = try await tunnels.startAmneziaWG(id: plan.id, title: title, profile: profile)
        case .xray(let server):
            guard let physical = snapshot?.physicalInterface else {
                throw RouterErrorInfo(.routingFailure, "Нет подключения к сети для «\(title)»")
            }
            _ = try await tunnels.startXray(id: plan.id, title: title, server: server, physicalInterface: physical)
        }
    }

    /// OpenVPN first: it only launches, while the others wait for their interface.
    private func startTunnels(_ plans: [TunnelPlan], generation started: Int) async throws {
        for plan in plans.sorted(by: { $0.isOpenVPN && !$1.isOpenVPN }) {
            guard generation == started else { throw CancellationError() }
            tunnelStatus[plan.id] = .init(phase: .connecting)
            do { try await start(plan) }
            catch is CancellationError {
                // Stopped while it came up; whoever stopped it has already said why.
            } catch {
                guard generation == started else { throw CancellationError() }
                await tunnelFailed(plan.id, error as? RouterErrorInfo ?? .init(.tunnelFailure, error.localizedDescription, recoverable: true))
            }
        }
    }

    /// Brings what runs in line with the routes, touching only what changed:
    /// a tunnel stops when no route that is on needs it any more, or when what
    /// it would run is different now — another profile, server or password.
    /// Everything else keeps its connections; a rule change only moves routes.
    private func reconcileIfRunning() async {
        guard status.desiredEnabled else { return }
        // Mid-start, or not up at all: only a fresh start gets everything right.
        guard !startingRuntime, policy != nil else {
            await stopRuntime(preserveDesiredState: true)
            // As on a network change: the app needs the reason, not a bare «Ошибка».
            do { try await startRuntimeOrRollBack() }
            catch {
                status.lastError = error as? RouterErrorInfo ?? .init(.routingFailure, error.localizedDescription)
                status.protection = .error
            }
            return
        }
        let started = generation
        let desired = desiredTunnels()
        for (id, plan) in running where desired[id]?.fingerprint != plan.fingerprint {
            record("\(title(id)): остановлен — \(desired[id] == nil ? "больше не нужен" : "профиль изменился")")
            forget(id)
        }
        // A kept tunnel carrying renamed routes keeps its connection, not its name.
        for (id, plan) in desired where running[id] != nil { running[id]?.title = plan.title }
        let fresh = desired.values.filter { running[$0.id] == nil }
        var resolved: Set<String> = []
        if !fresh.isEmpty {
            resolved = await Self.resolveEndpoints(fresh.flatMap(\.hosts))
            guard generation == started, policy != nil else { return }
        }
        refreshEndpointRuleSet()
        updateProtectionState()
        applyPolicyOrRecordError(addingControl: resolved)
        do { try await startTunnels(fresh, generation: started) } catch {}
    }

    private func forget(_ id: String) {
        tunnels.stop(id)
        retries.removeValue(forKey: id)?.cancel()
        retryAttempt[id] = nil
        running[id] = nil
        tunnelStatus[id] = nil
        pushed[id] = nil
    }

    private func startRuntime() async throws {
        let started = generation
        startingRuntime = true
        defer {
            // A superseded start leaves both to the teardown and to its replacement.
            if generation == started {
                startingRuntime = false
                // A path update that arrived mid-setup was deferred, not dropped.
                if missedNetworkChange {
                    missedNetworkChange = false
                    Task { [weak self] in await self?.networkChanged() }
                }
            }
        }
        for direction in settings.activeDirections {
            switch direction.path {
            case .direct: continue
            case .unset: throw RouterErrorInfo(.invalidConfiguration, "Для направления «\(direction.name)» не выбран VPN")
            case .vpn:
                guard plan(for: direction) != nil else {
                    throw RouterErrorInfo(.invalidConfiguration, "Профиль VPN направления «\(direction.name)» не найден: выберите другой или добавьте его на странице «VPN»")
                }
            }
        }
        let desired = desiredTunnels()
        guard !desired.isEmpty else {
            throw RouterErrorInfo(.invalidConfiguration, "Ни одно включённое направление не идёт через VPN")
        }
        guard !NetworkSnapshot.hasConflictingVPN(using: runner) else {
            throw RouterErrorInfo(.conflictingVPN, "Отключите сторонний VPN перед запуском Коммутатора")
        }
        // Endpoint resolution below can take tens of seconds on a bad network, and
        // the XPC reply only lands when everything is up, so the polled status is
        // the only thing the user has to tell «работает» from «зависло».
        status.protection = .starting
        let captured = try NetworkSnapshot.capture(using: runner)
        snapshot = captured
        record("Сеть: \(captured.physicalInterface), шлюз \(captured.ipv4Gateway ?? "—"), DNS-серверов — \(captured.dnsServers.count), локальных сетей — \(captured.lanNetworks.count)")
        // Without a gateway the direct and control classes get no route, fall into
        // the default halves and are dropped by their own block rule — an outage
        // that otherwise leaves no trace anywhere.
        if captured.ipv4Gateway == nil { record("Нет IPv4-шлюза по умолчанию: прямой трафик будет заблокирован") }
        if defaultPlan()?.supportsIPv6 == true, captured.ipv6Gateway == nil {
            record("Нет IPv6-шлюза по умолчанию: прямой IPv6-трафик будет заблокирован")
        }
        for plan in desired.values { tunnelStatus[plan.id] = .init(phase: .connecting) }
        ruleSet = try ruleSetFor(settings)
        var base = PolicyState(snapshot: captured)
        base.control.formUnion(captured.dnsServers)
        // Every subscription server's bare address too: the app pings them all
        // past the tunnel. Names get there through their endpoint rules; an
        // address has no name to be looked up by.
        // ponytail: an address a later refresh adds waits for the next start.
        base.control.formUnion(await Self.resolveEndpoints(desired.values.flatMap(\.hosts)))
        guard generation == started else { throw CancellationError() }
        let initial = computedPolicy(from: base)
        policy = initial

        upstreams.update(upstreamPlan())
        let proxy = DNSProxy(
            upstreams: upstreams,
            didReceiveResponse: { [weak self] data, domain in await self?.receivedDNS(data, domain: domain) }
        )
        // Held before it binds, so a teardown that runs while it does stops it too.
        dnsProxy = proxy
        do { try await proxy.start() }
        catch {
            guard generation == started else { throw CancellationError() }
            throw RouterErrorInfo(
                .dnsFailure,
                "Не удалось занять 127.0.0.1:\(DNSProxy.port.rawValue) под локальный DNS — вероятно, порт занят другим резолвером: \(error.localizedDescription)"
            )
        }
        guard generation == started else { throw CancellationError() }
        record("DNS-прокси слушает 127.0.0.1:\(DNSProxy.port.rawValue)")
        try resolvers.apply(suffixes: ruleSet.domainSuffixes, port: DNSProxy.port.rawValue, systemDNSService: systemDNSService())
        record("Резолверы перенастроены: доменных правил — \(ruleSet.domainSuffixes.count)")
        try pf.apply(initial)
        record("PF применён: направлений \(initial.lanes.count), control \(initial.control.count)")
        try routes.reconcile(initial)
        record("Маршруты применены")
        status.protection = .starting
        record("Маршрутизация включена: " + settings.activeDirections.map { "«\($0.name)»" }.joined(separator: ", "))
        try await startTunnels(Array(desired.values), generation: started)
        guard generation == started else { throw CancellationError() }
        startMaintenance()
    }

    private func stopRuntime(preserveDesiredState: Bool) async {
        generation += 1
        startingRuntime = false
        retries.values.forEach { $0.cancel() }
        retries.removeAll()
        // A fresh runtime deserves a fresh backoff: otherwise the first failure
        // after a network change waits the sixty seconds the old one had reached.
        retryAttempt.removeAll()
        maintenance?.cancel(); maintenance = nil
        // Hand the system its own resolver back before the proxy stops answering,
        // otherwise it briefly points at a dead 127.0.0.1.
        resolvers.cleanup()
        dnsProxy?.stop(); dnsProxy = nil
        record("Резолверы и DNS-прокси возвращены системе")
        tunnels.stopAll()
        routes.cleanup()
        pf.cleanup()
        record("Маршруты сняты, PF-анкер очищен")
        policy = nil
        dynamic.removeAll()
        running.removeAll()
        tunnelStatus.removeAll()
        pushed.removeAll()
        status = RouterStatus(
            protection: preserveDesiredState ? .starting : .off,
            desiredEnabled: preserveDesiredState,
            lastError: status.lastError
        )
        record("Маршрутизация выключена")
    }

    private func tunnelStatus(_ id: String, _ newStatus: TunnelStatus) async {
        // A supervisor callback can land after the runtime it belongs to was torn
        // down, which left the UI showing a tunnel as connected under "Выключен".
        guard status.desiredEnabled, let plan = running[id] else { return }
        let old = tunnelStatus[id] ?? .init()
        let previous = old.phase
        var newStatus = newStatus
        // Health checks re-report "connected" every few seconds, and «Подключён с»
        // is about when the tunnel came up, not about the latest check.
        if newStatus.phase == old.phase, newStatus.interfaceName == old.interfaceName { newStatus.changedAt = old.changedAt }
        tunnelStatus[id] = newStatus
        if newStatus.phase == .connected { retryAttempt[id] = 0 }
        // The subscription host is routed direct only while its tunnels are down
        // (see endpointHosts); a connect or a drop is the one moment that route
        // needs to flip, not every re-reported "connected" tick.
        if plan.subscriptionHost != nil, (previous == .connected) != (newStatus.phase == .connected) {
            refreshEndpointRuleSet()
        }
        updateProtectionState()
        applyPolicyOrRecordError()
        // Health checks re-report "connected" every ten seconds, and journalling
        // each one buried every other event under the same line.
        if newStatus.phase != previous { record("\(title(id)): \(newStatus.phase.rawValue)") }
    }

    private func tunnelFailed(_ id: String, _ error: RouterErrorInfo) async {
        guard status.desiredEnabled, let plan = running[id] else { return }
        record("\(title(id)) не работает: \(error.message)\(error.recoverable ? "" : " (без повторов)")")
        tunnels.stop(id)
        let wasConnected = tunnelStatus[id]?.phase == .connected
        tunnelStatus[id] = .init(phase: .error, message: error.message)
        // Same route flip as a normal drop (see endpointHosts): the subscription
        // host must go back to direct once its own tunnel is down.
        if wasConnected, plan.subscriptionHost != nil { refreshEndpointRuleSet() }
        status.lastError = error
        updateProtectionState()
        try? rebuildPolicy()
        guard error.recoverable else { return }
        let attempt = retryAttempt[id, default: 0]
        // A dead subscription server would otherwise be retried forever with no
        // sign it is hopeless; give up after maxXrayRetries and say so.
        if case .xray = plan.engine, attempt >= maxXrayRetries {
            let message = exhaustedRetriesMessage(plan)
            record(message)
            tunnelStatus[id]?.message = message
            return
        }
        retryAttempt[id] = attempt + 1
        let delay = [1, 2, 5, 10, 30, 60][min(attempt, 5)]
        record("\(title(id)): повтор через \(delay) с (попытка \(attempt + 1))")
        let started = generation
        retries[id]?.cancel()
        retries[id] = Task { [weak self] in
            // A cancelled sleep returns at once: carrying on here retried
            // immediately, on exactly the runtime the cancel came from.
            guard (try? await Task.sleep(for: .seconds(delay))) != nil else { return }
            await self?.retry(id, generation: started)
        }
    }

    /// Named by server where one exists: a subscription can list many, and only
    /// the one that was actually dialled is the dead end here.
    private func exhaustedRetriesMessage(_ plan: TunnelPlan) -> String {
        if case .xray(let server) = plan.engine, !server.name.isEmpty {
            return "Сервер «\(server.name)» не отвечает после \(maxXrayRetries + 1) попыток. Выберите другой сервер для «\(plan.title)» или подключите VPN снова."
        }
        return "«\(plan.title)»: VPN не отвечает после \(maxXrayRetries + 1) попыток. Проверьте профиль и сеть, затем подключите снова."
    }

    private func retry(_ id: String, generation started: Int) async {
        guard status.desiredEnabled, generation == started, let planned = desiredTunnels()[id] else { return }
        // A server's address can rotate between attempts, and one that is missing
        // from <control> is dropped by the anchor's final "block drop out quick all".
        // The set only grows: a stale endpoint address costs one extra pass rule.
        let resolved = await Self.resolveEndpoints(planned.hosts)
        // Editing or switching off a route cancels this task and forgets the
        // tunnel without touching `generation`; and the plan is read again, so
        // that what was edited meanwhile is what starts.
        guard !Task.isCancelled, generation == started, let plan = desiredTunnels()[id] else { return }
        if let current = policy, !resolved.isSubset(of: current.control) {
            applyPolicyOrRecordError(addingControl: resolved)
        }
        do {
            tunnelStatus[id] = .init(phase: .reconnecting)
            try await start(plan)
        } catch is CancellationError {
            // Stopped while it came up; whoever stopped it has already said why.
        } catch {
            guard !Task.isCancelled, generation == started else { return }
            await tunnelFailed(id, error as? RouterErrorInfo ?? .init(.tunnelFailure, error.localizedDescription, recoverable: true))
        }
    }

    private func receivedPush(_ id: String, _ options: PushedOptions) async {
        guard status.desiredEnabled, let plan = running[id] else { return }
        let received = PushedOptions(
            routes: Array(Set(options.routes)).sorted(),
            dns: Array(Set(options.dns)).sorted(),
            domains: Array(Set(options.domains.compactMap(RuleSet.normalizeDomain))).sorted(),
            receivedAt: Date()
        )
        pushed[id] = received
        // Kept for «Маршруты» after the VPN is off; routing only ever uses what
        // this session's server sent.
        if let index = connections.firstIndex(where: { $0.id == plan.connection }) {
            var updated = connections
            updated[index].pushed = received
            try? store(updated)
        }
        refreshEndpointRuleSet()
        applyPolicyOrRecordError()
    }

    // MARK: - Rules, DNS and policy

    /// Each route's own rules, and for OpenVPN the domains its server sent.
    private func ruleSetFor(_ settings: RouterSettings) throws -> RuleSet {
        let lists = settings.activeDirections.map { direction -> (UUID, [RoutingRule]) in
            guard let plan = plan(for: direction), plan.isOpenVPN else { return (direction.id, direction.rules) }
            return (direction.id, direction.rules + (pushed[plan.id]?.domains ?? []).map { .init(kind: .domain, value: $0) })
        }
        return try RuleSet(lists: lists, endpoints: endpointHosts())
    }

    /// Rebuilding the domain rules is how a change in what they route actually
    /// takes effect: new pushed domains, a subscription host flipping, routes
    /// edited.
    private func refreshEndpointRuleSet() {
        do { ruleSet = try ruleSetFor(settings) }
        catch { record("Домены отклонены: \((error as? RouterErrorInfo)?.code.rawValue ?? "internalError")") }
        guard status.desiredEnabled, policy != nil else { return }
        try? resolvers.apply(suffixes: ruleSet.domainSuffixes, port: DNSProxy.port.rawValue, systemDNSService: systemDNSService())
    }

    /// The VPN servers' own names must resolve over the network's DNS: their
    /// tunnels are exactly what is not up when we need to reach them.
    private func endpointHosts() -> [String] {
        let plans = desiredTunnels().values
        var hosts = plans.flatMap(\.hosts)
        // A subscription refresh must work while the tunnels it feeds are down —
        // but once one is up, the panel is very often blocked outside it (that's
        // usually why a VPN is in use at all), so from then on the address rides
        // the tunnel like everything else with no explicit rule.
        for (connection, group) in Dictionary(grouping: plans, by: \.connection) {
            guard let host = group.first?.subscriptionHost,
                  !running.values.contains(where: { $0.connection == connection && tunnelStatus[$0.id]?.phase == .connected })
            else { continue }
            hosts.append(host)
        }
        var seen = Set<String>()
        return hosts
            .filter { IPAddress($0) == nil }
            .compactMap(RuleSet.normalizeDomain)
            .filter { seen.insert($0).inserted }
    }

    private func receivedDNS(_ data: Data, domain: String) async {
        guard let message = try? DNSMessage.parse(data) else { return }
        // ponytail: dropped wholesale at the cap; an LRU if names go missing mid-browse.
        if recentNames.count > 5000 { recentNames.removeAll() }
        for record in message.addresses { recentNames[record.address] = domain }
        // Now that every system query passes through here, only names that need a
        // table entry are worth tracking; the rest already ride the default route.
        guard ruleSet.classify(domain: domain) != nil else { return }
        let expiry = Date().addingTimeInterval(Self.bindingLifetime)
        for record in message.addresses { dynamic[record.address, default: [:]][domain] = expiry }
        applyPolicyOrRecordError()
    }

    private func applyPolicyOrRecordError(addingControl endpoints: Set<String> = []) {
        do { try rebuildPolicy(addingControl: endpoints) }
        catch {
            let wrapped = error as? RouterErrorInfo ?? .init(.routingFailure, error.localizedDescription)
            status.lastError = wrapped
            status.protection = .error
            record("Ошибка применения политики: \(wrapped.code.rawValue)")
        }
    }

    /// The tunnel carrying what no route claims, if a route that is on does.
    private func defaultPlan() -> TunnelPlan? { settings.activeDefault.flatMap(plan(for:)) }

    private func interface(of plan: TunnelPlan?) -> String? {
        guard let plan, let status = tunnelStatus[plan.id], status.phase == .connected else { return nil }
        return status.interfaceName
    }

    /// The policy the routes and the tunnels call for right now, on top of
    /// `base`'s snapshot and control list, which only ever grows.
    private func computedPolicy(from base: PolicyState) -> PolicyState {
        var next = base
        let now = Date()
        dynamic = dynamic.reduce(into: [:]) { kept, entry in
            // Still in use: an open connection keeps its route whatever the answer's age.
            let open = openAddresses.contains(entry.key)
            let bindings = entry.value.compactMapValues { expiry -> Date? in
                if expiry > now { return expiry }
                if open { return now.addingTimeInterval(Self.bindingLifetime) }
                // `openAddresses` is up to a tick old: a connection opened since the
                // last netstat lost its route under it. Kept until a tick has looked.
                return now.timeIntervalSince(expiry) < Self.maintenanceInterval ? expiry : nil
            }
            if !bindings.isEmpty { kept[entry.key] = bindings }
        }
        let active = settings.activeDirections
        var lanes: [UUID: PolicyLane] = [:]
        for direction in active {
            var lane = PolicyLane()
            let plan = plan(for: direction)
            lane.interface = direction.path == .direct ? nil : interface(of: plan)
            // Waiting for its VPN, a route may go direct if it allows that; one
            // with no VPN at all (.unset, or a profile gone) never does.
            lane.direct = direction.path == .direct || (plan != nil && lane.interface == nil && !direction.blockWhenDown)
            if let plan {
                if plan.isOpenVPN {
                    lane.addresses.formUnion(plan.staticRoutes + (pushed[plan.id]?.routes ?? []))
                    lane.addresses.formUnion(pushed[plan.id]?.dns ?? [])
                } else {
                    // Its resolvers live behind it: without a route there, a
                    // route's names would be asked through another one.
                    // ponytail: two routes naming one resolver share the higher one's tunnel for it.
                    lane.addresses.formUnion(plan.dnsServers)
                }
            }
            lanes[direction.id] = lane
        }
        for (network, id) in ruleSet.explicitNetworks { lanes[id]?.addresses.insert(network.description) }
        for (address, bindings) in dynamic {
            let matches = bindings.keys.compactMap { ruleSet.classify(domain: $0) }
            if matches.contains(.endpoint) { next.control.insert(address); continue }
            let winner = matches.compactMap { match -> UUID? in
                if case .direction(let id) = match { return id }
                return nil
            }.min { (ruleSet.rank(of: $0) ?? .max) < (ruleSet.rank(of: $1) ?? .max) }
            if let winner { lanes[winner]?.addresses.insert(address) }
        }
        next.lanes = active.compactMap { lanes[$0.id] }
        next.tunnels = Set(desiredTunnels().values.compactMap { interface(of: $0) }).sorted()
        if let chosen = settings.activeDefault, chosen.path != .direct {
            let plan = plan(for: chosen)
            next.defaultInterface = interface(of: plan)
            next.defaultSupportsIPv6 = plan?.supportsIPv6 ?? false
            next.directByDefault = next.defaultInterface == nil && !chosen.blockWhenDown
        } else {
            next.defaultInterface = nil
            next.defaultSupportsIPv6 = false
            next.directByDefault = true
        }
        return next
    }

    /// `endpoints` are server addresses to let through from now on. They go into
    /// the new policy, not into `policy` beforehand: then the comparison below
    /// saw nothing to change and PF never learnt them, dropping the handshake.
    private func rebuildPolicy(addingControl endpoints: Set<String> = []) throws {
        upstreams.update(upstreamPlan())
        guard let current = policy else { return }
        var base = current
        base.control.formUnion(endpoints)
        let next = computedPolicy(from: base)
        // Every DNS answer reaches this point, in the client's response path, so
        // an unchanged policy must not cost a PF reload and a route reconcile.
        guard next != current else { return }
        do {
            // Route-first is fail-closed: the currently loaded PF policy blocks every
            // newly routed class until its matching pass rule is installed.
            try routes.reconcile(next)
            try pf.apply(next)
            if next.tunnels != current.tunnels {
                record("Интерфейсы туннелей: \(next.tunnels.isEmpty ? "—" : next.tunnels.joined(separator: ", ")), остальное — \(next.defaultInterface ?? (next.directByDefault ? "напрямую" : "заблокировано"))")
            }
            policy = next
        } catch {
            try? routes.reconcile(current)
            try? pf.apply(current)
            throw error
        }
    }

    // Which server answers each route. A VPN's resolver only exists behind its
    // tunnel, so until that is up we return nothing and the proxy answers
    // SERVFAIL rather than leaking the name to the network's DNS — unless the
    // route lets its traffic go direct meanwhile.
    private func upstreamPlan() -> UpstreamTable.Plan {
        let network = Self.failover(snapshot?.dnsServers ?? [])
        func servers(_ direction: Direction) -> [String] {
            switch direction.path {
            case .direct: return network
            case .unset: return []
            case .vpn:
                let plan = plan(for: direction)
                guard let plan, tunnelStatus[plan.id]?.phase == .connected else { return direction.blockWhenDown ? [] : network }
                let own = plan.isOpenVPN ? pushed[plan.id]?.dns ?? [] : plan.dnsServers
                // No resolver of its own: the network's, or the route would not work at all.
                return own.isEmpty ? network : Self.failover(own)
            }
        }
        return .init(
            ruleSet: ruleSet,
            network: network,
            lanes: Dictionary(settings.activeDirections.map { ($0.id, servers($0)) }) { first, _ in first },
            rest: settings.activeDefault.map(servers) ?? network
        )
    }

    // Two is the whole failover budget: a third server only lengthens the wait
    // before the client is told SERVFAIL.
    private static func failover(_ servers: [String]) -> [String] { Array(servers.prefix(2)) }

    // networksetup speaks service names ("Wi-Fi"), not BSD interfaces ("en0").
    // The system resolver moves to the proxy only when what carries the rest
    // has a resolver of its own to send those names to.
    private func systemDNSService() -> String? {
        guard let plan = defaultPlan(), plan.isOpenVPN || !plan.dnsServers.isEmpty,
              let interface = snapshot?.physicalInterface
        else { return nil }
        guard let listing = try? runner.run("/usr/sbin/networksetup", ["-listnetworkserviceorder"]).stdout,
              let service = ResolverController.serviceName(forInterface: interface, in: listing)
        else {
            record("Не найден сетевой сервис для \(interface); системный DNS не переключён")
            return nil
        }
        return service
    }

    private func updateProtectionState() {
        var tunnels = desiredTunnels().keys.map { tunnelStatus[$0] ?? .init() }
        // A route that is on with no VPN to run is down, not missing.
        for direction in settings.activeDirections where direction.path != .direct && plan(for: direction) == nil {
            tunnels.append(.init(phase: .error))
        }
        status.protection = .evaluate(desiredEnabled: status.desiredEnabled, tunnels: tunnels)
        if status.protection == .protected { status.lastError = nil }
    }

    private func startMaintenance() {
        maintenance?.cancel()
        maintenance = Task { [weak self] in
            var previousTick = Date()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(Self.maintenanceInterval))
                let now = Date()
                // The clock keeps counting while the Mac sleeps, so an overlong gap
                // between ticks is the only sign of a wake the daemon gets when the
                // network came back looking exactly as it left.
                let gap = now.timeIntervalSince(previousTick)
                previousTick = now
                if gap > 90 { await self?.record("Похоже, был сон: \(Int(gap / 60)) мин без работы") }
                await self?.refreshOpenAddresses()
                await self?.applyPolicyOrRecordError()
                await self?.recordState()
            }
        }
    }

    /// One `netstat` every half minute, far cheaper than nettop: the peers
    /// connections still talk to keep their route past bindingLifetime.
    private func refreshOpenAddresses() {
        let output = (try? runner.run("/usr/sbin/netstat", ["-an"]))?.stdout ?? ""
        openAddresses = OpenConnections.remoteAddresses(output)
    }

    /// One line every half minute: what is up and how much each route holds.
    /// Counts only — the addresses behind them are the user's traffic.
    private func recordState() {
        guard let policy else { return }
        let routes = zip(settings.activeDirections, policy.lanes).map { direction, lane in
            let phase = plan(for: direction).flatMap { tunnelStatus[$0.id]?.phase.rawValue } ?? (direction.path == .direct ? "напрямую" : "—")
            return "«\(direction.name)» \(phase) \(lane.interface ?? "") \(lane.addresses.count)"
        }
        record("Состояние: защита \(status.protection.rawValue); \(routes.joined(separator: "; ")); control \(policy.control.count)")
    }

    // MARK: - Reporting

    /// The app cannot show a stored password, so it sends nil for "unchanged":
    /// neither a re-imported profile nor a login edit may wipe it.
    static func carryingCredentials(_ incoming: ProfilePayload, from stored: ProfilePayload?) -> ProfilePayload {
        var result = incoming
        if result.kind == .openVPN, result.password == nil { result.password = stored?.password }
        return result
    }

    /// Scripts and plugins run as root, so a profile carrying them needs an admin
    /// approval once. Its digest is remembered, which is also what lets a stored
    /// profile load again after a restart without asking.
    private static func parseOpenVPN(_ payload: ProfilePayload) throws -> OpenVPNProfile {
        let inspected = try OpenVPNProfileParser.parse(payload.configuration)
        guard !inspected.dangerousDirectives.isEmpty else { return inspected }
        let digest = SHA256.hash(data: Data(payload.configuration.utf8)).hex
        if !UnsafeProfileTrust.contains(digest) {
            guard let authorization = payload.unsafeAuthorization, AdminAuthorization.validate(authorization)
            else { throw RouterErrorInfo(.unsafeProfileNeedsApproval, "Профиль содержит scripts/plugins и требует подтверждения администратора") }
            try UnsafeProfileTrust.add(digest)
        }
        return try OpenVPNProfileParser.parse(payload.configuration, allowUnsafe: true)
    }

    private func storedState() -> StoredState {
        .init(connections: connections, settings: settings, enabled: enabledByUser, bootTime: StoredState.currentBoot)
    }

    private func reported() -> RouterStatus {
        var result = status
        // The switch shows the wish, not only the runtime: after a failed automatic
        // start it stays on, so that switching it off is what disarms the next one.
        result.desiredEnabled = status.desiredEnabled || enabledByUser
        result.tunnels = [:]
        for direction in settings.activeDirections where direction.path != .direct {
            guard let plan = plan(for: direction) else {
                result.tunnels[direction.id] = .init(phase: .error, message: direction.path == .unset ? "VPN не выбран" : "Профиль VPN не найден")
                continue
            }
            var tunnel = tunnelStatus[plan.id] ?? .init()
            if plan.isOpenVPN {
                // Something that answers from inside the work network, for the
                // app's check that the tunnel itself carries traffic.
                tunnel.probeAddress = pushed[plan.id]?.dns.first { !$0.contains(":") }
            }
            result.tunnels[direction.id] = tunnel
        }
        result.connections = connections.compactMap(summary)
        return result
    }

    private func summary(_ stored: StoredConnection) -> ConnectionSummary? {
        if let payload = stored.openVPN {
            let profile = openProfiles[stored.id]
            let remote = profile.flatMap { $0.remotes.first { $0 == stored.preferredRemote } ?? $0.remotes.first }
            return .init(
                id: stored.id, kind: .openVPN, title: remote?.host ?? "Профиль OpenVPN", protocolTitle: "OpenVPN",
                needsLogin: profile?.requiresCredentials ?? false, username: payload.username,
                hasPassword: !(payload.password ?? "").isEmpty, remotes: profile?.remotes, preferredRemote: stored.preferredRemote,
                pushed: stored.pushed, profileRoutes: profile?.staticRoutes
            )
        }
        if stored.amneziaWG != nil {
            let profile = awgProfiles[stored.id]
            return .init(id: stored.id, kind: .amneziaWG, title: profile?.endpointHost ?? "Профиль AmneziaWG", protocolTitle: profile?.protocolTitle)
        }
        if let state = stored.xray {
            return .init(id: stored.id, kind: .xray, title: state.label, protocolTitle: state.profileProtocolTitle, xray: state.summary)
        }
        return nil
    }

    // Blocking the actor here would deadlock once the proxy is the system
    // resolver: getaddrinfo waits for an answer whose delivery needs the actor.
    /// In parallel: a subscription brings every one of its servers, and resolved
    /// one by one on a slow network each lookup's timeout held the start in turn.
    /// GCD threads, not the task pool: getaddrinfo blocks.
    private static func resolveEndpoints(_ hosts: [String]) async -> Set<String> {
        let unique = Array(Set(hosts))
        return await Task.detached {
            let found = OSAllocatedUnfairLock(initialState: Set<String>())
            DispatchQueue.concurrentPerform(iterations: unique.count) { index in
                let addresses = HostResolver.addresses(unique[index])
                found.withLock { $0.formUnion(addresses) }
            }
            return found.withLock { $0 }
        }.value
    }

    private func decodePayload<T: Decodable>(_ request: IPCRequest) throws -> T {
        guard let payload = request.payload else { throw RouterErrorInfo(.invalidConfiguration, "Отсутствует payload") }
        return try IPCCodec.decoder.decode(T.self, from: payload)
    }

    private func response<T: Encodable>(_ value: T) throws -> IPCResponse {
        .init(payload: try IPCCodec.encoder.encode(value))
    }

    /// This Mac to a subscription's device limit: stable across reinstalls, so
    /// it never takes a second slot, but not the hardware UUID itself.
    private static let deviceID: String = {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(service) }
        let platform = IORegistryEntryCreateCFProperty(service, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String ?? UUID().uuidString
        return SHA256.hash(data: Data("vpnrouter-hwid:\(platform)".utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
    }()

    /// Errors never carry the address: its token is the subscription's password.
    private func fetchSubscription(_ address: String, userAgent: String?) async throws -> XraySubscription {
        guard let url = URL(string: address), url.scheme?.lowercased() == "https", url.host != nil else {
            throw RouterErrorInfo(.invalidConfiguration, "Некорректный адрес подписки")
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue(userAgent ?? XrayProfileParser.defaultUserAgent, forHTTPHeaderField: "User-Agent")
        // Panels with a device limit (Remnawave) give a client without one a placeholder server.
        request.setValue(Self.deviceID, forHTTPHeaderField: "x-hwid")
        request.setValue("macOS", forHTTPHeaderField: "x-device-os")
        let os = ProcessInfo.processInfo.operatingSystemVersion
        request.setValue("\(os.majorVersion).\(os.minorVersion)", forHTTPHeaderField: "x-ver-os")
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch let error as URLError {
            let message: String
            switch error.code {
            case .timedOut: message = "Сервер подписки не ответил за 15 секунд"
            case .notConnectedToInternet, .networkConnectionLost: message = "Нет подключения к интернету"
            case .cannotFindHost, .cannotConnectToHost: message = "Не удалось подключиться к серверу подписки"
            default: message = "Не удалось загрузить подписку"
            }
            throw RouterErrorInfo(.invalidConfiguration, message)
        } catch {
            throw RouterErrorInfo(.invalidConfiguration, "Не удалось загрузить подписку")
        }
        guard let http = response as? HTTPURLResponse else {
            throw RouterErrorInfo(.invalidConfiguration, "Сервер подписки не ответил по HTTP")
        }
        if http.value(forHTTPHeaderField: "x-hwid-max-devices-reached") == "true" {
            throw RouterErrorInfo(.invalidConfiguration, "Подписка: достигнут лимит устройств. Удалите лишнее устройство в личном кабинете провайдера")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RouterErrorInfo(.invalidConfiguration, "Сервер подписки ответил \(http.statusCode)")
        }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String { headers[key.lowercased()] = value }
        }
        let fetched = try XrayProfileParser.subscription(body: String(decoding: data, as: UTF8.self), headers: headers)
        // A placeholder next to servers we cannot run looks like a placeholder alone.
        if !fetched.skipped.isEmpty {
            record("Подписка Xray: серверов — \(fetched.servers.count), пропущено — \(fetched.skipped.count): \(Set(fetched.skipped).sorted().joined(separator: "; "))")
        }
        return fetched
    }

    /// Replaces the app and this daemon from a downloaded pkg, with no password:
    /// only a client signed as Commutator can ask, and only an app signed the
    /// same way and newer than this daemon is installed. The pkg's own scripts
    /// never run, every root step comes from the verified bundle. They run as a
    /// launchd job of their own: installing boots this daemon out, and a child
    /// of it would go down with it.
    private func installUpdate(_ package: String) throws {
        guard ProcessInfo.processInfo.environment["VPNROUTER_ALLOW_UNSIGNED"] != "1",
              let requirement = ListenerDelegate.clientRequirement()
        else { throw RouterErrorInfo(.permissionDenied, "Эту сборку Коммутатора можно обновить только вручную, из pkg") }
        // A second click while the first install runs would boot it out halfway.
        if let job = try? runner.run("/bin/launchctl", ["print", "system/" + Self.updateLabel]), job.stdout.contains("state = running") {
            throw RouterErrorInfo(.internalError, "Обновление уже устанавливается")
        }
        // Only a plain file: through a link the user could swap what was checked.
        guard (try? FileManager.default.attributesOfItem(atPath: package)[.type] as? FileAttributeType) == .typeRegular else {
            throw RouterErrorInfo(.invalidConfiguration, "Скачанное обновление не найдено")
        }
        // Root-only, so nothing is swapped between the check and the install.
        let work = StoredState.directory.appendingPathComponent("update", isDirectory: true)
        try? FileManager.default.removeItem(at: work)
        var started = false
        defer { if !started { try? FileManager.default.removeItem(at: work) } }
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let copy = work.appendingPathComponent("Commutator.pkg").path
        try FileManager.default.copyItem(atPath: package, toPath: copy)
        let expanded = work.appendingPathComponent("expanded").path
        try runner.checked("/usr/sbin/pkgutil", ["--expand-full", copy, expanded])
        // Our bundle has no links. One in the payload could point the check at
        // a folder the user owns and swap the script in it before it runs.
        let links = try runner.checked("/usr/bin/find", [expanded, "-type", "l"])
        guard links.stdout.isEmpty else {
            throw RouterErrorInfo(.permissionDenied, "В обновлении есть символические ссылки, установка отменена")
        }
        let app = expanded + "/Payload/Commutator.app"
        guard try runner.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R", "=" + requirement, app]).status == 0 else {
            throw RouterErrorInfo(.permissionDenied, "Подпись обновления не совпадает с установленной версией")
        }
        // A downgrade would bring back whatever a newer version fixed.
        guard let version = NSDictionary(contentsOfFile: app + "/Contents/Info.plist")?["CFBundleShortVersionString"] as? String,
              VPNRouterVersion.isNewer(version, than: VPNRouterVersion.current)
        else { throw RouterErrorInfo(.invalidConfiguration, "Обновление не новее установленной версии") }
        // No LaunchOnlyOnce: that is once per boot, and would keep a second
        // update before a reboot from running. Without KeepAlive it runs once anyway.
        let job: [String: Any] = [
            "Label": Self.updateLabel,
            "ProgramArguments": ["/bin/zsh", app + "/Contents/Resources/install-update.sh", app, work.path],
            "RunAtLoad": true,
        ]
        let plist = work.appendingPathComponent("job.plist")
        try PropertyListSerialization.data(fromPropertyList: job, format: .xml, options: 0).write(to: plist)
        // The previous update's job stays loaded, finished, until a reboot.
        _ = try? runner.run("/bin/launchctl", ["bootout", "system/" + Self.updateLabel])
        try runner.checked("/bin/launchctl", ["bootstrap", "system", plist.path])
        started = true
        record("Установка обновления \(version)")
    }

    private static let updateLabel = "com.vpnrouter.update"

    /// «Удалить Коммутатор…» without a password, for the same signed client
    /// that may install updates. The removal itself is uninstall.sh as a job of
    /// its own, after this daemon is gone: stopping, it logs and saves state,
    /// and would put back files removed while it still ran.
    private func uninstall(_ app: String) throws {
        guard ProcessInfo.processInfo.environment["VPNROUTER_ALLOW_UNSIGNED"] != "1",
              let requirement = ListenerDelegate.clientRequirement()
        else { throw RouterErrorInfo(.permissionDenied, "Эту сборку Коммутатора можно удалить только с паролем администратора") }
        // Root removes this folder, seconds after the check: only the one place
        // the installer uses, links resolved, so a swapped parent folder cannot
        // turn it into another app. A copy elsewhere is the user's own file.
        let installed = "/Applications/Commutator.app"
        guard URL(fileURLWithPath: app).resolvingSymlinksInPath().path == installed,
              try runner.run("/usr/bin/codesign", ["--verify", "-R", "=" + requirement, installed]).status == 0
        else { throw RouterErrorInfo(.permissionDenied, "Без пароля удаляется только Коммутатор из «Программ»") }
        // Installed next to the daemon, where only root writes: not run from the
        // bundle in /Applications, which any admin process can change.
        let script = "/Library/PrivilegedHelperTools/com.vpnrouter/uninstall.sh"
        guard FileManager.default.fileExists(atPath: script) else {
            throw RouterErrorInfo(.helperUnavailable, "Системный компонент установлен старой версией")
        }
        let job: [String: Any] = [
            "Label": Self.uninstallLabel,
            // The pause lets this reply reach the app before the script stops the daemon.
            "ProgramArguments": ["/bin/zsh", "-c", "sleep 1; exec /bin/zsh \"$0\" \"$1\"", script, installed],
            "RunAtLoad": true,
        ]
        let plist = StoredState.directory.appendingPathComponent("uninstall.plist")
        try FileManager.default.createDirectory(at: StoredState.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try PropertyListSerialization.data(fromPropertyList: job, format: .xml, options: 0).write(to: plist)
        _ = try? runner.run("/bin/launchctl", ["bootout", "system/" + Self.uninstallLabel])
        try runner.checked("/bin/launchctl", ["bootstrap", "system", plist.path])
        record("Удаление Коммутатора")
    }

    private static let uninstallLabel = "com.vpnrouter.uninstall"

    private func record(_ message: String) {
        TunnelLog.shared.write("router", message)
    }
}

/// What one tunnel runs: a VPN, and for a subscription one of its servers.
struct TunnelPlan {
    enum Engine {
        case openVPN(String, TunnelSupervisor.Credentials)
        case amneziaWG(AmneziaWGProfile)
        case xray(XrayServer)
    }

    /// The connection's id, and for Xray the server too: routes on one VPN
    /// and server share a tunnel, two servers of a subscription make two.
    let id: String
    let connection: UUID
    /// The names of the routes it carries, for the log and the messages.
    var title: String
    let engine: Engine
    /// Resolved into the pass list, and over the network's DNS.
    let hosts: [String]
    /// Asked through the tunnel. OpenVPN's arrive with its push instead.
    let dnsServers: [String]
    let supportsIPv6: Bool
    /// What it would run: a tunnel whose fingerprint changed is restarted.
    let fingerprint: String
    var staticRoutes: [String] = []
    var subscriptionHost: String?

    var isOpenVPN: Bool {
        if case .openVPN = engine { return true }
        return false
    }
}

/// A saved VPN as the daemon keeps it: exactly one of the three is set.
struct StoredConnection: Codable {
    var id: UUID
    var openVPN: ProfilePayload?
    var amneziaWG: ProfilePayload?
    var xray: XrayState?
    /// OpenVPN: the server tried first; nil keeps the profile's order.
    var preferredRemote: OpenVPNRemote?
    /// OpenVPN: what its server sent last time, for «Маршруты».
    var pushed: PushedOptions?
}

/// Everything the daemon needs to bring protection back on its own, secrets
/// included. Kept in a root-only directory: an atomic write's temporary file is
/// created with the default umask, readable for a moment before any chmod.
struct StoredState: Codable {
    var connections: [StoredConnection] = []
    var settings = RouterSettings()
    var enabled = false
    /// The boot this was saved in: a different one at launch means macOS started
    /// again, not just the daemon. Absent in a state from before it was kept.
    var bootTime: Int?
    /// Read from a state saved before routes, and not yet written back.
    var migrated = false

    private enum CodingKeys: String, CodingKey { case connections, settings, enabled, bootTime }
    /// Before routes: one work profile, one AmneziaWG, one Xray and the spares.
    private enum LegacyKeys: String, CodingKey { case openVPN, amneziaWG, xray, spares, settings }
    private struct LegacySettings: Decodable { var preferredOpenVPNRemote: OpenVPNRemote? }

    init(connections: [StoredConnection] = [], settings: RouterSettings = RouterSettings(), enabled: Bool = false, bootTime: Int? = nil) {
        self.connections = connections
        self.settings = settings
        self.enabled = enabled
        self.bootTime = bootTime
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        settings = try values.decodeIfPresent(RouterSettings.self, forKey: .settings) ?? RouterSettings()
        enabled = try values.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        bootTime = try values.decodeIfPresent(Int.self, forKey: .bootTime)
        if let connections = try values.decodeIfPresent([StoredConnection].self, forKey: .connections) {
            self.connections = connections
            return
        }
        // Under the fixed ids the settings' own migration points its routes at.
        let legacy = try decoder.container(keyedBy: LegacyKeys.self)
        var migrated: [StoredConnection] = []
        if let payload = try legacy.decodeIfPresent(ProfilePayload.self, forKey: .openVPN) {
            let old = try? legacy.decodeIfPresent(LegacySettings.self, forKey: .settings)
            migrated.append(.init(id: LegacyIDs.openVPN, openVPN: payload, preferredRemote: old?.preferredOpenVPNRemote))
        }
        if let payload = try legacy.decodeIfPresent(ProfilePayload.self, forKey: .amneziaWG) {
            migrated.append(.init(id: LegacyIDs.amneziaWG, amneziaWG: payload))
        }
        if let state = try legacy.decodeIfPresent(XrayState.self, forKey: .xray), !state.servers.isEmpty {
            migrated.append(.init(id: LegacyIDs.xray, xray: state))
        }
        for spare in try legacy.decodeIfPresent([SpareExit].self, forKey: .spares) ?? [] {
            migrated.append(.init(id: spare.id, amneziaWG: spare.amneziaWG, xray: spare.xray))
        }
        connections = migrated
        self.migrated = true
    }

    static var currentBoot: Int {
        var time = timeval()
        var size = MemoryLayout<timeval>.size
        sysctlbyname("kern.boottime", &time, &size, nil, 0)
        return time.tv_sec
    }

    static let directory = URL(fileURLWithPath: "/var/db/com.vpnrouter", isDirectory: true)
    static let url = directory.appendingPathComponent("state.json")

    static func load() -> StoredState {
        guard let data = try? Data(contentsOf: url),
              let state = try? IPCCodec.decoder.decode(StoredState.self, from: data)
        else { return .init() }
        return state
    }

    func save() throws {
        do {
            try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true)
            chmod(Self.directory.path, S_IRWXU)
            try IPCCodec.encoder.encode(self).write(to: Self.url, options: .atomic)
            chmod(Self.url.path, S_IRUSR | S_IWUSR)
        } catch {
            throw RouterErrorInfo(.internalError, "Не удалось сохранить профили: \(error.localizedDescription)")
        }
    }
}

private enum UnsafeProfileTrust {
    static let url = URL(fileURLWithPath: "/var/db/com.vpnrouter.trusted-profiles")

    static func contains(_ digest: String) -> Bool {
        (try? String(contentsOf: url, encoding: .utf8))?.components(separatedBy: .newlines).contains(digest) == true
    }

    static func add(_ digest: String) throws {
        var values = Set((try? String(contentsOf: url, encoding: .utf8))?.components(separatedBy: .newlines) ?? [])
        values.insert(digest)
        try (values.filter { !$0.isEmpty }.sorted().joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
        chmod(url.path, S_IRUSR | S_IWUSR)
    }
}

private enum AdminAuthorization {
    static func validate(_ data: Data) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { data.copyBytes(to: $0) }
        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, []) }
        return kAuthorizationRightExecute.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(authorization, &rights, nil, [.extendRights], nil) == errAuthorizationSuccess
            }
        }
    }
}

private extension SHA256.Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// The Xray exit's servers and where they came from. Stored with the profiles:
/// a subscription URL is as much a secret as a password.
struct XrayState: Codable {
    var subscriptionURL: String?
    var servers: [XrayServer] = []
    var selected = 0
    var title: String?
    var usedBytes: Int64?
    var totalBytes: Int64?
    var expiresAt: Date?
    var updatedAt: Date?
    var updateInterval: TimeInterval = 12 * 3600
    var userAgent: String?
    var announce: String?
    var supportURL: URL?
    var webPageURL: URL?

    var server: XrayServer? { servers.indices.contains(selected) ? servers[selected] : nil }

    /// A route's pick, while the list still has it; otherwise the one chosen
    /// here, which a subscription starts at its first.
    func server(for choice: ServerChoice?) -> XrayServer? {
        choice.flatMap { choice in servers.first { choice.matches(name: $0.name, host: $0.host, port: $0.port, protocolName: $0.protocolName) } } ?? server
    }

    /// A share-link profile can name its protocol. A subscription cannot: its
    /// server list may mix several protocols, so one label would be misleading.
    var profileProtocolTitle: String? {
        guard subscriptionURL == nil else { return nil }
        let titles = Set(servers.map {
            XraySummary.Server(name: $0.name, protocolName: $0.protocolName).protocolTitle
        })
        return titles.count == 1 ? titles.first : nil
    }

    /// Tells saved ones apart: several subscriptions may share a provider.
    var label: String {
        guard let subscriptionURL else { return "Ссылка" + (servers.first.map { " · \($0.name)" } ?? "") }
        return "Подписка" + (title.map { " «\($0)»" } ?? URL(string: subscriptionURL)?.host.map { " · \($0)" } ?? "")
    }

    /// A refreshed list keeps the chosen server if it is still in it.
    mutating func apply(_ fetched: XraySubscription, keeping current: XrayServer?) {
        servers = fetched.servers
        selected = current.flatMap { current in servers.firstIndex { $0.name == current.name && $0.host == current.host } } ?? 0
        title = fetched.title
        usedBytes = fetched.usedBytes
        totalBytes = fetched.totalBytes
        expiresAt = fetched.expiresAt
        updateInterval = fetched.updateInterval ?? 12 * 3600
        announce = fetched.announce
        supportURL = fetched.supportURL
        webPageURL = fetched.webPageURL
        updatedAt = Date()
    }

    var summary: XraySummary? {
        guard !servers.isEmpty else { return nil }
        return .init(
            servers: servers.map { .init(name: $0.name, protocolName: $0.protocolName, host: $0.host, port: $0.port) },
            selected: selected, title: title, fromSubscription: subscriptionURL != nil,
            updatedAt: updatedAt, usedBytes: usedBytes, totalBytes: totalBytes, expiresAt: expiresAt, userAgent: userAgent,
            announce: announce, supportURL: supportURL, webPageURL: webPageURL
        )
    }
}

/// A personal profile kept aside before routes; read only to migrate.
struct SpareExit: Codable {
    var id = UUID()
    var amneziaWG: ProfilePayload?
    var xray: XrayState?
}
