import CryptoKit
import Foundation
import IOKit
import Network
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
    private var ruleSet = try! RuleSet(rules: [])
    private var openPayload: ProfilePayload?
    private var awgPayload: ProfilePayload?
    private var openProfile: OpenVPNProfile?
    private var awgProfile: AmneziaWGProfile?
    private var snapshot: NetworkSnapshot?
    private var policy: PolicyState?
    private var status = RouterStatus()
    private var pushedRoutes: [String] = []
    private var pushedDNS: [String] = []
    private var pushedDomains: [String] = []
    private var dynamic: [String: [String: Date]] = [:]
    /// Recent DNS answers, address → the name asked, so the app's traffic view
    /// can show names where it only sees addresses. Memory only.
    private var recentNames: [String: String] = [:]
    private var retries: [VPNKind: Task<Void, Never>] = [:]
    private var retryAttempt: [VPNKind: Int] = [:]
    private var maintenance: Task<Void, Never>?
    private let upstreams = UpstreamTable()
    private var startingRuntime = false
    private var missedNetworkChange = false
    /// Bumped by every teardown. A start or a retry suspended across one finds out
    /// when it resumes and stops, instead of building on a runtime that is gone —
    /// XPC requests do run in the gaps of a start that is waiting on its tunnels.
    private var generation = 0
    /// How long an address stays bound to the name that classified it. Longer than
    /// most TTLs on purpose: a kept-alive connection outlives its record, and
    /// dropping its route mid-stream sent it into AmneziaWG, where it died.
    private static let bindingLifetime: TimeInterval = 3600
    /// The user's «Включить», which outlives the daemon; `status.desiredEnabled`
    /// is only whether the runtime is up right now.
    private var enabledByUser = false
    private var lastResumeIdentity: [String]?
    private var xray = XrayState()
    /// Personal profiles kept but not current: adding one never loses another.
    private var spares: [SpareExit] = []
    private var subscriptionUpdates: Task<Void, Never>?

    private lazy var tunnels = TunnelSupervisor(runner: runner, callbacks: .init(
        status: { [weak self] kind, tunnelStatus in Task { await self?.tunnelStatus(kind, tunnelStatus) } },
        pushedOptions: { [weak self] routes, dns, domains in Task { await self?.receivedPush(routes, dns, domains) } },
        failed: { [weak self] kind, error in Task { await self?.tunnelFailed(kind, error) } },
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
        if stored.bootTime != boot {
            if stored.enabled, !enabled {
                TunnelLog.shared.write("router", "Новая загрузка macOS: VPN не включается сам — приложение не открывается при входе")
            }
            var stamped = stored
            stamped.enabled = enabled
            stamped.bootTime = boot
            try? stamped.save()
        }
        if let payload = stored.openVPN, let profile = try? Self.parseOpenVPN(payload) {
            openPayload = payload
            openProfile = profile
        }
        if let payload = stored.amneziaWG, let profile = try? AmneziaWGProfileParser.parse(payload.configuration) {
            awgPayload = payload
            awgProfile = profile
        }
        xray = stored.xray ?? XrayState()
        spares = stored.spares ?? []
        Self.registerLogHosts(open: openProfile, awg: awgProfile, xray: xray)
    }

    /// The names this daemon works with, so the log can alias them instead of
    /// printing them. Everything else keeps its name: see `LogRedactor`.
    private static func registerLogHosts(open: OpenVPNProfile?, awg: AmneziaWGProfile?, xray: XrayState) {
        for remote in open?.remotes ?? [] { TunnelLog.shared.register(host: remote.host) }
        if let awg { TunnelLog.shared.register(host: awg.endpointHost) }
        for server in xray.servers { TunnelLog.shared.register(host: server.host) }
        if let host = xray.subscriptionURL.flatMap(URL.init(string:))?.host { TunnelLog.shared.register(host: host) }
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
                guard var payload = openPayload else {
                    throw RouterErrorInfo(.invalidConfiguration, "Сначала импортируйте профиль рабочего VPN")
                }
                payload.username = update.username
                payload.password = update.password
                try await replace(payload)
                return try response(reported())
            case .selectExit:
                let item: ExitItem = try decodePayload(request)
                status.lastError = nil
                try await selectExit(item)
                return try response(reported())
            case .deleteExit:
                let item: ExitItem = try decodePayload(request)
                status.lastError = nil
                try deleteExit(item)
                return try response(reported())
            case .getDiagnostics:
                let diagnostics = Diagnostics(
                    status: status,
                    physicalInterface: snapshot?.physicalInterface,
                    openVPNInterface: status.openVPN.interfaceName,
                    amneziaWGInterface: status.amneziaWG.interfaceName
                )
                return try response(diagnostics)
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
                guard let payload = asked.kind == .openVPN ? openPayload : awgPayload else {
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
    /// points at a proxy with no upstream for the AmneziaWG class, while PF and
    /// the routes that would make it work are not in place yet.
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

    // The app re-sends both profiles every time its UI starts, so an unchanged
    // profile must not cost a teardown and rebuild of a working connection.
    private func isUnchanged(_ payload: ProfilePayload) -> Bool {
        guard let stored = payload.kind == .openVPN ? openPayload : awgPayload else { return false }
        return stored.configuration == payload.configuration
            && stored.username == payload.username
            && stored.password == payload.password
    }

    private func replace(_ incoming: ProfilePayload) async throws {
        var payload = Self.carryingCredentials(incoming, from: openPayload)
        guard !isUnchanged(payload) else { return }
        // Saved before it takes effect: the app keeps no copy any more, so a
        // profile that only ever lived in memory is one restart from being lost.
        var next = storedState()
        switch payload.kind {
        case .openVPN:
            let profile = try Self.parseOpenVPN(payload)
            // A one-time approval, already turned into a remembered digest above.
            payload.unsafeAuthorization = nil
            next.openVPN = payload
            try next.save()
            openProfile = profile
            openPayload = payload
        case .amneziaWG:
            let profile = try AmneziaWGProfileParser.parse(payload.configuration)
            if payload.keepPrevious == true {
                next.spares = spares.filter { $0.amneziaWG?.configuration != payload.configuration }
                if let awgPayload { next.spares?.append(.init(amneziaWG: awgPayload)) }
            }
            payload.keepPrevious = nil
            next.amneziaWG = payload
            try next.save()
            spares = next.spares ?? []
            awgProfile = profile
            awgPayload = payload
        }
        record("Обновлён профиль \(payload.kind.title)")
        Self.registerLogHosts(open: openProfile, awg: awgProfile, xray: xray)
        if status.desiredEnabled {
            await stopRuntime(preserveDesiredState: true)
            try await startRuntimeOrRollBack()
        }
    }

    private func update(_ newSettings: RouterSettings) async throws {
        guard newSettings.useOpenVPN || newSettings.useAmneziaWG else {
            throw RouterErrorInfo(.invalidConfiguration, "Включите хотя бы один VPN")
        }
        let tunnelsChanged = newSettings.useOpenVPN != settings.useOpenVPN || newSettings.useAmneziaWG != settings.useAmneziaWG
            || newSettings.exitEngine != settings.exitEngine
        let rulesChanged = Self.routing(currentRules(newSettings)) != Self.routing(currentRules())
        let firstServerChanged = newSettings.preferredOpenVPNRemote != settings.preferredOpenVPNRemote
        let newRuleSet = try RuleSet(rules: currentRules(newSettings), endpoints: endpointHosts())
        if newSettings.killSwitch != settings.killSwitch { record("Kill switch: \(newSettings.killSwitch ? "включён" : "выключен")") }
        var next = storedState()
        next.settings = newSettings
        try next.save()
        settings = newSettings
        ruleSet = newRuleSet
        guard status.desiredEnabled else { return }
        // A tunnel joining or leaving changes routes, PF and DNS all at once:
        // a fresh start is the one path that already gets all three right. So
        // is a rule change: browsers keep using connections opened on the old
        // path, and cached answers, until the tunnels going away closes them.
        if tunnelsChanged || rulesChanged {
            record(tunnelsChanged ? "Изменён набор VPN" : "Изменены маршруты")
            await stopRuntime(preserveDesiredState: true)
            try await startRuntimeOrRollBack()
            return
        }
        // Another first server restarts only the work tunnel, the way a retry
        // does: the personal one and the rules stay up. Every remote is in the
        // pass list already, whichever comes first.
        if firstServerChanged, settings.useOpenVPN, let profile = openProfile, let payload = openPayload {
            record("Рабочий VPN: выбран другой первый сервер")
            retries[.openVPN]?.cancel()
            status.openVPN = .init(phase: .reconnecting)
            updateProtectionState()
            try tunnels.startOpenVPN(
                configuration: profile.configuration(preferring: settings.preferredOpenVPNRemote),
                credentials: Self.credentials(payload)
            )
        }
        try resolvers.apply(suffixes: ruleSet.domainSuffixes, port: DNSProxy.port.rawValue, systemDNSService: systemDNSService())
        try rebuildPolicy()
    }

    /// What the rules route, without the ids every «Применить» hands out anew:
    /// the app re-sends unchanged settings on each launch, and that must not
    /// restart the tunnels.
    private static func routing(_ rules: [RoutingRule]) -> Set<String> {
        Set(rules.filter(\.enabled).map { "\($0.target) \($0.kind) \($0.value)" })
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
        let useOpenVPN = settings.useOpenVPN
        let useAmneziaWG = settings.useAmneziaWG
        guard useOpenVPN || useAmneziaWG else { throw RouterErrorInfo(.invalidConfiguration, "Включите хотя бы один VPN") }
        let openProfile = useOpenVPN ? self.openProfile : nil
        let exit = useAmneziaWG ? self.exit : nil
        guard !useOpenVPN || (openPayload != nil && openProfile != nil), !useAmneziaWG || exit != nil else {
            throw RouterErrorInfo(.invalidConfiguration, "Импортируйте профиль для каждого включённого VPN")
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
        // the AmneziaWG default halves and are dropped by their own block rule —
        // an outage that otherwise leaves no trace anywhere.
        if captured.ipv4Gateway == nil { record("Нет IPv4-шлюза по умолчанию: прямой трафик будет заблокирован") }
        if exit?.supportsIPv6 == true, captured.ipv6Gateway == nil {
            record("Нет IPv6-шлюза по умолчанию: прямой IPv6-трафик будет заблокирован")
        }
        ruleSet = try RuleSet(rules: currentRules(), endpoints: endpointHosts())
        var initial = PolicyState(snapshot: captured)
        for (network, target) in ruleSet.explicitNetworks {
            if target == .corporate { initial.corporate.insert(network.description) }
            else { initial.direct.insert(network.description) }
        }
        initial.corporate.formUnion(openProfile?.staticRoutes ?? [])
        initial.amneziaWGSupportsIPv6 = exit?.supportsIPv6 ?? false
        initial.directByDefault = settings.directByDefault(amneziaWGUp: false)
        initial.control.formUnion(captured.dnsServers)
        // Every subscription server's bare address too: the app pings them all
        // past the tunnel. Names get there through their direct rules; an
        // address has no name to be looked up by.
        // ponytail: an address a later refresh adds waits for the next start.
        let pingable = settings.useAmneziaWG && settings.exitEngine == .xray
            ? xray.servers.map(\.host).filter { IPAddress($0) != nil } : []
        let endpoints = (openProfile?.remoteHosts ?? []) + (exit?.hosts ?? []) + pingable
        initial.control.formUnion(await Self.resolveEndpoints(endpoints))
        guard generation == started else { throw CancellationError() }
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
        record("PF применён: corp \(initial.corporate.count), direct \(initial.direct.count), control \(initial.control.count)")
        try routes.reconcile(initial)
        record("Маршруты применены")
        status.protection = .starting
        status.openVPN = .init(phase: useOpenVPN ? .connecting : .disconnected)
        status.amneziaWG = .init(phase: useAmneziaWG ? .connecting : .disconnected)
        record(useOpenVPN && useAmneziaWG ? "Маршрутизация включена" : "Маршрутизация включена, только \(useOpenVPN ? "OpenVPN" : settings.exitEngine.title)")

        if let openProfile, let openPayload {
            do {
                try tunnels.startOpenVPN(
                    configuration: openProfile.configuration(preferring: settings.preferredOpenVPNRemote),
                    credentials: Self.credentials(openPayload)
                )
            }
            catch { await tunnelFailed(.openVPN, error as? RouterErrorInfo ?? .init(.tunnelFailure, error.localizedDescription, recoverable: true)) }
        }
        if let exit {
            do {
                try await start(exit)
            } catch is CancellationError {
                // Stopped while it came up; whoever stopped it has already said why.
            } catch {
                guard generation == started else { throw CancellationError() }
                await tunnelFailed(.amneziaWG, error as? RouterErrorInfo ?? .init(.tunnelFailure, error.localizedDescription, recoverable: true))
            }
        }
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
        pushedRoutes.removeAll(); pushedDNS.removeAll(); pushedDomains.removeAll()
        status = RouterStatus(
            protection: preserveDesiredState ? .starting : .off,
            desiredEnabled: preserveDesiredState,
            lastError: status.lastError
        )
        record("Маршрутизация выключена")
    }

    private func tunnelStatus(_ kind: VPNKind, _ newStatus: TunnelStatus) async {
        // A supervisor callback can land after the runtime it belongs to was torn
        // down, which left the UI showing a tunnel as connected under "Выключен".
        guard status.desiredEnabled else { return }
        let old = kind == .openVPN ? status.openVPN : status.amneziaWG
        let previous = old.phase
        var newStatus = newStatus
        // Health checks re-report "connected" every few seconds, and «Подключён с»
        // is about when the tunnel came up, not about the latest check.
        if newStatus.phase == old.phase, newStatus.interfaceName == old.interfaceName { newStatus.changedAt = old.changedAt }
        if kind == .openVPN {
            status.openVPN = newStatus
        } else {
            status.amneziaWG = newStatus
        }
        if newStatus.phase == .connected { retryAttempt[kind] = 0 }
        updateProtectionState()
        applyPolicyOrRecordError()
        // The AmneziaWG health check re-reports "connected" every ten seconds, and
        // journalling each one buried every other event under the same line.
        if newStatus.phase != previous { record("\(title(kind)): \(newStatus.phase.rawValue)") }
    }

    private func tunnelFailed(_ kind: VPNKind, _ error: RouterErrorInfo) async {
        guard status.desiredEnabled else { return }
        record("\(title(kind)) не работает: \(error.message)\(error.recoverable ? "" : " (без повторов)")")
        tunnels.stop(kind)
        if kind == .openVPN {
            status.openVPN = .init(phase: .error, message: error.message)
        } else {
            status.amneziaWG = .init(phase: .error, message: error.message)
        }
        status.lastError = error
        updateProtectionState()
        try? rebuildPolicy()
        guard error.recoverable else { return }
        let attempt = retryAttempt[kind, default: 0]
        retryAttempt[kind] = attempt + 1
        let delay = [1, 2, 5, 10, 30, 60][min(attempt, 5)]
        record("\(title(kind)): повтор через \(delay) с (попытка \(attempt + 1))")
        let started = generation
        retries[kind]?.cancel()
        retries[kind] = Task { [weak self] in
            // A cancelled sleep returns at once: carrying on here retried
            // immediately, on exactly the runtime the cancel came from.
            guard (try? await Task.sleep(for: .seconds(delay))) != nil else { return }
            await self?.retry(kind, generation: started)
        }
    }

    private func retry(_ kind: VPNKind, generation started: Int) async {
        guard status.desiredEnabled, generation == started,
              (kind == .openVPN ? settings.useOpenVPN : settings.useAmneziaWG)
        else { return }
        await refreshEndpoints(for: kind)
        guard generation == started else { return }
        do {
            if kind == .openVPN, let profile = openProfile, let payload = openPayload {
                status.openVPN = .init(phase: .reconnecting)
                try tunnels.startOpenVPN(
                    configuration: profile.configuration(preferring: settings.preferredOpenVPNRemote),
                    credentials: Self.credentials(payload)
                )
            } else if kind == .amneziaWG, let exit {
                status.amneziaWG = .init(phase: .reconnecting)
                try await start(exit)
            }
        } catch is CancellationError {
            // Stopped while it came up; whoever stopped it has already said why.
        } catch {
            guard generation == started else { return }
            await tunnelFailed(kind, error as? RouterErrorInfo ?? .init(.tunnelFailure, error.localizedDescription, recoverable: true))
        }
    }

    // A server's address can rotate between attempts, and one that is missing
    // from <control> is dropped by the anchor's final "block drop out quick all".
    // The set only grows: a stale endpoint address costs one extra pass rule.
    private func refreshEndpoints(for kind: VPNKind) async {
        let hosts = kind == .openVPN
            ? openProfile?.remoteHosts ?? []
            : exit?.hosts ?? []
        guard !hosts.isEmpty else { return }
        let resolved = await Self.resolveEndpoints(hosts)
        guard var current = policy, !resolved.isSubset(of: current.control) else { return }
        current.control.formUnion(resolved)
        policy = current
        applyPolicyOrRecordError()
    }

    private func receivedPush(_ newRoutes: [String], _ dns: [String], _ domains: [String]) async {
        guard status.desiredEnabled else { return }
        pushedRoutes = Array(Set(newRoutes))
        pushedDNS = Array(Set(dns))
        pushedDomains = Array(Set(domains.compactMap(RuleSet.normalizeDomain)))
        do { ruleSet = try RuleSet(rules: currentRules(), endpoints: endpointHosts()) }
        catch { record("Pushed-домены отклонены: \((error as? RouterErrorInfo)?.code.rawValue ?? "internalError")") }
        try? resolvers.apply(suffixes: ruleSet.domainSuffixes, port: DNSProxy.port.rawValue, systemDNSService: systemDNSService())
        applyPolicyOrRecordError()
    }

    private func receivedDNS(_ data: Data, domain: String) async {
        guard let message = try? DNSMessage.parse(data) else { return }
        // ponytail: dropped wholesale at the cap; an LRU if names go missing mid-browse.
        if recentNames.count > 5000 { recentNames.removeAll() }
        for record in message.addresses { recentNames[record.address] = domain }
        // Now that every system query passes through here, only names that need a
        // table entry are worth tracking; the rest already ride the default route.
        guard ruleSet.classify(domain: domain) != .amneziaWG else { return }
        let now = Date()
        for record in message.addresses {
            let lifetime = max(TimeInterval(min(record.ttl, 86_400)), Self.bindingLifetime)
            dynamic[record.address, default: [:]][domain] = now.addingTimeInterval(lifetime)
        }
        applyPolicyOrRecordError()
    }

    private func applyPolicyOrRecordError() {
        do { try rebuildPolicy() }
        catch {
            let wrapped = error as? RouterErrorInfo ?? .init(.routingFailure, error.localizedDescription)
            status.lastError = wrapped
            status.protection = .error
            record("Ошибка применения политики: \(wrapped.code.rawValue)")
        }
    }

    private func rebuildPolicy() throws {
        upstreams.update(upstreamPlan())
        guard var next = policy else { return }
        let now = Date()
        dynamic = dynamic.compactMapValues { bindings in
            let active = bindings.filter { $0.value > now }
            return active.isEmpty ? nil : active
        }
        next.corporate = Set(ruleSet.explicitNetworks.filter { $0.1 == .corporate }.map { $0.0.description })
        next.direct = Set(ruleSet.explicitNetworks.filter { $0.1 == .direct }.map { $0.0.description })
        next.corporate.formUnion(openProfile?.staticRoutes ?? [])
        next.corporate.formUnion(pushedRoutes)
        next.corporate.formUnion(pushedDNS)
        for (address, bindings) in dynamic {
            let classes = bindings.keys.map(ruleSet.classify(domain:))
            if classes.contains(.corporate) { next.corporate.insert(address); next.direct.remove(address) }
            else if classes.contains(.direct), !next.corporate.contains(address) { next.direct.insert(address) }
        }
        next.openVPNInterface = status.openVPN.phase == .connected ? status.openVPN.interfaceName : nil
        next.amneziaWGInterface = status.amneziaWG.phase == .connected ? status.amneziaWG.interfaceName : nil
        next.directByDefault = settings.directByDefault(amneziaWGUp: next.amneziaWGInterface != nil)
        // Every DNS answer reaches this point, in the client's response path, so
        // an unchanged policy must not cost a PF reload and a route reconcile.
        guard next != policy else { return }
        let previous = policy
        do {
            // Route-first is fail-closed: the currently loaded PF policy blocks every
            // newly routed class until its matching pass rule is installed.
            try routes.reconcile(next)
            try pf.apply(next)
            if next.openVPNInterface != policy?.openVPNInterface || next.amneziaWGInterface != policy?.amneziaWGInterface {
                record("Интерфейсы: OpenVPN \(next.openVPNInterface ?? "—"), личный \(next.amneziaWGInterface ?? "—")")
            }
            policy = next
        } catch {
            if let previous {
                try? routes.reconcile(previous)
                try? pf.apply(previous)
            }
            throw error
        }
    }

    private func updateProtectionState() {
        status.protection = .evaluate(
            desiredEnabled: status.desiredEnabled,
            openVPN: settings.useOpenVPN ? status.openVPN : nil,
            amneziaWG: settings.useAmneziaWG ? status.amneziaWG : nil
        )
        if status.protection == .protected { status.lastError = nil }
    }

    private func startMaintenance() {
        maintenance?.cancel()
        maintenance = Task { [weak self] in
            var previousTick = Date()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                let now = Date()
                // The clock keeps counting while the Mac sleeps, so an overlong gap
                // between ticks is the only sign of a wake the daemon gets when the
                // network came back looking exactly as it left.
                let gap = now.timeIntervalSince(previousTick)
                previousTick = now
                if gap > 90 { await self?.record("Похоже, был сон: \(Int(gap / 60)) мин без работы") }
                await self?.applyPolicyOrRecordError()
                await self?.recordState()
            }
        }
    }

    /// One line every half minute: what is up and how much each class holds. Counts
    /// only — the addresses behind them are the user's traffic.
    private func recordState() {
        guard let policy else { return }
        record("Состояние: защита \(status.protection.rawValue), OpenVPN \(status.openVPN.phase.rawValue) \(policy.openVPNInterface ?? "—"), личный \(status.amneziaWG.phase.rawValue) \(policy.amneziaWGInterface ?? "—"); corp \(policy.corporate.count), direct \(policy.direct.count), control \(policy.control.count)")
    }

    /// What carries the traffic no rule claims right now, if it has a profile.
    private var exit: Exit? {
        switch settings.exitEngine {
        case .amneziaWG: awgProfile.map(Exit.amneziaWG)
        case .xray: xray.server.map(Exit.xray)
        }
    }

    private func title(_ kind: VPNKind) -> String { kind == .openVPN ? kind.title : settings.exitEngine.title }

    private func start(_ exit: Exit) async throws {
        switch exit {
        case .amneziaWG(let profile):
            _ = try await tunnels.startAmneziaWG(profile: profile)
        case .xray(let server):
            guard let physical = snapshot?.physicalInterface else {
                throw RouterErrorInfo(.routingFailure, "Нет подключения к сети для личного VPN")
            }
            _ = try await tunnels.startXray(server: server, physicalInterface: physical)
        }
    }

    private func updateXray(_ update: XrayUpdate) async throws {
        let previous = xray.server
        if let agent = update.userAgent {
            xray.userAgent = try XrayProfileParser.userAgent(agent)
            try storedState().save()
        }
        if let source = update.source?.trimmingCharacters(in: .whitespacesAndNewlines), !source.isEmpty {
            let lowered = source.lowercased()
            let next: XrayState
            if lowered.hasPrefix("https://") {
                let fetched = try await fetchSubscription(source)
                var subscription = XrayState(subscriptionURL: source, userAgent: xray.userAgent)
                subscription.apply(fetched, keeping: nil)
                next = subscription
            } else if lowered.hasPrefix("http://") {
                throw RouterErrorInfo(.invalidConfiguration, "Подписка должна открываться по https://: по http её адрес и серверы видит любая сеть по пути")
            } else {
                next = XrayState(servers: try XrayProfileParser.servers(from: source), userAgent: xray.userAgent)
            }
            // The one it replaces stays as a spare, unless it is this same one again.
            spares.removeAll { $0.xray.map { $0.subscriptionURL == next.subscriptionURL && ($0.subscriptionURL != nil || $0.servers == next.servers) } ?? false }
            let same = xray.subscriptionURL == next.subscriptionURL && (xray.subscriptionURL != nil || xray.servers == next.servers)
            if !xray.servers.isEmpty, !same { spares.append(.init(xray: xray)) }
            xray = next
            record("Xray: серверов — \(xray.servers.count)")
        }
        if update.refresh, let source = xray.subscriptionURL {
            let fetched = try await fetchSubscription(source)
            if xray.subscriptionURL == source { xray.apply(fetched, keeping: xray.server) }
        }
        if let selected = update.selected {
            guard xray.servers.indices.contains(selected) else {
                throw RouterErrorInfo(.invalidConfiguration, "Такого сервера в списке нет")
            }
            xray.selected = selected
        }
        try storedState().save()
        Self.registerLogHosts(open: openProfile, awg: awgProfile, xray: xray)
        try await restartIfExitChanged(from: previous)
    }

    /// A spare becomes its engine's current profile and the one in use; the
    /// profile it displaces takes its place among the spares.
    private func selectExit(_ item: ExitItem) async throws {
        guard let id = item.spare, let index = spares.firstIndex(where: { $0.id == id }) else {
            throw RouterErrorInfo(.invalidConfiguration, "Такого профиля нет")
        }
        let chosen = spares[index]
        let current = storedState()
        if let payload = chosen.amneziaWG {
            let profile = try AmneziaWGProfileParser.parse(payload.configuration)
            if let awgPayload { spares[index] = .init(amneziaWG: awgPayload) } else { spares.remove(at: index) }
            awgPayload = payload
            awgProfile = profile
            settings.exitEngine = .amneziaWG
        } else if let state = chosen.xray {
            if xray.servers.isEmpty { spares.remove(at: index) } else { spares[index] = .init(xray: xray) }
            xray = state
            settings.exitEngine = .xray
        }
        do { try storedState().save() } catch {
            // Back as it was: memory must not run what the disk does not hold.
            spares = current.spares ?? []
            awgPayload = current.amneziaWG
            awgProfile = current.amneziaWG.flatMap { try? AmneziaWGProfileParser.parse($0.configuration) }
            xray = current.xray ?? XrayState()
            settings = current.settings
            throw error
        }
        record("Личный VPN: выбран другой профиль")
        Self.registerLogHosts(open: openProfile, awg: awgProfile, xray: xray)
        // A spare subscription may have waited long past its interval.
        Task { await self.refreshSubscriptionIfDue() }
        guard status.desiredEnabled, settings.useAmneziaWG else { return }
        await stopRuntime(preserveDesiredState: true)
        try await startRuntimeOrRollBack()
    }

    /// The profile in use is not deleted: that would leave the personal VPN
    /// with nothing to run.
    private func deleteExit(_ item: ExitItem) throws {
        if let id = item.spare {
            spares.removeAll { $0.id == id }
        } else {
            guard item.engine != settings.exitEngine else {
                throw RouterErrorInfo(.invalidConfiguration, "Этот профиль используется. Сначала выберите другой")
            }
            if item.engine == .amneziaWG {
                awgPayload = nil
                awgProfile = nil
            } else {
                xray = XrayState()
            }
        }
        try storedState().save()
        record("Удалён профиль личного VPN")
    }

    /// By name, whichever is current: choosing one must not move it.
    private var exitItems: [ExitItem] {
        var items: [ExitItem] = []
        if let awgProfile { items.append(.init(engine: .amneziaWG, title: Self.title(awg: awgProfile))) }
        if !xray.servers.isEmpty { items.append(.init(engine: .xray, title: xray.label)) }
        for spare in spares {
            if let payload = spare.amneziaWG, let profile = try? AmneziaWGProfileParser.parse(payload.configuration) {
                items.append(.init(engine: .amneziaWG, spare: spare.id, title: Self.title(awg: profile)))
            } else if let state = spare.xray {
                items.append(.init(engine: .xray, spare: spare.id, title: state.label))
            }
        }
        return items.sorted {
            let order = $0.title.localizedStandardCompare($1.title)
            // Only identical names can still trade places, by id.
            return order == .orderedSame ? $0.id < $1.id : order == .orderedAscending
        }
    }

    private static func title(awg: AmneziaWGProfile) -> String { "Файл AmneziaWG · \(awg.endpointHost)" }

    /// Another server under a running Xray exit takes effect at once. Its address
    /// is a new pass rule and route, so the runtime starts over, as on any
    /// profile change.
    private func restartIfExitChanged(from previous: XrayServer?) async throws {
        guard xray.server != previous, settings.exitEngine == .xray, settings.useAmneziaWG, status.desiredEnabled else { return }
        record("Xray: сервер «\(xray.server?.name ?? "—")»")
        await stopRuntime(preserveDesiredState: true)
        try await startRuntimeOrRollBack()
    }

    /// Checked every ten minutes and fetched once the subscription's own interval
    /// is up: the daemon keeps it fresh without the app, as it keeps protection on.
    private func startSubscriptionUpdates() {
        subscriptionUpdates = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshSubscriptionIfDue()
                try? await Task.sleep(for: .seconds(600))
            }
        }
    }

    private func refreshSubscriptionIfDue() async {
        guard let source = xray.subscriptionURL,
              Date().timeIntervalSince(xray.updatedAt ?? .distantPast) >= xray.updateInterval
        else { return }
        do {
            let fetched = try await fetchSubscription(source)
            // Replaced by the user while this was in flight: theirs wins.
            guard xray.subscriptionURL == source else { return }
            let current = xray.server
            xray.apply(fetched, keeping: current)
            Self.registerLogHosts(open: openProfile, awg: awgProfile, xray: xray)
            try storedState().save()
            try await restartIfExitChanged(from: current)
        } catch {
            record("Подписка Xray не обновилась: \((error as? RouterErrorInfo)?.message ?? error.localizedDescription)")
        }
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
    private func fetchSubscription(_ address: String) async throws -> XraySubscription {
        guard let url = URL(string: address), url.scheme?.lowercased() == "https", url.host != nil else {
            throw RouterErrorInfo(.invalidConfiguration, "Некорректный адрес подписки")
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue(xray.userAgent ?? XrayProfileParser.defaultUserAgent, forHTTPHeaderField: "User-Agent")
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
        catch { throw RouterErrorInfo(.invalidConfiguration, "Подписка не загрузилась: \((error as? URLError)?.code.rawValue ?? 0)") }
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

    private func currentRules(_ source: RouterSettings? = nil) -> [RoutingRule] {
        let source = source ?? settings
        // Without OpenVPN a corporate rule would only steer its traffic into the
        // corporate block rule; such traffic is ordinary traffic then.
        let rules = source.useOpenVPN ? source.effectiveRules : source.effectiveRules.filter { $0.target != .corporate }
        return rules + pushedDomainRules() + endpointRules()
    }

    private func pushedDomainRules() -> [RoutingRule] {
        pushedDomains.map { .init(target: .corporate, kind: .domain, value: $0) }
    }

    // The VPN servers' own names must resolve over the network's DNS: their
    // tunnels are exactly what is not up when we need to reach them. Routing
    // them as "direct" reuses the rule pipeline instead of a special case.
    private func endpointRules() -> [RoutingRule] {
        endpointHosts().map { .init(target: .direct, kind: .domain, value: $0) }
    }

    /// Also handed to the rule set on their own, where they beat a corporate
    /// suffix the server pushed over its own name.
    private func endpointHosts() -> [String] {
        var hosts = settings.useOpenVPN ? openProfile?.remoteHosts ?? [] : []
        if settings.useAmneziaWG {
            // Every subscription server, not only the chosen one: the app pings
            // them all, and through the tunnel that would time the tunnel instead.
            hosts += settings.exitEngine == .xray ? xray.servers.map(\.host) : exit?.hosts ?? []
        }
        // A subscription refresh must work while the tunnel it feeds is down.
        if settings.exitEngine == .xray, let host = xray.subscriptionURL.flatMap(URL.init(string:))?.host { hosts.append(host) }
        var seen = Set<String>()
        return hosts
            .filter { IPAddress($0) == nil }
            .compactMap(RuleSet.normalizeDomain)
            .filter { seen.insert($0).inserted }
    }

    // Which server answers each class. The AmneziaWG resolver only exists behind
    // its tunnel, so until that is up we return nil and the proxy answers
    // SERVFAIL rather than leaking the name to the network's DNS.
    private func upstreamPlan() -> UpstreamTable.Plan {
        let network = Self.failover(snapshot?.dnsServers ?? [])
        let profileDNS = Self.failover(exit?.dnsServers ?? [])
        return .init(
            ruleSet: ruleSet,
            corporate: pushedDNS.isEmpty
                ? (settings.corporateDNSFallbackToCurrent ? network : [])
                : Self.failover(pushedDNS),
            direct: network,
            amneziaWG: profileDNS.isEmpty || !settings.useAmneziaWG
                ? network
                : status.amneziaWG.phase == .connected ? profileDNS
                : settings.killSwitch ? [] : network
        )
    }

    // Two is the whole failover budget: a third server only lengthens the wait
    // before the client is told SERVFAIL.
    private static func failover(_ servers: [String]) -> [String] { Array(servers.prefix(2)) }

    // networksetup speaks service names ("Wi-Fi"), not BSD interfaces ("en0").
    // Only switch the system resolver when the profile actually names a DNS.
    private func systemDNSService() -> String? {
        guard settings.useAmneziaWG, exit?.dnsServers.isEmpty == false, let interface = snapshot?.physicalInterface else { return nil }
        guard let listing = try? runner.run("/usr/sbin/networksetup", ["-listnetworkserviceorder"]).stdout,
              let service = ResolverController.serviceName(forInterface: interface, in: listing)
        else {
            record("Не найден сетевой сервис для \(interface); системный DNS не переключён")
            return nil
        }
        return service
    }

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
        .init(openVPN: openPayload, amneziaWG: awgPayload, settings: settings, enabled: enabledByUser, xray: xray, spares: spares, bootTime: StoredState.currentBoot)
    }

    private func reported() -> RouterStatus {
        var result = status
        // The switch shows the wish, not only the runtime: after a failed automatic
        // start it stays on, so that switching it off is what disarms the next one.
        result.desiredEnabled = status.desiredEnabled || enabledByUser
        result.profiles = .init(
            hasOpenVPN: openPayload != nil,
            hasAmneziaWG: awgPayload != nil,
            openVPNNeedsLogin: openProfile?.requiresCredentials ?? false,
            openVPNUsername: openPayload?.username,
            openVPNHasPassword: !(openPayload?.password ?? "").isEmpty,
            xray: xray.summary,
            openVPNServer: openProfile.flatMap { $0.remotes.first { $0 == settings.preferredOpenVPNRemote } ?? $0.remotes.first }?.host,
            amneziaWGServer: awgProfile.map(\.endpointHost),
            openVPNRemotes: openProfile?.remotes,
            exits: exitItems
        )
        // Something that answers from inside the corporate network, for the
        // app's check that the tunnel itself carries traffic.
        result.openVPN.probeAddress = pushedDNS.first { !$0.contains(":") }
        return result
    }

    private static func credentials(_ payload: ProfilePayload) -> TunnelSupervisor.Credentials {
        .init(username: payload.username, password: payload.password)
    }

    // Blocking the actor here would deadlock once the proxy is the system
    // resolver: getaddrinfo waits for an answer whose delivery needs the actor.
    private static func resolveEndpoints(_ hosts: [String]) async -> Set<String> {
        await Task.detached { Set(hosts.flatMap(HostResolver.addresses)) }.value
    }

    private func decodePayload<T: Decodable>(_ request: IPCRequest) throws -> T {
        guard let payload = request.payload else { throw RouterErrorInfo(.invalidConfiguration, "Отсутствует payload") }
        return try IPCCodec.decoder.decode(T.self, from: payload)
    }

    private func response<T: Encodable>(_ value: T) throws -> IPCResponse {
        .init(payload: try IPCCodec.encoder.encode(value))
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

/// Everything the daemon needs to bring protection back on its own, secrets
/// included. Kept in a root-only directory: an atomic write's temporary file is
/// created with the default umask, readable for a moment before any chmod.
private struct StoredState: Codable {
    var openVPN: ProfilePayload?
    var amneziaWG: ProfilePayload?
    var settings = RouterSettings()
    var enabled = false
    var xray: XrayState?
    var spares: [SpareExit]?
    /// The boot this was saved in: a different one at launch means macOS started
    /// again, not just the daemon. Absent in a state from before it was kept.
    var bootTime: Int?

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

/// What carries the traffic no rule claims, with what the routes, PF and DNS
/// need to know about it.
private enum Exit {
    case amneziaWG(AmneziaWGProfile)
    case xray(XrayServer)

    /// Resolved into the pass list, and over the network's DNS.
    var hosts: [String] {
        switch self {
        case .amneziaWG(let profile): [profile.endpointHost]
        case .xray(let server): [server.host]
        }
    }

    var supportsIPv6: Bool {
        switch self {
        case .amneziaWG(let profile): profile.supportsIPv6
        // Xray's TUN takes only IPv4 on macOS.
        case .xray: false
        }
    }

    /// Asked through the tunnel. Xray brings no resolver of its own, so it
    /// gets the two public ones.
    var dnsServers: [String] {
        switch self {
        case .amneziaWG(let profile): profile.dnsServers
        case .xray: ["1.1.1.1", "8.8.8.8"]
        }
    }
}

/// The Xray exit's servers and where they came from. Stored with the profiles:
/// a subscription URL is as much a secret as a password.
private struct XrayState: Codable {
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

/// A personal profile kept aside, whole: a subscription keeps its server
/// choice and User-Agent for when it is chosen again.
private struct SpareExit: Codable {
    var id = UUID()
    var amneziaWG: ProfilePayload?
    var xray: XrayState?
}
