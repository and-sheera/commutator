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
}

@MainActor
final class AppModel: ObservableObject {
    @Published var status = RouterStatus()
    @Published var settings: RouterSettings
    /// The rules page as edited; only «Применить» turns it into settings.
    @Published var routing = RoutingText()
    @Published var openVPNUsername = ""
    /// Only ever what the user is typing: the stored password stays in the daemon.
    @Published var openVPNPassword = ""
    var hasOpenVPN: Bool { status.profiles.hasOpenVPN }
    var hasAmneziaWG: Bool { status.profiles.hasAmneziaWG }
    var xray: XraySummary? { status.profiles.xray }
    var exits: [ExitItem] { status.profiles.exits ?? [] }
    /// The engine chosen for what no rule claims has something to run.
    var hasExit: Bool { settings.exitEngine == .xray ? xray != nil : hasAmneziaWG }
    /// The VPNs in use that have nothing to run yet.
    var missingProfiles: [VPNKind] {
        VPNKind.allCases.filter { uses($0) && !($0 == .openVPN ? hasOpenVPN : hasExit) }
    }

    /// Which server a VPN dials, the way its profile names it.
    func serverName(_ kind: VPNKind) -> String? {
        if kind == .openVPN { return status.profiles.openVPNServer }
        guard settings.exitEngine == .xray else { return status.profiles.amneziaWGServer }
        guard let xray, xray.servers.indices.contains(xray.selected) else { return nil }
        return xray.servers[xray.selected].name
    }

    /// The window's page, here so the menu and other pages can send you to one.
    /// Remembered, so the window reopens where it was left.
    @Published var page: Page? = UserDefaults.standard.string(forKey: "page").flatMap(Page.init(rawValue:)) ?? .overview {
        didSet { UserDefaults.standard.set(page?.rawValue, forKey: "page") }
    }
    /// The sheet that takes a personal VPN profile, here so «Обзор» can open it.
    @Published var addingExit = false
    /// Only a profile with `auth-user-pass` asks for a login; for any other the
    /// field is noise that sends people hunting for a value that does not exist.
    var openVPNNeedsLogin: Bool { status.profiles.openVPNNeedsLogin }
    var openVPNHasPassword: Bool { status.profiles.openVPNHasPassword }
    /// Whether the fields hold something the daemon does not have yet.
    var credentialsChanged: Bool {
        !openVPNPassword.isEmpty || (openVPNUsername.isEmpty ? nil : openVPNUsername) != status.profiles.openVPNUsername
    }
    /// The target of an on/off request still in flight. The daemon answers only
    /// once the tunnels are launched, and until then the switch snapped back
    /// and looked as if the click did nothing.
    @Published private(set) var pendingEnabled: Bool?
    var displayedEnabled: Bool { pendingEnabled ?? status.desiredEnabled }
    @Published var errorMessage: String?
    @Published var systemComponentMessage: String?
    @Published var pendingUnsafe: PendingUnsafeProfile?
    @Published private(set) var diagnosticsInfo: Diagnostics?
    /// Ping by server endpoint, so a refreshed list keeps what was measured.
    @Published private(set) var serverPings: [String: PingState] = [:]
    @Published private(set) var pingingServers = false
    @Published private(set) var updatingXray = false
    @Published private var dismissedError: String?
    @Published private(set) var logLines: [String] = []
    private var logCursor = 0
    @Published private(set) var report: ConnectionReport?
    @Published private(set) var checking = false
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
        let current = errorMessage ?? status.lastError?.message
        return current == dismissedError ? nil : current
    }

    func dismissError() { dismissedError = errorMessage ?? status.lastError?.message }

    private let client = XPCClient()
    private(set) lazy var traffic = TrafficMonitor { [client] addresses in
        (try? await client.request(.lookupNames, payload: addresses, as: [String: String].self)) ?? [:]
    }
    private var pollTask: Task<Void, Never>?
    private var previousStatus: RouterStatus?
    private var syncedToDaemon = false
    private let settingsKey = "router-settings"

    init() {
        // VPNROUTER_DEMO=1: made-up data for README screenshots. The daemon is
        // never contacted, so nothing real is shown or changed.
        if XPCClient.isDemo {
            settings = RouterSettings()
            routing = RoutingText(settings: settings)
            fillDemo()
            return
        }
        settings = Self.loadSettings()
        routing = RoutingText(settings: settings)
        Task { await bootstrap() }
    }

    private func fillDemo() {
        let since = Calendar.current.date(bySettingHour: 9, minute: 12, second: 0, of: Date()) ?? Date()
        var work = TunnelStatus(phase: .connected, interfaceName: "utun4", changedAt: since)
        work.probeAddress = "10.0.0.53"
        status = RouterStatus(
            protection: .protected,
            openVPN: work,
            amneziaWG: .init(phase: .connected, interfaceName: "utun5", changedAt: since),
            desiredEnabled: true,
            profiles: .init(hasOpenVPN: true, hasAmneziaWG: true, openVPNServer: "vpn.company.example", amneziaWGServer: "Нидерланды")
        )
        report = ConnectionReport(
            com: .init(ip: "203.0.113.24", country: "NL", city: "Amsterdam", org: "AS64500 Example Hosting", interface: "utun5", milliseconds: 48),
            ru: .init(ip: "198.51.100.17", country: "RU", city: "Москва", org: "AS64501 Домашний провайдер", interface: "en0", milliseconds: 12),
            corporate: .milliseconds(23)
        )
    }

    deinit { pollTask?.cancel() }

    func setRouting(_ enabled: Bool) {
        // The daemon in place during an install is about to be replaced.
        guard !installingUpdate, pendingEnabled == nil, enabled != status.desiredEnabled else { return }
        let missing = missingProfiles
        guard !enabled || missing.isEmpty else {
            errorMessage = (missing.count > 1 ? "Нет профилей ни для одного VPN" : "Нет профиля для \(missing[0].genitive)")
                + ": добавьте их в «Профилях» или выключите лишний VPN на «Обзоре»"
            return
        }
        pendingEnabled = enabled
        Task {
            defer { pendingEnabled = nil }
            // Without an OpenVPN profile there is nothing to push, and demanding one
            // here kept «только AmneziaWG» from ever switching on.
            if enabled, hasOpenVPN { guard await pushCredentials() else { return } }
            await setEnabled(enabled)
        }
    }

    /// Quitting takes protection down with it. false: the daemon did not confirm,
    /// and the app stays open rather than leave VPN on behind the user's back.
    func turnOffForQuit() async -> Bool {
        await setEnabled(false)
        return !status.desiredEnabled
    }

    /// false: the panel was cancelled.
    @discardableResult
    func importFile(_ kind: VPNKind) -> Bool {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = kind == .openVPN ? [.init(filenameExtension: "ovpn")!] : [.init(filenameExtension: "conf")!]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return false }
        importProfile(at: url, as: kind)
        return true
    }

    /// Dropped files pick their kind by extension, the way the official clients take them.
    func importDropped(_ urls: [URL]) -> Bool {
        var accepted = false
        for url in urls {
            switch url.pathExtension.lowercased() {
            case "ovpn": importProfile(at: url, as: .openVPN)
            case "conf": importProfile(at: url, as: .amneziaWG)
            default: continue
            }
            accepted = true
        }
        return accepted
    }

    private func importProfile(at url: URL, as kind: VPNKind) {
        do { importConfiguration(try String(contentsOf: url, encoding: .utf8), as: kind) }
        catch { errorMessage = error.localizedDescription }
    }

    /// Whatever was pasted for the personal VPN — Amnezia's «Поделиться VPN» link,
    /// a share link or a subscription — goes to the engine it is for.
    func addExit(_ text: String) async -> Bool {
        switch ExitEngine(profile: text) {
        case .amneziaWG: importConfiguration(text, as: .amneziaWG)
        case .xray: await updateXray(.init(source: text))
        }
    }

    /// AmneziaWG accepts either a `.conf` text or Amnezia's «Поделиться VPN» link.
    private func normalizedAmneziaWG(_ text: String) throws -> String {
        guard text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("vpn://") else { return text }
        return try AmneziaWGProfileParser.nativeConfig(fromVpnLink: text)
    }

    /// A picked file and an edited profile go through the same checks. Returns whether it was accepted.
    @discardableResult
    private func importConfiguration(_ configuration: String, as kind: VPNKind, adding: Bool = true) -> Bool {
        do {
            var configuration = configuration
            if kind == .amneziaWG { configuration = try normalizedAmneziaWG(configuration) }
            if kind == .openVPN {
                let inspected = try OpenVPNProfileParser.parse(configuration)
                if !inspected.dangerousDirectives.isEmpty {
                    pendingUnsafe = .init(configuration: configuration, directives: inspected.dangerousDirectives)
                    return false
                }
            } else {
                _ = try AmneziaWGProfileParser.parse(configuration)
            }
            Task { await storeAndSend(kind, configuration: configuration, authorization: nil, adding: adding) }
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func confirmUnsafeImport() {
        guard let pending = pendingUnsafe else { return }
        do {
            let authorization = try AdminAuthorization.request()
            pendingUnsafe = nil
            Task { await storeAndSend(.openVPN, configuration: pending.configuration, authorization: authorization) }
        } catch { errorMessage = error.localizedDescription }
    }

    func cancelUnsafeImport() { pendingUnsafe = nil }

    /// The stored profile as text, to edit in place. Where the daemon takes
    /// unsigned clients it asks for an administrator first: keys ride inline.
    func profileText(_ kind: VPNKind) async -> String? {
        do {
            return try await client.request(.getProfile, payload: ProfileRequest(kind: kind), as: String.self)
        } catch let refused as RouterErrorInfo where refused.code == .permissionDenied {
            do {
                let authorization = try AdminAuthorization.request()
                return try await client.request(.getProfile, payload: ProfileRequest(kind: kind, authorization: authorization), as: String.self)
            } catch { errorMessage = error.localizedDescription }
        } catch { errorMessage = error.localizedDescription }
        return nil
    }

    /// Checked before anything is sent, so a typo stays in the editor; then
    /// stored like a freshly picked file. nil: accepted.
    func saveProfile(_ text: String, as kind: VPNKind) -> String? {
        do {
            if kind == .openVPN { _ = try OpenVPNProfileParser.parse(text) } else { _ = try AmneziaWGProfileParser.parse(normalizedAmneziaWG(text)) }
        } catch { return error.localizedDescription }
        importConfiguration(text, as: kind, adding: false)
        return nil
    }

    func saveCredentials() {
        Task { await pushCredentials() }
    }

    /// What the fields show is what gets used, so «Включить» never runs with an
    /// older password than the one just typed. An empty password field means
    /// "keep the stored one": the daemon never sends it back to fill the field.
    @discardableResult
    private func pushCredentials() async -> Bool {
        guard hasOpenVPN else { errorMessage = "Сначала добавьте профиль рабочего VPN"; return false }
        guard credentialsChanged else { return true }
        let username = openVPNUsername.isEmpty ? nil : openVPNUsername
        let password = openVPNPassword.isEmpty ? nil : openVPNPassword
        do {
            let update = CredentialsUpdate(username: username, password: password)
            status = try await client.request(.updateCredentials, payload: update, as: RouterStatus.self)
            openVPNPassword = ""
            errorMessage = nil
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func saveRules() {
        do {
            settings = try routing.applied(to: settings)
            // Read back the way it was stored, so an applied edit shows no changes.
            routing = RoutingText(settings: settings)
            try persistSettings()
            Task { await sendSettings() }
        } catch { errorMessage = error.localizedDescription }
    }

    /// Compared with what the applied settings read back as.
    var rulesChanged: Bool { routing != RoutingText(settings: settings) }

    /// Why «Применить» would fail, said while the lists are still being typed.
    var rulesError: String? {
        guard rulesChanged else { return nil }
        do { _ = try routing.applied(to: settings); return nil } catch { return error.localizedDescription }
    }

    /// A site from «Трафик» or the route check, applied at once: the click is
    /// the decision. Edits still being typed stay unapplied, with it added.
    func addRule(_ host: String, to target: RuleTarget) {
        func adding(_ text: RoutingText) -> RoutingText {
            var text = text
            if target == .corporate { text.corporate = Self.appending(host, to: text.corporate) }
            else { text.direct = Self.appending(host, to: text.direct) }
            return text
        }
        let hadEdits = rulesChanged
        let edited = adding(routing)
        do {
            settings = try adding(RoutingText(settings: settings)).applied(to: settings)
            routing = hadEdits ? edited : RoutingText(settings: settings)
            try persistSettings()
            Task { await sendSettings() }
        } catch { errorMessage = error.localizedDescription }
    }

    private static func appending(_ line: String, to text: String) -> String {
        guard !text.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == line }) else { return text }
        return text.isEmpty || text.hasSuffix("\n") ? text + line : text + "\n" + line
    }

    func revertRules() { routing = RoutingText(settings: settings) }

    func exportRules() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(routing.exported, forType: .string)
    }

    /// Fills the page rather than applying: the lists stay to be looked over,
    /// and «Отменить» still brings the old ones back.
    func importRules() {
        guard let text = NSPasteboard.general.string(forType: .string), let imported = RoutingText(exported: text) else {
            errorMessage = "В буфере обмена нет маршрутов Коммутатора: сначала скопируйте их кнопкой «Экспорт»"
            return
        }
        routing = imported
    }

    func updateGeneralSettings() {
        do {
            try persistSettings()
            configureLoginItem()
            Task { await sendSettings() }
        } catch { errorMessage = error.localizedDescription }
    }

    /// Polled every second while the page is open, so a failure stays quiet:
    /// the status banner already says when the daemon is gone.
    func refreshDiagnostics() async {
        guard var value = try? await client.request(.getDiagnostics, as: Diagnostics.self) else { return }
        // Only the app knows its own bundle version; the daemon reports its own.
        value.appVersion = appVersion
        diagnosticsInfo = value
    }

    /// The two lines over the log, and the head of what «Скопировать всё» copies.
    /// Protocols are named here: this text is for whoever helps with a problem.
    var diagnostics: String {
        guard let value = diagnosticsInfo else { return "Диагностика ещё не загружена" }
        let open = value.status.openVPN.phase.russianTitle, exit = value.status.amneziaWG.phase.russianTitle
        return """
        Коммутатор \(value.appVersion), компонент \(value.daemonVersion) · \(value.status.protection.russianTitle) · сеть: \(value.physicalInterface ?? "—")
        \(VPNKind.openVPN.name) (OpenVPN): \(open) (\(value.openVPNInterface ?? "—")) · \(VPNKind.amneziaWG.name) (\(settings.exitEngine.title)): \(exit) (\(value.amneziaWGInterface ?? "—"))
        """
    }

    func refreshLog() async {
        guard let chunk = try? await client.request(.getLog, payload: logCursor, as: LogChunk.self) else { return }
        // A restarted daemon counts from zero again and sends everything it kept.
        if chunk.next < logCursor { logLines.removeAll() }
        logCursor = chunk.next
        guard !chunk.lines.isEmpty else { return }
        logLines = Array((logLines + chunk.lines).suffix(10_000))
    }

    func copyDiagnostics() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(diagnostics + "\n\n" + logLines.joined(separator: "\n"), forType: .string)
    }

    func uses(_ kind: VPNKind) -> Bool { kind == .openVPN ? settings.useOpenVPN : settings.useAmneziaWG }

    func setTunnel(_ kind: VPNKind, inUse: Bool) {
        var updated = settings
        if kind == .openVPN { updated.useOpenVPN = inUse } else { updated.useAmneziaWG = inUse }
        guard updated.useOpenVPN || updated.useAmneziaWG else { return }
        settings = updated
        updateGeneralSettings()
    }

    /// The work server tried first; the rest follow in the profile's order.
    func preferRemote(_ remote: OpenVPNRemote) {
        guard remote != settings.preferredOpenVPNRemote else { return }
        settings.preferredOpenVPNRemote = remote
        updateGeneralSettings()
    }

    func setExitEngine(_ engine: ExitEngine) {
        guard engine != settings.exitEngine else { return }
        settings.exitEngine = engine
        updateGeneralSettings()
    }

    /// Links or a subscription URL, a server choice, or a refresh. false leaves
    /// the field filled, so a mistyped address can be fixed rather than retyped.
    @discardableResult
    func updateXray(_ update: XrayUpdate) async -> Bool {
        updatingXray = true
        defer { updatingXray = false }
        do {
            status = try await client.request(.updateXray, payload: update, as: RouterStatus.self)
            errorMessage = nil
            // A newly added link is what the user wants to run, not a spare kept out of sight.
            if update.source != nil { setExitEngine(.xray) }
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// The daemon switches the engine along with the profile; the settings
    /// here follow, so the next «Применить» does not switch it back.
    func selectExit(_ item: ExitItem) {
        guard item.spare != nil else { return setExitEngine(item.engine) }
        Task {
            do {
                status = try await client.request(.selectExit, payload: item, as: RouterStatus.self)
                errorMessage = nil
                setExitEngine(item.engine)
            } catch { errorMessage = error.localizedDescription }
        }
    }

    func deleteExit(_ item: ExitItem) {
        let alert = NSAlert()
        alert.messageText = "Удалить профиль «\(item.title)»?"
        alert.informativeText = "Вернуть его можно, только добавив заново."
        alert.addButton(withTitle: "Удалить")
        alert.addButton(withTitle: "Отмена")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            do {
                status = try await client.request(.deleteExit, payload: item, as: RouterStatus.self)
                errorMessage = nil
            } catch { errorMessage = error.localizedDescription }
        }
    }

    func selectServer(_ index: Int) {
        Task { await updateXray(.init(selected: index)) }
    }

    func ping(of server: XraySummary.Server) -> PingState? { server.endpoint.flatMap { serverPings[$0] } }

    var fastestServer: Int? {
        guard let servers = xray?.servers else { return nil }
        return servers.indices
            .compactMap { index -> (Int, Double)? in
                guard case .milliseconds(let value)? = ping(of: servers[index]) else { return nil }
                return (index, value)
            }
            .min { $0.1 < $1.1 }?.0
    }

    /// Every server at once, each result shown as it lands.
    func pingServers() {
        guard !pingingServers, let servers = xray?.servers else { return }
        pingingServers = true
        Task {
            defer { pingingServers = false }
            await withTaskGroup(of: (String, PingState).self) { group in
                for server in servers {
                    guard let endpoint = server.endpoint, let host = server.host, let port = server.port else { continue }
                    let udp = server.protocolName == "hysteria"
                    group.addTask { (endpoint, await NetworkProbes.serverPing(host: host, port: port, udp: udp)) }
                }
                for await (endpoint, result) in group { serverPings[endpoint] = result }
            }
        }
    }

    /// Once a session, when the servers are first shown; after that, on request.
    func pingServersIfNeeded() {
        if serverPings.isEmpty { pingServers() }
    }

    /// Runs by itself once protection comes up, and after that only on request.
    func runChecks() {
        guard !checking else { return }
        checking = true
        let corporateTunnel = settings.useOpenVPN ? status.openVPN : nil
        Task {
            defer { checking = false }
            async let com = NetworkProbes.echo(NetworkProbes.comCheck)
            async let ru = NetworkProbes.echo(NetworkProbes.ruCheck)
            async let corporate = NetworkProbes.ping(corporateTunnel)
            report = await ConnectionReport(com: com, ru: ru, corporate: corporate)
        }
    }

    func checkRoute(_ input: String) {
        var host = input.trimmingCharacters(in: .whitespaces)
        host = RoutingText.site(host)
        guard !host.isEmpty, !checkingRoute else { return }
        checkingRoute = true
        Task {
            defer { checkingRoute = false }
            do { routeCheck = try await NetworkProbes.checkRoute(host) }
            catch { errorMessage = error.localizedDescription }
        }
    }

    /// An interface as the user knows it.
    func via(_ interface: String?) -> String {
        guard let interface else { return "через неизвестный интерфейс" }
        if interface == status.openVPN.interfaceName { return "через \(VPNKind.openVPN.lowercasedName) (\(interface))" }
        if interface == status.amneziaWG.interfaceName { return "через \(VPNKind.amneziaWG.lowercasedName) (\(interface))" }
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
        alert.addButton(withTitle: "Удалить")
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
    /// nothing to replay here beyond the rules shown in this window.
    private func syncConfiguration() async {
        let success = await sendSettings()
        if success { openVPNUsername = status.profiles.openVPNUsername ?? "" }
        syncedToDaemon = success
    }

    private func storeAndSend(_ kind: VPNKind, configuration: String, authorization: Data?, adding: Bool = true) async {
        var payload = ProfilePayload(kind: kind, configuration: configuration, unsafeAuthorization: authorization)
        payload.keepPrevious = adding
        if kind == .openVPN {
            payload.username = openVPNUsername.isEmpty ? nil : openVPNUsername
            payload.password = openVPNPassword.isEmpty ? nil : openVPNPassword
        }
        guard await sendProfile(payload) else { return }
        if kind == .openVPN { openVPNPassword = "" }
        // Switched only once stored: a dropped .conf used to land while a
        // subscription was in use and never show up. Sent after the profile,
        // so the daemon never runs an engine that has nothing to run.
        else { setExitEngine(.amneziaWG) }
    }

    private func sendProfile(_ payload: ProfilePayload) async -> Bool {
        guard !installingUpdate else { return false }
        do {
            status = try await client.request(.replaceProfile, payload: payload, as: RouterStatus.self)
            errorMessage = nil
            return true
        } catch { errorMessage = error.localizedDescription; return false }
    }

    private func sendSettings() async -> Bool {
        // The old copy must not sync its settings into the new daemon.
        guard !installingUpdate else { return false }
        do {
            status = try await client.request(.updateRules, payload: settings, as: RouterStatus.self)
            errorMessage = nil
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
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
                        await syncConfiguration()
                        if syncedToDaemon { resumeAfterUpdate() }
                    } else {
                        notifyTransitions(from: previousStatus, to: latest)
                        let cameUp = latest.protection == .protected && previousStatus?.protection != .protected
                        if previousStatus?.desiredEnabled == true, !latest.desiredEnabled { report = nil }
                        previousStatus = latest
                        status = latest
                        traffic.follow(latest, recording: settings.watchTraffic)
                        if cameUp { runChecks() }
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
        guard isInApplications else { return }
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
        UserDefaults.standard.set(try IPCCodec.encoder.encode(settings), forKey: settingsKey)
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
