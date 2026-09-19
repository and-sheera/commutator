import AppKit
import SwiftUI
import VPNRouterCore

@main
struct VPNRouterApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    /// People, not the app, decide whether the icon takes menu bar space.
    @AppStorage("showsMenuBarExtra") private var showsMenuBarExtra = true

    var body: some Scene {
        // Window, not WindowGroup: there is one window, and «Открыть Коммутатор…»
        // brings it forward instead of stacking another copy.
        Window("Коммутатор", id: "main") {
            MainWindow(model: delegate.model)
        }
        .defaultSize(width: 820, height: 600)

        MenuBarExtra(isInserted: $showsMenuBarExtra) {
            MenuContent(model: delegate.model)
        } label: {
            MenuBarLabel(model: delegate.model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Owns the model rather than a @StateObject: quitting has to ask it first.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()

    /// Closing the window keeps VPN running and the menu bar icon in place.
    /// Without this SwiftUI quits on close and re-asks after every «Отмена».
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    /// Cmd+Q, the Dock and «Выйти» all land here. Quitting takes VPN down too,
    /// so it is confirmed first while VPN is on.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // The demo's VPN is made up: there is nothing to turn off.
        guard model.displayedEnabled, !XPCClient.isDemo else { return .terminateNow }
        // Logout, restart and shutdown must not wait on a dialog. VPN outlives them
        // only if the app opens at login to show it is on; otherwise it goes off
        // quietly, as the daemon also keeps it off after a boot without the app.
        if NSAppleEventManager.shared().currentAppleEvent?.attributeDescriptor(forKeyword: AEKeyword(kAEQuitReason)) != nil {
            guard !model.settings.launchAtLogin else { return .terminateNow }
            Task {
                _ = await model.turnOffForQuit()
                sender.reply(toApplicationShouldTerminate: true)
            }
            return .terminateLater
        }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Выйти из Коммутатора?"
        alert.informativeText = "VPN тоже выключится: весь трафик пойдёт напрямую, без туннелей."
        alert.addButton(withTitle: "Выключить VPN и выйти")
        alert.addButton(withTitle: "Отмена")
        guard alert.runModal() == .alertFirstButtonReturn else { return .terminateCancel }
        Task {
            let off = await model.turnOffForQuit()
            if !off {
                let failure = NSAlert()
                failure.messageText = "VPN не выключился"
                failure.informativeText = model.errorMessage ?? "Системный компонент не ответил"
                failure.runModal()
            }
            sender.reply(toApplicationShouldTerminate: off)
        }
        return .terminateLater
    }
}

private struct MenuBarLabel: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Image(systemName: model.status.protection.symbol)
            .accessibilityLabel("Коммутатор: \(model.status.protection.russianTitle)")
    }
}

extension VPNKind {
    /// Which VPN, not which protocol: the protocol only matters where a
    /// profile is picked.
    var name: String { self == .openVPN ? "Рабочий VPN" : "Личный VPN" }
    /// For «через рабочий VPN».
    var lowercasedName: String { self == .openVPN ? "рабочий VPN" : "личный VPN" }
    /// For «профиль рабочего VPN».
    var genitive: String { self == .openVPN ? "рабочего VPN" : "личного VPN" }
    /// Work and home; the globe already stands for .com sites on «Обзоре».
    var symbol: String { self == .openVPN ? "building.2" : "house" }
}

extension OpenVPNRemote {
    /// «vpn.corp.com:1194 · UDP»
    var title: String {
        host + (port.map { ":\($0)" } ?? "") + (proto.map { " · \($0.uppercased())" } ?? "")
    }
}

extension ProtectionState {
    var color: Color {
        switch self {
        case .protected: .green
        case .starting: .blue
        case .degraded: .orange
        case .error: .red
        case .off: .gray
        }
    }

    /// Connected nodes, not a shield: the app switches paths, it is no
    /// antivirus. Filled nodes say "working" without colour, which the menu
    /// bar does not have.
    var symbol: String {
        switch self {
        case .protected: "point.3.filled.connected.trianglepath.dotted"
        case .off, .starting, .degraded: "point.3.connected.trianglepath.dotted"
        case .error: "exclamationmark.triangle"
        }
    }
}

extension TunnelPhase {
    var color: Color {
        switch self {
        case .connected: .green
        case .connecting: .blue
        case .reconnecting: .orange
        case .error: .red
        case .disconnected: .gray
        }
    }
}

extension PingState {
    var text: String {
        switch self {
        case .milliseconds(let value): value < 1 ? "<1 мс" : "\(Int(value.rounded())) мс"
        case .noReply: "нет ответа"
        }
    }

    var color: Color {
        switch self {
        case .milliseconds(let value): value < 150 ? .green : value < 400 ? .orange : .red
        case .noReply: .secondary
        }
    }
}

extension RouterStatus {
    /// What the state means for traffic, under the title and in notifications.
    func summary(_ settings: RouterSettings) -> String {
        switch protection {
        case .off: return "Трафик идёт без VPN"
        case .starting: return "Подключение VPN…"
        case .protected:
            switch (settings.useOpenVPN, settings.useAmneziaWG) {
            case (true, false): return "Рабочие сайты — через рабочий VPN, остальное — напрямую"
            case (false, true): return "Всё, кроме списка «Напрямую», — через личный VPN"
            default: return "Рабочие сайты — через рабочий VPN, остальное — через личный"
            }
        case .degraded:
            let down = [(VPNKind.openVPN, openVPN, settings.useOpenVPN), (.amneziaWG, amneziaWG, settings.useAmneziaWG)]
                .filter { $0.2 && $0.1.phase != .connected }
            guard !down.isEmpty else { return "VPN подключены не полностью" }
            let names = down.map { "\($0.0.name): \($0.1.phase.russianTitle.lowercased())" }.joined(separator: ", ")
            guard settings.killSwitch || !down.contains(where: { $0.0 == .amneziaWG }) else {
                return names + (down.count == 1 ? " — остальной трафик идёт напрямую" : " — рабочий трафик заблокирован, остальной идёт напрямую")
            }
            return names + (down.count == 1 ? " — его трафик заблокирован" : " — трафик заблокирован")
        case .error:
            return desiredEnabled ? "Не удалось применить правила" : "Маршрутизация выключена из-за ошибки"
        }
    }
}

extension XraySummary {
    /// What the provider is about to cut off, if anything.
    var warning: String? {
        if let expires = expiresAt {
            if expires < .now { return "Подписка закончилась" }
            if expires.timeIntervalSinceNow < 3 * 86_400 {
                return "Подписка заканчивается \(expires.formatted(.relative(presentation: .named)))"
            }
        }
        if let used = usedBytes, let total = totalBytes, total > 0, used * 10 >= total * 9 {
            return "Трафика подписки осталось \(ByteCountFormatter.string(fromByteCount: max(total - used, 0), countStyle: .file))"
        }
        return nil
    }
}

/// «🇳🇱 Нидерланды, Амстердам» from what an address check found.
private func place(_ result: EchoResult) -> String? {
    let parts = [result.country.map(countryName), result.city].compactMap { $0 }
    return parts.isEmpty ? nil : parts.joined(separator: ", ")
}

private func countryName(_ code: String) -> String {
    let flag = code.uppercased().unicodeScalars.compactMap { UnicodeScalar(127_397 + $0.value) }.map(String.init).joined()
    return "\(flag) \(Locale.current.localizedString(forRegionCode: code) ?? code)"
}

private let linkFormats = "Подходит файл .conf AmneziaWG или WireGuard, ссылка vpn:// из Amnezia («Поделиться VPN»), ссылка vless://, hysteria2://, trojan://, ss://, vmess:// или адрес подписки https://…, как в Happ. Подписка обновляется сама; зашифрованные happ://crypt не поддерживаются."

// MARK: - Menu bar

private struct MenuContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                StatusBadge(state: model.status.protection, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.status.protection.russianTitle).font(.headline)
                    Text(model.status.summary(model.settings))
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                PowerSwitch(model: model)
            }
            .padding(12)

            Divider().padding(.horizontal, 12)

            VStack(alignment: .leading, spacing: 10) {
                TunnelRows(model: model)
                if model.uses(.amneziaWG), model.settings.exitEngine == .xray, let xray = model.xray, xray.servers.count > 1 {
                    MenuServerPicker(model: model, xray: xray)
                }
                if model.displayedEnabled { SeenAs(model: model) }
            }
            .padding(12)

            Banners(model: model, insets: .init(top: 0, leading: 12, bottom: 12, trailing: 12))

            Divider().padding(.horizontal, 12)

            VStack(spacing: 0) {
                if !model.missingProfiles.isEmpty {
                    MenuRowButton(title: "Добавить профиль…") { show(.profiles) }
                }
                MenuRowButton(title: "Открыть Коммутатор…") { show(nil) }
                MenuRowButton(title: "Выйти", detail: model.displayedEnabled ? "VPN выключится" : nil) {
                    NSApp.terminate(nil)
                }
            }
            .padding(6)
        }
        .frame(width: 340)
        .textSelection(.enabled)
    }

    private func show(_ page: Page?) {
        if let page { model.page = page }
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "main")
    }
}

/// Another subscription server without opening the window.
private struct MenuServerPicker: View {
    @ObservedObject var model: AppModel
    let xray: XraySummary

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "server.rack").foregroundStyle(.secondary).frame(width: 22)
            ServerPicker(model: model, xray: xray)
        }
        .task { model.pingServersIfNeeded() }
    }
}

/// The subscription's servers with their ping, as a pop-up: a list of rows
/// under the profile read as a third VPN.
private struct ServerPicker: View {
    @ObservedObject var model: AppModel
    let xray: XraySummary

    var body: some View {
        // A closure, not `set: model.selectServer`: that method reference
        // crashes the Swift 6 compiler in IRGen.
        Picker("Сервер", selection: Binding(get: { xray.selected }, set: { model.selectServer($0) })) {
            ForEach(Array(xray.servers.enumerated()), id: \.offset) { index, server in
                Text(model.ping(of: server).map { "\(server.name) · \($0.text)" } ?? server.name).tag(index)
            }
        }
        .labelsHidden()
        .disabled(model.updatingXray)
    }
}

/// The connection check in brief: where .com and .ru sites see you from.
/// The work network is left to the window; here it would crowd the menu.
private struct SeenAs: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Проверка подключения").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if model.checking { ProgressView().controlSize(.mini) }
                Button { model.runChecks() } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless)
                    .disabled(model.checking)
                    .help("Проверить ещё раз")
                    .accessibilityLabel("Проверить ещё раз")
            }
            row(symbol: "globe", title: "Сайты .com", result: model.report?.com)
            row(symbol: "flag", title: "Сайты .ru", result: model.report?.ru)
        }
    }

    private func row(symbol: String, title: String, result: EchoResult?) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
            Text(title)
            Spacer()
            if model.report != nil {
                if let result {
                    Text(result.country.map(countryName) ?? result.ip ?? "ответили").foregroundStyle(.secondary)
                } else {
                    Label("нет ответа", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            } else {
                Text(model.checking ? "…" : "—").foregroundStyle(.secondary)
            }
        }
        .font(.callout)
    }
}

/// A full-width row with the hover highlight of a native menu item.
private struct MenuRowButton: View {
    let title: String
    var detail: String?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                if let detail { Text(detail).foregroundStyle(.secondary) }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(hovering ? Color.primary.opacity(0.1) : .clear, in: RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

// MARK: - Main window

enum Page: String, CaseIterable, Identifiable {
    case overview, profiles, rules, general, diagnostics
    var id: Self { self }

    var title: String {
        switch self {
        case .overview: "Обзор"
        case .profiles: "Профили"
        case .rules: "Маршруты"
        case .general: "Общие"
        case .diagnostics: "Диагностика"
        }
    }

    var symbol: String {
        switch self {
        case .overview: "point.3.filled.connected.trianglepath.dotted"
        case .profiles: "key"
        case .rules: "arrow.triangle.branch"
        case .general: "gearshape"
        case .diagnostics: "stethoscope"
        }
    }
}

private struct MainWindow: View {
    @ObservedObject var model: AppModel

    var body: some View {
        NavigationSplitView {
            List(Page.allCases, selection: $model.page) { page in
                HStack {
                    Label(page.title, systemImage: page.symbol)
                    Spacer()
                    // What the page is waiting on, before you open it.
                    if let hint = attention(page) {
                        Circle().fill(.orange).frame(width: 7, height: 7)
                            .help(hint)
                            .accessibilityLabel(hint)
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 200, max: 250)
            // The one control every page needs, named, and where the state is
            // already shown: a bare switch in the toolbar read as anything but VPN.
            .safeAreaInset(edge: .bottom) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("VPN").font(.headline)
                        HStack(spacing: 5) {
                            Circle().fill(model.status.protection.color).frame(width: 7, height: 7)
                            // One line: with the spinner beside the switch, a
                            // longer state wrapped and the block jumped in height.
                            Text(model.status.protection.russianTitle)
                                .lineLimit(1)
                                .help(model.status.protection.russianTitle)
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    Spacer()
                    PowerSwitch(model: model)
                }
                .padding(12)
                .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .padding(10)
            }
        } detail: {
            VStack(spacing: 0) {
                Banners(model: model)
                switch model.page ?? .overview {
                case .overview: OverviewPage(model: model)
                case .profiles: ProfilesPage(model: model)
                case .rules: RulesPage(model: model)
                case .general: GeneralPage(model: model)
                case .diagnostics: DiagnosticsPage(model: model)
                }
            }
            // Not on the sidebar: there, selectable labels would take the click
            // that should pick the page.
            .textSelection(.enabled)
            // The page, not the app name: the title says where you are.
            .navigationTitle((model.page ?? .overview).title)
        }
        .frame(minWidth: 740, minHeight: 520)
        .alert(item: $model.pendingUnsafe) { pending in
            Alert(
                title: Text("Доверенный системный профиль?"),
                message: Text("Эти строки смогут запускать код с правами root:\n\n\(pending.directives.joined(separator: "\n"))"),
                primaryButton: .destructive(Text("Разрешить"), action: model.confirmUnsafeImport),
                secondaryButton: .cancel(model.cancelUnsafeImport)
            )
        }
    }

    private func attention(_ page: Page) -> String? {
        switch page {
        case .profiles: model.missingProfiles.isEmpty ? nil : "Не хватает профиля"
        case .rules: model.rulesChanged ? "Есть неприменённые изменения" : nil
        default: nil
        }
    }
}

private struct OverviewPage: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Form {
            // No big status block: the state is already by the switch in the
            // sidebar, and what it means for traffic fits under the VPNs.
            Section {
                TunnelRows(model: model, inWindow: true)
            } header: {
                Text("VPN")
            } footer: {
                Note(model.status.summary(model.settings))
            }
            Section {
                if let report = model.report {
                    CheckRow(symbol: "globe", title: "Сайты .com", result: echo(report.com, url: NetworkProbes.comCheck))
                    CheckRow(symbol: "flag", title: "Сайты .ru", result: echo(report.ru, url: NetworkProbes.ruCheck))
                    if model.settings.useOpenVPN {
                        CheckRow(symbol: VPNKind.openVPN.symbol, title: "Рабочая сеть", result: corporate(report.corporate))
                    }
                } else {
                    Text(model.checking ? "Проверка…" :"Проверка запустится сама, когда VPN подключится.")
                        .foregroundStyle(.secondary)
                }
            } header: {
                HStack {
                    Text("Проверка подключения")
                    if let report = model.report, !model.checking {
                        Text("· проверено в \(report.checkedAt.formatted(date: .omitted, time: .shortened))")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.checking { ProgressView().controlSize(.small) }
                    Button("Проверить", action: model.runChecks)
                        .keyboardShortcut("r")
                        .disabled(model.checking)
                }
            } footer: {
                Note("Сайты .com и .ru отвечают, с каким адресом вас видят. Страна, город и провайдер определяются по этому адресу через ipinfo.io. Рабочая сеть проверяется пингом до DNS компании через рабочий VPN.")
            }
        }
        .formStyle(.grouped)
    }

    private func echo(_ result: EchoResult?, url: URL) -> CheckResult {
        var rows = [("Запрос", (url.host() ?? "") + url.path())]
        guard let result else { return .init(ok: false, rows: rows + [("Ответ", "не пришёл за 8 секунд")]) }
        if let ip = result.ip { rows.append(("Видят адрес", ip)) }
        if let place = place(result) { rows.append(("Откуда", place)) }
        if let org = result.org { rows.append(("Провайдер", org)) }
        rows.append(("Маршрут", model.via(result.interface)))
        rows.append(("Время", "\(result.milliseconds) мс"))
        return .init(ok: true, rows: rows)
    }

    private func corporate(_ ping: PingState?) -> CheckResult {
        var rows: [(String, String)] = []
        if let target = model.status.openVPN.probeAddress { rows.append(("Запрос", "ping \(target) — DNS компании")) }
        switch ping {
        case .milliseconds?:
            rows.append(("Маршрут", model.via(model.status.openVPN.interfaceName)))
            rows.append(("Время", ping?.text ?? ""))
            return .init(ok: true, rows: rows)
        case .noReply?:
            return .init(ok: false, rows: rows + [("Ответ", "DNS компании не ответил через рабочий VPN")])
        case nil:
            return .init(ok: false, rows: rows + [("Ответ", "рабочий VPN не подключён или сервер не прислал свой DNS")])
        }
    }
}

private struct CheckResult {
    var ok: Bool
    var rows: [(String, String)]
}

private struct CheckRow: View {
    let symbol: String
    let title: String
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
                Text(title)
                Spacer()
                Image(systemName: result.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(result.ok ? .green : .orange)
            }
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 3) {
                ForEach(result.rows, id: \.0) { label, value in
                    GridRow {
                        Text(label).foregroundStyle(.secondary)
                        Text(value)
                    }
                }
            }
            .font(.caption)
            .padding(.leading, 32)
        }
    }
}

private struct ProfilesPage: View {
    @ObservedObject var model: AppModel
    @State private var dropTargeted = false
    @State private var editing: EditedProfile?

    var body: some View {
        Form {
            Section {
                LabeledContent("Профиль") {
                    HStack {
                        if model.hasOpenVPN {
                            Text(model.status.profiles.openVPNServer ?? "Сохранён")
                                .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            Button("Изменить…") { edit(.openVPN) }
                            Button("Заменить…") { model.importFile(.openVPN) }
                        } else {
                            Text("Не добавлен").foregroundStyle(.secondary)
                            Button("Добавить .ovpn…") { model.importFile(.openVPN) }
                        }
                    }
                }
                if model.hasOpenVPN {
                    if let remotes = model.status.profiles.openVPNRemotes, remotes.count > 1 {
                        Picker("Сначала подключаться к", selection: Binding(
                            get: { model.settings.preferredOpenVPNRemote.flatMap { remotes.contains($0) ? $0 : nil } ?? remotes[0] },
                            set: { model.preferRemote($0) }
                        )) {
                            ForEach(remotes, id: \.self) { remote in Text(remote.title).tag(remote) }
                        }
                    }
                    if model.openVPNNeedsLogin {
                        TextField("Логин", text: $model.openVPNUsername)
                            .onSubmit(model.saveCredentials)
                    }
                    // The button sits on the password's own row: under the whole
                    // section it read as if the profile needed saving too.
                    LabeledContent("Пароль") {
                        HStack {
                            SecureField("Пароль", text: $model.openVPNPassword, prompt: Text(model.openVPNHasPassword ? "Сохранён" : "Не задан"))
                                .labelsHidden()
                                .onSubmit(model.saveCredentials)
                            Button("Сохранить", action: model.saveCredentials)
                                .disabled(!model.credentialsChanged)
                        }
                    }
                }
            } header: {
                ProfileHeader(model: model, kind: .openVPN)
            } footer: {
                if (model.status.profiles.openVPNRemotes?.count ?? 0) > 1 {
                    Note("Если выбранный сервер не ответит, рабочий VPN попробует остальные по порядку из профиля.")
                }
            }
            Section {
                ExitProfileRow(model: model) { edit(.amneziaWG) }
                if model.settings.exitEngine == .xray, let xray = model.xray {
                    LabeledContent("Сервер") {
                        HStack {
                            ServerPicker(model: model, xray: xray).fixedSize()
                            if model.pingingServers { ProgressView().controlSize(.small) }
                            Button("Проверить пинг", action: model.pingServers)
                                .disabled(model.pingingServers)
                            Button("Самый быстрый") {
                                if let fastest = model.fastestServer { model.selectServer(fastest) }
                            }
                            .disabled(model.fastestServer == nil || model.fastestServer == xray.selected || model.updatingXray)
                        }
                    }
                    .onAppear(perform: model.pingServersIfNeeded)
                    if xray.fromSubscription {
                        SubscriptionRows(model: model, xray: xray)
                        DisclosureGroup("Дополнительно") { UserAgentRow(model: model, xray: xray) }
                    }
                }
            } header: {
                ProfileHeader(model: model, kind: .amneziaWG)
            } footer: {
                Note("Через него идёт всё, чего нет в списках «Маршрутов»."
                    + (model.settings.exitEngine == .xray && model.xray != nil
                        ? " Пинг идёт напрямую, без VPN: он показывает, что сервер доступен, но не проверяет сам прокси."
                        : ""))
            }
        }
        .formStyle(.grouped)
        .sheet(item: $editing) { ProfileEditor(model: model, file: $0) }
        .sheet(isPresented: $model.addingExit) { AddExitSheet(model: model) }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            EdgeBar {
                Label("Файлы .ovpn и .conf можно перетащить в это окно", systemImage: "arrow.down.doc")
                    .foregroundStyle(.secondary)
            }
        }
        .dropDestination(for: URL.self) { urls, _ in
            model.importDropped(urls)
        } isTargeted: { dropTargeted = $0 }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 10).strokeBorder(Color.accentColor, lineWidth: 3).padding(6)
            }
        }
    }

    private func edit(_ kind: VPNKind) {
        Task { if let text = await model.profileText(kind) { editing = .init(kind: kind, text: text) } }
    }
}

private struct EditedProfile: Identifiable {
    let id = UUID()
    let kind: VPNKind
    let text: String
}

/// The stored profile as text. The file it once came from is not involved.
private struct ProfileEditor: View {
    @ObservedObject var model: AppModel
    let file: EditedProfile
    @State private var text: String
    @State private var failure: String?
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, file: EditedProfile) {
        self.model = model
        self.file = file
        _text = State(initialValue: file.text)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Профиль \(file.kind.genitive)").font(.headline)
                Spacer()
            }
            .padding(12)
            Divider()
            PlainTextEditor(text: $text)
            EdgeBar {
                if let failure {
                    Label(failure, systemImage: "xmark.octagon.fill").foregroundStyle(.red).lineLimit(2)
                } else {
                    Text("Сохранится в Коммутаторе и сразу применится").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Отмена") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Сохранить и применить") {
                    failure = model.saveProfile(text, as: file.kind)
                    if failure == nil { dismiss() }
                }
                .keyboardShortcut("s")
                .buttonStyle(.borderedProminent)
                .disabled(text == file.text)
            }
        }
        .frame(minWidth: 640, minHeight: 480)
    }
}

/// Types exactly what is typed: smart quotes, dashes or autocorrect would
/// quietly break a profile.
private struct PlainTextEditor: NSViewRepresentable {
    @Binding var text: String

    @MainActor final class Coordinator: NSObject, NSTextViewDelegate {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }

        func textDidChange(_ notification: Notification) {
            if let view = notification.object as? NSTextView { text.wrappedValue = view.string }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let view = scroll.documentView as? NSTextView {
            view.isAutomaticQuoteSubstitutionEnabled = false
            view.isAutomaticDashSubstitutionEnabled = false
            view.isAutomaticTextReplacementEnabled = false
            view.isAutomaticSpellingCorrectionEnabled = false
            view.isContinuousSpellCheckingEnabled = false
            view.allowsUndo = true
            view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
            view.textContainerInset = NSSize(width: 8, height: 8)
            view.string = text
            view.delegate = context.coordinator
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView, view.string != text else { return }
        view.string = text
    }
}

/// Choosing and managing apart, as the HIG has it: radio buttons pick the
/// profile in one click with all of them in sight; deleting, rare and
/// destructive, sits in its own menu and never touches the one in use.
private struct ExitProfileRow: View {
    @ObservedObject var model: AppModel
    let onEdit: () -> Void

    private var inUse: ExitItem? {
        model.exits.first { $0.spare == nil && $0.engine == model.settings.exitEngine }
    }

    var body: some View {
        if model.exits.isEmpty {
            LabeledContent("Профиль") {
                HStack {
                    Text("Не добавлен").foregroundStyle(.secondary)
                    Button("Добавить…") { model.addingExit = true }
                }
            }
        } else {
            Picker("Профиль", selection: Binding<String?>(
                get: { inUse?.id },
                set: { id in if let item = model.exits.first(where: { $0.id == id }) { model.selectExit(item) } }
            )) {
                ForEach(model.exits) { item in Text(item.title).tag(Optional(item.id)) }
            }
            .pickerStyle(.radioGroup)
            LabeledContent {
                HStack {
                    Button("Добавить…") { model.addingExit = true }
                    if inUse?.engine == .amneziaWG { Button("Изменить…", action: onEdit) }
                    Menu("Удалить") {
                        ForEach(model.exits.filter { $0 != inUse }) { item in
                            Button(item.title + "…") { model.deleteExit(item) }
                        }
                    }
                    .fixedSize()
                    .disabled(model.exits.count < 2)
                    .help(model.exits.count < 2 ? "Используемый профиль удалить нельзя" : "")
                }
            } label: { EmptyView() }
        }
    }
}

/// Whether a VPN is used sits by its profile: a footnote sending people to
/// «Обзор» for it read as a chore.
private struct ProfileHeader: View {
    @ObservedObject var model: AppModel
    let kind: VPNKind

    var body: some View {
        let inUse = model.uses(kind)
        let canTurnOff = model.uses(kind == .openVPN ? .amneziaWG : .openVPN)
        HStack {
            Text(kind.name)
            Spacer()
            Toggle("Использовать", isOn: Binding(get: { inUse }, set: { model.setTunnel(kind, inUse: $0) }))
                .toggleStyle(.switch)
                .controlSize(.mini)
                .disabled(inUse && !canTurnOff)
                .help(inUse && !canTurnOff ? "Хотя бы один VPN должен оставаться включённым" : "")
        }
    }
}

/// Every way to give the personal VPN a profile, in one place. The kind is
/// read from what was given. A failed link stays in the field, so a mistyped
/// address can be fixed rather than retyped.
private struct AddExitSheet: View {
    @ObservedObject var model: AppModel
    @State private var source = ""
    @State private var dropTargeted = false
    @Environment(\.dismiss) private var dismiss

    private var trimmed: String { source.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Профиль личного VPN").font(.headline)
            VStack(spacing: 8) {
                Image(systemName: "arrow.down.doc").font(.largeTitle).foregroundStyle(.secondary)
                Text("Перетащите сюда файл .conf").foregroundStyle(.secondary)
                Button("Выбрать файл…") {
                    if model.importFile(.amneziaWG), model.errorMessage == nil { dismiss() }
                }
            }
            .frame(maxWidth: .infinity)
            .padding(18)
            .background {
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.4),
                                  style: StrokeStyle(lineWidth: dropTargeted ? 3 : 1, dash: dropTargeted ? [] : [5]))
            }
            .dropDestination(for: URL.self) { urls, _ in
                let accepted = model.importDropped(urls)
                if accepted { dismiss() }
                return accepted
            } isTargeted: { dropTargeted = $0 }
            TextField("Или вставьте ссылку", text: $source, prompt: Text("vpn://…, vless://… или https://… подписки"))
                .onSubmit(add)
            Note(linkFormats)
            if let error = model.errorMessage {
                Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.callout)
            }
            HStack {
                if model.updatingXray { ProgressView().controlSize(.small) }
                Spacer()
                Button("Отмена") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Добавить", action: add)
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmed.isEmpty || model.updatingXray)
            }
        }
        .padding(20)
        .frame(width: 500)
        // An old error from the window would read as this sheet's.
        .onAppear { model.errorMessage = nil }
    }

    private func add() {
        guard !trimmed.isEmpty, !model.updatingXray else { return }
        Task { if await model.addExit(trimmed) { dismiss() } }
    }
}

private struct SubscriptionRows: View {
    @ObservedObject var model: AppModel
    let xray: XraySummary

    var body: some View {
        if let announce = xray.announce {
            Label {
                Text(announce)
            } icon: {
                Image(systemName: "megaphone").foregroundStyle(.secondary)
            }
        }
        if let used = xray.usedBytes {
            LabeledContent("Трафик") {
                if let total = xray.totalBytes, total > 0 {
                    VStack(alignment: .trailing, spacing: 4) {
                        ProgressView(value: Double(min(used, total)), total: Double(total))
                            .frame(width: 160)
                            .tint(used * 10 >= total * 9 ? Color.orange : Color.accentColor)
                        Text("\(size(used)) из \(size(total))").foregroundStyle(.secondary)
                    }
                } else {
                    Text("\(size(used)), без лимита").foregroundStyle(.secondary)
                }
            }
        }
        if let expires = xray.expiresAt {
            LabeledContent("Действует") {
                Text("до \(expires.formatted(date: .abbreviated, time: .omitted)) · \(expires.formatted(.relative(presentation: .named)))")
                    .foregroundStyle(expires.timeIntervalSinceNow < 3 * 86_400 ? .orange : .secondary)
            }
        }
        LabeledContent("Обновлена") {
            HStack {
                if let updated = xray.updatedAt {
                    Text(updated.formatted(Calendar.current.isDateInToday(updated) ? .dateTime.hour().minute() : .dateTime.day().month().hour().minute()))
                        .foregroundStyle(.secondary)
                }
                Button("Обновить") { Task { await model.updateXray(.init(refresh: true)) } }
                    .disabled(model.updatingXray)
            }
        }
        if xray.supportURL != nil || xray.webPageURL != nil {
            LabeledContent("Провайдер") {
                HStack(spacing: 12) {
                    if let url = xray.supportURL { Link("Поддержка", destination: url) }
                    if let url = xray.webPageURL { Link("Сайт", destination: url) }
                }
            }
        }
    }

    private func size(_ bytes: Int64) -> String { ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file) }
}

private struct UserAgentRow: View {
    @ObservedObject var model: AppModel
    let xray: XraySummary
    @State private var agent = ""

    var body: some View {
        LabeledContent("User-Agent") {
            HStack {
                TextField("User-Agent", text: $agent, prompt: Text(XrayProfileParser.defaultUserAgent))
                    .labelsHidden()
                    .onAppear { agent = xray.userAgent ?? "" }
                    .onSubmit(apply)
                Button("Применить", action: apply)
                    .disabled(model.updatingXray || agent == (xray.userAgent ?? ""))
            }
        }
        Note("Если подписка отдаёт заглушку «Обновите приложение», укажите User-Agent приложения, которое она ждёт, например Happ.")
    }

    private func apply() {
        Task { await model.updateXray(.init(refresh: true, userAgent: agent)) }
    }
}

private struct RulesPage: View {
    @ObservedObject var model: AppModel
    @State private var checkHost = ""
    @State private var exported = false
    @State private var showsFormat = false

    var body: some View {
        Form {
            Section {
                RuleEditor(text: $model.routing.corporate, placeholder: "corp.example.com\n10.0.0.0/8")
            } header: {
                RuleHeader(symbol: VPNKind.openVPN.symbol, title: "Через рабочий VPN", subtitle: "Рабочие сайты и внутренние сети компании", count: entries(model.routing.corporate))
            } footer: {
                Note(model.settings.useOpenVPN
                    ? "Если адрес есть в обоих списках, он пойдёт через рабочий VPN."
                    : "Рабочий VPN сейчас выключен, и этот список не действует.")
            }
            Section {
                LabeledContent("Все сайты в зонах") {
                    HStack(spacing: 14) {
                        Toggle(".ru", isOn: $model.routing.directRU)
                        Toggle(".su", isOn: $model.routing.directSU)
                        Toggle(".рф", isOn: $model.routing.directRF)
                    }
                    .toggleStyle(.checkbox)
                }
                RuleEditor(text: $model.routing.direct, placeholder: "example.com\n192.168.0.0/16")
            } header: {
                RuleHeader(symbol: "arrow.right", title: "Напрямую, без VPN", subtitle: "Сайты, которые должны открываться через ваш обычный интернет", count: entries(model.routing.direct))
            }
            Section {
                RouteRow(
                    symbol: VPNKind.amneziaWG.symbol, title: "Всё, чего нет в списках выше", detail: nil,
                    target: model.settings.useAmneziaWG ? "через \(VPNKind.amneziaWG.lowercasedName)" : "напрямую"
                )
            }
            Section {
                HStack {
                    TextField("Сайт или IP", text: $checkHost, prompt: Text("site.org"))
                        .labelsHidden()
                        .onSubmit { model.checkRoute(checkHost) }
                    Button("Проверить") { model.checkRoute(checkHost) }
                        .disabled(checkHost.trimmingCharacters(in: .whitespaces).isEmpty || model.checkingRoute)
                    if model.checkingRoute { ProgressView().controlSize(.small) }
                }
                if let check = model.routeCheck {
                    RouteCheckRow(check: check, via: model.via(check.interface))
                    HStack {
                        Spacer()
                        Button("Добавить в «Напрямую»") { model.addRule(check.host, to: .direct) }
                        if model.settings.useOpenVPN {
                            Button("Добавить в «Через рабочий VPN»") { model.addRule(check.host, to: .corporate) }
                        }
                    }
                    .controlSize(.small)
                    .help("Сайт попадёт в список, и правила сразу применятся")
                }
            } header: {
                RuleHeader(symbol: "magnifyingglass", title: "Проверка", subtitle: "Открывает настоящее соединение и показывает, через что оно прошло")
            } footer: {
                Note("Проверяются применённые правила. Какие соединения идут через что прямо сейчас — в «Диагностике», вкладка «Трафик».")
            }
        }
        .formStyle(.grouped)
        // Plain bordered buttons in the page itself: in the toolbar they drew
        // grey and read as disabled.
        .safeAreaInset(edge: .top, spacing: 0) {
            EdgeBar(divider: .bottom) {
                Button { showsFormat.toggle() } label: {
                    Label("Как записывать", systemImage: "questionmark.circle")
                }
                .popover(isPresented: $showsFormat, arrowEdge: .bottom) { FormatHelp() }
                Spacer()
                // Text only: the document symbols stood taller than the button.
                Button(exported ? "Скопировано" : "Экспорт") {
                    model.exportRules()
                    exported = true
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        exported = false
                    }
                }
                .help("Скопировать маршруты в буфер обмена")
                Button("Импорт", action: model.importRules)
                .help("Вставить маршруты из буфера обмена; применить их останется кнопкой «Применить»")
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            let error = model.rulesError
            EdgeBar {
                Group {
                    if let error {
                        Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red).lineLimit(2)
                    } else if model.rulesChanged {
                        Label("Есть неприменённые изменения", systemImage: "pencil.circle.fill").foregroundStyle(.orange)
                    } else {
                        Label("Правила применены", systemImage: "checkmark.circle").foregroundStyle(.secondary)
                    }
                }
                .font(.callout)
                Spacer()
                Button("Отменить", action: model.revertRules)
                    .disabled(!model.rulesChanged)
                Button("Применить", action: model.saveRules)
                    .keyboardShortcut("s")
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.rulesChanged || error != nil)
            }
        }
    }

    private func entries(_ text: String) -> Int {
        text.split(whereSeparator: \.isNewline).filter { !$0.allSatisfy(\.isWhitespace) }.count
    }
}

private struct FormatHelp: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Одна запись в строке").font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                ForEach([
                    ("site.org", "сайт и все его поддомены: www.site.org, mail.site.org…"),
                    ("192.168.1.10", "один IP-адрес"),
                    ("10.0.0.0/8", "диапазон адресов"),
                ], id: \.0) { code, meaning in
                    GridRow {
                        Text(code).font(.system(.callout, design: .monospaced))
                        Text(meaning).font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            Text("Ссылку из браузера можно вставить целиком — останется только сайт.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(16)
    }
}

private struct RuleHeader: View {
    let symbol: String
    let title: String
    let subtitle: String
    var count: Int?

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            if let count {
                Spacer()
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary).help("Записей в списке")
            }
        }
    }
}

private struct RuleEditor: View {
    @Binding var text: String
    let placeholder: String

    var body: some View {
        TextEditor(text: $text)
            .font(.system(.body, design: .monospaced))
            .scrollContentBackground(.hidden)
            .frame(minHeight: 110)
            // A pasted link becomes its site as it lands. Only a paste: typed
            // one key at a time, a half-written https://… would jump about.
            .onChange(of: text) { old, new in
                guard new.count - old.count > 1, new.contains("://") else { return }
                text = new.components(separatedBy: "\n")
                    .map { $0.contains("://") ? RoutingText.site($0.trimmingCharacters(in: .whitespaces)) : $0 }
                    .joined(separator: "\n")
            }
            .overlay(alignment: .topLeading) {
                if text.isEmpty {
                    Text(placeholder)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .padding(.leading, 5)
                        .allowsHitTesting(false)
                }
            }
    }
}

private struct GeneralPage: View {
    @ObservedObject var model: AppModel
    @AppStorage("showsMenuBarExtra") private var showsMenuBarExtra = true

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $model.settings.launchAtLogin) {
                    Text("Открывать при входе в macOS")
                    Text("Без этого после перезагрузки Mac VPN выключен, пока вы не откроете приложение")
                }
                Toggle("Показывать в строке меню", isOn: $showsMenuBarExtra)
            }
            Section {
                Toggle(isOn: $model.settings.corporateDNSFallbackToCurrent) {
                    Text("Рабочие имена через DNS текущей сети")
                    Text("Если рабочий VPN не прислал свой DNS. Выключено — такие запросы блокируются")
                }
            } header: {
                Text("DNS")
            }
            Section {
                Toggle(isOn: $model.settings.killSwitch) {
                    Text("Kill switch")
                    Text("Блокирует трафик и DNS, пока личный VPN не подключён")
                }
                .disabled(!model.settings.useAmneziaWG)
            } header: {
                Text(VPNKind.amneziaWG.name)
            } footer: {
                if !model.settings.useAmneziaWG {
                    Note("Действует, только когда используется личный VPN.")
                }
            }
            Section {
                // Folded: it matters once a site goes the wrong way, not every visit.
                DisclosureGroup("Что обходит правила для сайтов") {
                    VStack(alignment: .leading, spacing: 10) {
                        Note("Коммутатор видит, какой адрес DNS вернул для сайта, и направляет трафик на этот адрес. Всё, что узнаёт адрес мимо него, идёт по общему правилу. Правил для IP-адресов и диапазонов это не касается.")
                        Limitation(
                            title: "Безопасный DNS в браузере (DoH)",
                            text: "Браузер спрашивает адреса у своего DNS по шифрованному каналу, мимо Коммутатора: сайт из «Напрямую» пойдёт через личный VPN, а рабочий — мимо рабочего VPN. Выключите: Chrome — Настройки → Конфиденциальность и безопасность → Безопасность → «Использовать безопасный DNS»; Edge — Настройки → Конфиденциальность, поиск и службы → Безопасность; Firefox — Настройки → Приватность и защита → «DNS через HTTPS»."
                        )
                        Limitation(
                            title: "Частный узел iCloud (Private Relay)",
                            text: "Safari и часть трафика системы идут через серверы Apple, правила к ним не применяются. Выключите: Системные настройки → ваше имя → iCloud → Частный узел."
                        )
                        Limitation(
                            title: "Адреса, которые приложение уже помнит",
                            text: "Сайт, открытый до включения VPN или до изменения правил, пойдёт по новым правилам после перезапуска приложения."
                        )
                        Limitation(
                            title: "Общие адреса CDN",
                            text: "Правило для одного сайта на общем адресе направит тем же путём и остальные сайты на этом адресе."
                        )
                    }
                    .padding(.top, 6)
                }
            }
            Section {
                LabeledContent("Версия", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? VPNRouterVersion.current)
                HStack {
                    if let update = model.update {
                        Text("Доступна версия \(update.release.version)").foregroundStyle(.secondary)
                    } else if let result = model.updateCheckResult {
                        Text(result).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.checkingUpdate { ProgressView().controlSize(.small) }
                    Button("Проверить сейчас") { Task { await model.checkForUpdate() } }
                        .disabled(model.checkingUpdate)
                }
            } header: {
                Text("Обновления")
            }
            Section {
                Button("Удалить Коммутатор…", role: .destructive) { model.uninstall() }
            } footer: {
                Note("Удалит приложение, системный компонент, профили и настройки и вернёт сеть в состояние до установки.")
            }
        }
        .formStyle(.grouped)
        .onChange(of: model.settings.launchAtLogin) { _, _ in model.updateGeneralSettings() }
        .onChange(of: model.settings.corporateDNSFallbackToCurrent) { _, _ in model.updateGeneralSettings() }
        .onChange(of: model.settings.killSwitch) { _, _ in model.updateGeneralSettings() }
    }
}

private struct Limitation: View {
    let title: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
            Note(text)
        }
        .padding(.vertical, 2)
    }
}

private struct DiagnosticsPage: View {
    @ObservedObject var model: AppModel
    @State private var showsTraffic = false

    var body: some View {
        Group {
            if showsTraffic {
                TrafficView(model: model, traffic: model.traffic)
            } else {
                LogView(model: model)
            }
        }
        // Switching views belongs in the toolbar, not in the content it switches.
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Раздел", selection: $showsTraffic) {
                    Text("Журнал").tag(false)
                    Text("Трафик").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
        }
    }
}

/// The daemon's log as it is written, the way a terminal tail shows it.
private struct LogView: View {
    @ObservedObject var model: AppModel
    @State private var follow = true
    @State private var copied = false
    @State private var query = ""

    private var lines: [String] {
        let needle = query.trimmingCharacters(in: .whitespaces)
        return needle.isEmpty ? model.logLines : model.logLines.filter { $0.localizedCaseInsensitiveContains(needle) }
    }

    var body: some View {
        VStack(spacing: 0) {
            Text(model.diagnostics)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            Divider()
            LogText(lines: lines, follow: follow)
            EdgeBar {
                TextField("Поиск", text: $query, prompt: Text("Поиск по журналу"))
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 240)
                if !query.isEmpty { Text("Найдено: \(lines.count)").foregroundStyle(.secondary) }
                Toggle("Прокручивать к новым", isOn: $follow).toggleStyle(.checkbox)
                Spacer()
                Button(copied ? "Скопировано" : "Скопировать всё") {
                    model.copyDiagnostics()
                    copied = true
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        copied = false
                    }
                }
                .help("Пароли в журнал не попадают")
            }
        }
        .task {
            while !Task.isCancelled {
                await model.refreshLog()
                await model.refreshDiagnostics()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }
}

/// The log as one text view: with a Text per line, a selection could never
/// span more than one line.
private struct LogText: NSViewRepresentable {
    let lines: [String]
    let follow: Bool

    final class Coordinator {
        var shown: [String]?
        var follow = false
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        if let text = scroll.documentView as? NSTextView {
            text.isEditable = false
            text.textContainerInset = NSSize(width: 8, height: 8)
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let text = scroll.documentView as? NSTextView else { return }
        let state = context.coordinator
        let turnedOn = follow && !state.follow
        state.follow = follow
        // Replaced under a selection, the text would drop it every second, so
        // new lines wait until nothing is selected.
        if lines != state.shown, text.selectedRange().length == 0 {
            state.shown = lines
            let font = NSFont.monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
            let log = NSMutableAttributedString()
            for line in lines {
                let failed = line.localizedCaseInsensitiveContains("ошибк") || line.contains("ERROR")
                log.append(NSAttributedString(string: line + "\n", attributes: [
                    .font: font, .foregroundColor: failed ? NSColor.systemRed : NSColor.textColor,
                ]))
            }
            text.textStorage?.setAttributedString(log)
            if follow { text.scrollToEndOfDocument(nil) }
        } else if turnedOn {
            text.scrollToEndOfDocument(nil)
        }
    }
}

/// Connections as the kernel routed them, not as the rules predict.
private struct TrafficView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var traffic: TrafficMonitor
    @State private var filter = ""
    @State private var selection = Set<TrafficEntry.ID>()
    @State private var showsHelp = false
    /// Empty: the order connections arrived in.
    @State private var sortOrder: [KeyPathComparator<TrafficEntry>] = []

    private var rows: [TrafficEntry] {
        let query = filter.trimmingCharacters(in: .whitespaces).lowercased()
        let found = query.isEmpty ? traffic.entries : traffic.entries.filter { entry in
            [entry.destination, entry.flow.address, entry.owner.app, entry.owner.process, entry.via].contains { $0.lowercased().contains(query) }
        }
        return sortOrder.isEmpty ? found : found.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            if traffic.entries.isEmpty, !model.settings.watchTraffic {
                ContentUnavailableView {
                    Label("Запись соединений выключена", systemImage: "tablecells")
                } description: {
                    Text("Пока запись включена, Коммутатор раз в пару секунд спрашивает у системы список соединений. Включайте её, когда нужно разобраться, каким путём идёт сайт.")
                } actions: {
                    Button("Включить") { model.settings.watchTraffic = true }
                }
                // Unstretched, the placeholder and the bar under it sat mid-window.
                .frame(maxHeight: .infinity)
            } else if traffic.entries.isEmpty {
                ContentUnavailableView(
                    model.displayedEnabled ? "Соединений пока нет" : "Маршрутизация выключена",
                    systemImage: "tablecells",
                    description: Text(model.displayedEnabled
                        ? "Новые соединения появятся здесь через пару секунд."
                        : "Соединения записываются, пока маршрутизация включена.")
                )
                .frame(maxHeight: .infinity)
            } else {
                Table(rows, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn("Время", value: \.time) { entry in
                        Text(entry.time, format: .dateTime.hour().minute().second()).monospacedDigit()
                    }
                    .width(70)
                    TableColumn("Приложение", value: \.owner.app) { entry in
                        Text(entry.owner.app).help(entry.ownerHelp)
                    }
                    .width(min: 90, ideal: 140)
                    TableColumn("Куда", value: \.destination) { entry in
                        (Text(entry.destination).italic(entry.routerDNS == nil && entry.nameSource == .reverse)
                            + Text("  \(entry.flow.proto.uppercased()) \(entry.flow.port)").foregroundStyle(.secondary))
                            .help(entry.nameHelp)
                    }
                    TableColumn("Через", value: \.via) { entry in
                        HStack(spacing: 5) {
                            Circle().fill(Self.color(entry.via)).frame(width: 7, height: 7)
                            Text(entry.via)
                            if let early = entry.early, entry.routerDNS == nil { Text(early.tag).foregroundStyle(.secondary) }
                        }
                        .help(entry.viaHelp)
                    }
                    .width(min: 90, ideal: 200)
                }
                // A connection that went the wrong way is where the rule starts.
                .contextMenu(forSelectionType: TrafficEntry.ID.self) { ids in
                    if let entry = traffic.entries.first(where: { ids.contains($0.id) }) {
                        let host = entry.name ?? entry.flow.address
                        Button("Всегда напрямую: \(host)") { model.addRule(host, to: .direct) }
                        if model.settings.useOpenVPN {
                            Button("Всегда через рабочий VPN: \(host)") { model.addRule(host, to: .corporate) }
                        }
                        Divider()
                        Button("Скопировать \(host)") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(host, forType: .string)
                        }
                    }
                }
            }
            EdgeBar {
                Button { showsHelp.toggle() } label: {
                    Label("Как читать", systemImage: "questionmark.circle")
                }
                .popover(isPresented: $showsHelp, arrowEdge: .top) { TrafficHelp() }
                TextField("Фильтр", text: $filter, prompt: Text("Фильтр: сайт, адрес или приложение"))
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
                Spacer()
                Toggle("Записывать соединения", isOn: $model.settings.watchTraffic).toggleStyle(.checkbox)
                Text("Последние \(traffic.entries.count) из 1000").foregroundStyle(.secondary)
                Button("Очистить", action: traffic.clear)
                    .disabled(traffic.entries.isEmpty)
            }
        }
        .onChange(of: model.settings.watchTraffic) { _, _ in model.updateGeneralSettings() }
    }

    private static func color(_ via: String) -> Color {
        switch via {
        case VPNKind.openVPN.name: .blue
        case VPNKind.amneziaWG.name: .purple
        case _ where via.hasPrefix("Чужой"): .orange
        default: .gray
        }
    }
}

/// Why a row reads as it does, for the tooltip over it: a direct row or a
/// bare address looked like a leak when it was only older than the tunnel.
private extension TrafficEntry {
    /// The daemon's own lookups. Each class of names has its server on a path of
    /// its own — the network's on the physical interface, the company's through
    /// the work VPN, the rest through the personal one — so the path names it.
    var routerDNS: (label: String, help: String)? {
        guard owner.process == "VPNRouterDaemon", flow.port == "53" else { return nil }
        switch via {
        case VPNKind.amneziaWG.name:
            return ("DNS личного VPN", "Коммутатор спрашивает имя сайта у DNS личного VPN через туннель")
        case VPNKind.openVPN.name:
            return ("DNS рабочей сети", "Коммутатор спрашивает рабочее имя у DNS компании")
        case _ where via.hasPrefix("Напрямую"):
            return ("DNS текущей сети", "Коммутатор спрашивает имя из «Напрямую» у DNS вашей сети")
        default:
            return nil
        }
    }

    var destination: String {
        routerDNS.map { "\($0.label) · \(flow.address)" } ?? name ?? flow.address
    }

    // Tooltips stay one phrase: the long story is in «Как читать».
    var nameHelp: String {
        if let routerDNS { return routerDNS.help }
        switch nameSource {
        case .dns?: return ""
        case .reverse?: return "Обратное имя адреса: чей сервер, а не какой сайт"
        case nil: return "Имя неизвестно: DNS-запрос прошёл мимо Коммутатора"
        }
    }

    var ownerHelp: String {
        let path = owner.path.map { "\n\($0)" } ?? ""
        if owner.process == "VPNRouterDaemon" { return "Системный компонент Коммутатора" + path }
        if owner.app != owner.process { return "Открыл вспомогательный процесс «\(owner.process)»" + path }
        return (owner.isSystem ? "\(owner.process) — служба macOS" : owner.process) + path
    }

    var viaHelp: String {
        if via.hasPrefix("Чужой") { return "Интерфейс другой VPN-программы, виртуальной машины или macOS" }
        if via.hasPrefix("Закрытый") { return "Прежний туннель: соединение ещё не закрылось" }
        switch early {
        case .beforeTunnel?: return "Открыто до VPN, перейдёт на туннель при переподключении приложения"
        case .beforeRecording?: return "Было открыто до начала записи"
        case nil: break
        }
        guard via.hasPrefix("Напрямую") else { return "" }
        return owner.pid == ProcessInfo.processInfo.processIdentifier
            ? "Проверка Коммутатора: пинг серверов идёт мимо туннеля"
            : "Напрямую по правилам, в локальную сеть или к серверу VPN"
    }
}

private extension TrafficEntry.Early {
    var tag: String { self == .beforeTunnel ? "· до VPN" : "· было открыто" }
}

private struct TrafficHelp: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Как читать «Трафик»").font(.headline)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 6) {
                ForEach([
                    (Color.blue, "Рабочий VPN"),
                    (.purple, "Личный VPN"),
                    (.gray, "Напрямую — по правилам или потому, что открыто раньше VPN; «Закрытый интерфейс» — прежний туннель"),
                    (.orange, "Чужой туннель — его создала другая программа"),
                ], id: \.1) { color, meaning in
                    GridRow {
                        Circle().fill(color).frame(width: 7, height: 7)
                        Text(meaning).font(.callout)
                    }
                }
            }
            Divider()
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 8) {
                GridRow {
                    Text("Приложение").font(.callout.weight(.medium))
                    Text("Программа, которой принадлежит соединение. Если его открыл вспомогательный процесс — как Helper у браузеров, — показана сама программа. Службы macOS видны под своим именем: apsd — уведомления Apple, mDNSResponder — DNS.")
                }
                GridRow {
                    Text("· до VPN").font(.callout.weight(.medium))
                    Text("Открыто, пока VPN ещё не подключился. Уже открытое соединение остаётся на своём интерфейсе и перейдёт на VPN, когда приложение переподключится.")
                }
                GridRow {
                    Text("142.251.1.1").font(.callout.monospaced())
                    Text("Только адрес: DNS-запрос прошёл мимо Коммутатора — например, до включения VPN или из кэша, — и имя сайта неизвестно.")
                }
                GridRow {
                    Text("host.1e100.net").font(.callout).italic()
                    Text("Обратное имя адреса. Обычный DNS отвечает, какой адрес у сайта, а обратный — как называется сам адрес. Это имя записывает владелец адреса — провайдер или хостинг: оно говорит, чей это сервер, но не какой сайт на нём открыт.")
                }
                GridRow {
                    Text("DNS личного VPN").font(.callout.weight(.medium))
                    Text("Запрос имени от самого Коммутатора. Имена сайтов не из правил он спрашивает у DNS личного VPN через туннель, рабочие — у DNS компании, из «Напрямую» и .ru — у DNS вашей сети.")
                }
            }
            .font(.callout)
            .foregroundStyle(.primary)
            Text("Подробности — в подсказке при наведении на строку.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
        .padding(16)
        .frame(width: 420)
    }
}

private struct RouteCheckRow: View {
    let check: RouteCheck
    let via: String

    var body: some View {
        if check.connected {
            Label {
                Text("\(check.host) → \(check.address) · \(via)" + (check.milliseconds.map { " · \($0) мс" } ?? ""))
            } icon: {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            }
        } else {
            Label {
                Text("\(check.host) → \(check.address): соединение не установилось. По таблице маршрутов — \(via).")
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
    }
}

private struct EdgeBar<Content: View>: View {
    var divider: VerticalEdge = .top
    @ViewBuilder let content: Content

    var body: some View {
        HStack(spacing: 10) { content }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.bar)
            .overlay(alignment: divider == .top ? .top : .bottom) { Divider() }
    }
}

// MARK: - Shared pieces

private struct StatusBadge: View {
    let state: ProtectionState
    let size: CGFloat

    var body: some View {
        // No .fill variant: the symbol's own filled ends carry the state.
        Image(systemName: state.symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .symbolEffect(.pulse, isActive: state == .starting)
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(state.color.gradient, in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
            .accessibilityHidden(true)
    }
}

private struct PowerSwitch: View {
    @ObservedObject var model: AppModel

    var body: some View {
        HStack(spacing: 8) {
            if model.pendingEnabled != nil || model.status.protection == .starting {
                ProgressView().controlSize(.small)
            }
            Toggle("VPN", isOn: Binding(get: { model.displayedEnabled }, set: { model.setRouting($0) }))
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(model.pendingEnabled != nil)
                .help(model.displayedEnabled ? "Выключить VPN" : "Включить VPN")
        }
    }
}

/// Both VPNs, each with the switch that keeps it in or out of use.
private struct TunnelRows: View {
    @ObservedObject var model: AppModel
    /// The window adds the way to a missing profile and to the log.
    var inWindow = false

    var body: some View {
        ForEach(VPNKind.allCases, id: \.self) { kind in
            TunnelRow(
                kind: kind,
                status: kind == .openVPN ? model.status.openVPN : model.status.amneziaWG,
                hasProfile: kind == .openVPN ? model.hasOpenVPN : model.hasExit,
                server: model.serverName(kind),
                warning: kind == .amneziaWG && model.settings.exitEngine == .xray ? model.xray?.warning : nil,
                inUse: model.uses(kind),
                canTurnOff: model.uses(kind == .openVPN ? .amneziaWG : .openVPN),
                onToggle: { model.setTunnel(kind, inUse: $0) },
                add: inWindow ? add(kind) : nil,
                onShowLog: inWindow ? { model.page = .diagnostics } : nil
            )
        }
    }

    /// The work profile is only ever a file; the personal one opens the sheet
    /// that takes a file or any link.
    private func add(_ kind: VPNKind) -> (title: String, action: () -> Void) {
        kind == .openVPN
            ? ("Добавить .ovpn…", { model.importFile(kind) })
            : ("Добавить…", { model.page = .profiles; model.addingExit = true })
    }
}

private struct TunnelRow: View {
    let kind: VPNKind
    let status: TunnelStatus
    let hasProfile: Bool
    let server: String?
    let warning: String?
    let inUse: Bool
    let canTurnOff: Bool
    let onToggle: (Bool) -> Void
    var add: (title: String, action: () -> Void)?
    var onShowLog: (() -> Void)?

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: kind.symbol)
                .foregroundStyle(.secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(kind.name)
                HStack(spacing: 5) {
                    if hasProfile, inUse { Circle().fill(status.phase.color).frame(width: 7, height: 7) }
                    Text(subtitle).lineLimit(2).help(subtitle)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if hasProfile, inUse, let warning {
                    Text(warning).font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if hasProfile, inUse, status.phase == .error, let onShowLog {
                Button("Журнал", action: onShowLog).controlSize(.small)
            }
            if !hasProfile, let add { Button(add.title, action: add.action) }
            // A VPN in use keeps its switch even without a profile: otherwise the
            // other VPN could never be left to run alone.
            if hasProfile || inUse {
                Toggle("Использовать \(kind.lowercasedName)", isOn: Binding(get: { inUse }, set: { onToggle($0) }))
                    .toggleStyle(.switch)
                    .controlSize(.mini)
                    .labelsHidden()
                    .disabled(inUse && !canTurnOff)
                    .help(inUse && !canTurnOff
                        ? "Хотя бы один VPN должен оставаться включённым"
                        : inUse ? "Не использовать \(kind.lowercasedName)" : "Использовать \(kind.lowercasedName)")
            }
        }
    }

    private var subtitle: String {
        guard hasProfile else { return "Профиль не добавлен" }
        guard inUse else {
            return kind == .openVPN
                ? "Не используется: рабочие адреса идут как обычный трафик"
                : "Не используется: остальной трафик идёт напрямую"
        }
        // The daemon says why; «Ошибка» alone sent people to the log for it.
        if status.phase == .error, let message = status.message { return message }
        let suffix = server.map { " · \($0)" } ?? ""
        guard status.phase == .connected else { return status.phase.russianTitle + suffix }
        let time: Date.FormatStyle = Calendar.current.isDateInToday(status.changedAt)
            ? .dateTime.hour().minute()
            : .dateTime.day().month().hour().minute()
        return "Подключён с \(status.changedAt.formatted(time))" + suffix
    }
}

private struct RouteRow: View {
    let symbol: String
    let title: String
    let detail: String?
    let target: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let detail { Text(detail).font(.caption).foregroundStyle(.secondary) }
            }
            Spacer()
            Text(target).foregroundStyle(.secondary)
        }
    }
}

private struct Banners: View {
    @ObservedObject var model: AppModel
    var insets = EdgeInsets(top: 12, leading: 20, bottom: 0, trailing: 20)

    var body: some View {
        // Modifiers on a Group reach each child, so no banner means no gap.
        Group {
            if let error = model.visibleError {
                MessageBanner(error, color: .red) { model.dismissError() }
            } else if let message = model.systemComponentMessage {
                MessageBanner(message, color: .orange, actions: model.componentFix.map { fix in
                    [(fix == .install ? "Установить…" : "Открыть настройки", { model.fixSystemComponent() })]
                } ?? [])
            } else if let update = model.update {
                UpdateBanner(model: model, update: update)
            }
        }
        .padding(insets)
    }
}

/// Two clicks, each the user's: download, then install, which takes VPN down.
private struct UpdateBanner: View {
    @ObservedObject var model: AppModel
    let update: AppModel.UpdateState

    var body: some View {
        let version = update.release.version
        switch update {
        case .available:
            MessageBanner("Доступна версия \(version)", color: .blue, symbol: "arrow.down.circle.fill", actions: [
                ("Что нового", { model.showReleaseNotes() }), ("Скачать", { model.downloadUpdate() }),
            ])
        case .downloading:
            MessageBanner("Скачивается обновление \(version)…", color: .blue, symbol: "arrow.down.circle.fill")
        case .ready:
            MessageBanner("Обновление \(version) скачано. VPN выключится на время обновления, Коммутатор перезапустится", color: .blue, symbol: "arrow.down.circle.fill", actions: [
                ("Что нового", { model.showReleaseNotes() }), ("Обновить и перезапустить…", { model.installUpdate() }),
            ])
        case .installing:
            MessageBanner("Устанавливается обновление \(version)…", color: .blue, symbol: "arrow.down.circle.fill")
        }
    }
}

private struct MessageBanner: View {
    let message: String
    let color: Color
    var symbol: String?
    /// The fix, where the banner itself can offer one.
    let actions: [(title: String, run: () -> Void)]
    let onDismiss: (() -> Void)?

    init(_ message: String, color: Color, symbol: String? = nil, actions: [(title: String, run: () -> Void)] = [], onDismiss: (() -> Void)? = nil) {
        self.message = message
        self.color = color
        self.symbol = symbol
        self.actions = actions
        self.onDismiss = onDismiss
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            // Errors are octagons elsewhere in the app; the triangle is for warnings.
            Image(systemName: symbol ?? (color == .red ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")).foregroundStyle(color)
            // No fixedSize: the window's minimum is measured at a near-zero width,
            // where a fixed height wraps into a column taller than the window and
            // SwiftUI centres the overflow, pushing the whole window up.
            Text(message)
                .frame(maxWidth: .infinity, alignment: .leading)
            ForEach(actions.indices, id: \.self) { index in Button(actions[index].title, action: actions[index].run) }
            if let onDismiss {
                Button(action: onDismiss) { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Скрыть сообщение")
            }
        }
        .font(.callout)
        .padding(10)
        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(color.opacity(0.35)))
    }
}

private struct Note: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}
