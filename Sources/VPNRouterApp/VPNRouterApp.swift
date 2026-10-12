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
        .commands { AppCommands(model: delegate.model) }

        MenuBarExtra(isInserted: $showsMenuBarExtra) {
            MenuContent(model: delegate.model)
        } label: {
            MenuBarLabel(model: delegate.model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Commands repeat the actions in the relevant toolbar, so keyboard users do
/// not have to discover a page-specific control first.
private struct AppCommands: Commands {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button("Настройки…") { show(.general) }
                .keyboardShortcut(",", modifiers: .command)
        }
        CommandMenu("Маршруты") {
            Button("Скопировать маршруты") { model.exportRules() }
            // The imported lists fill the draft on «Маршруты»: shown there, or not at all.
            Button("Вставить маршруты") {
                model.importRules()
                show(.rules)
            }
            Divider()
            Button("Как записывать") {
                model.showsRuleFormat = true
                show(.rules)
            }
        }
    }

    private func show(_ page: Page) {
        model.page = page
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "main")
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
        // Logout, restart and shutdown must not wait on a dialog.
        let quitBySystem = NSAppleEventManager.shared().currentAppleEvent?.attributeDescriptor(forKeyword: AEKeyword(kAEQuitReason)) != nil
        if !quitBySystem {
            NSApp.activate(ignoringOtherApps: true)
            guard model.settleRuleEdits() else { return .terminateCancel }
        }
        // The demo's VPN is made up: there is nothing to turn off.
        guard model.displayedEnabled, !XPCClient.isDemo else { return .terminateNow }
        // VPN outlives logout, restart and shutdown only if the app opens at login
        // to show it is on; otherwise it goes off quietly, as the daemon also
        // keeps it off after a boot without the app.
        if quitBySystem {
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
        let state = model.status.protection
        // A plain symbol at the size the menu bar picks: one sized by hand came
        // out taller than the bar, cut off and blurry on a 1x display. The bar's
        // own symbols have no side margins and a larger switch instead.
        Group {
            if let lever = state.leverColor {
                Image(state.menuBarSymbol).symbolRenderingMode(.palette).foregroundStyle(lever, .primary)
            } else {
                Image(state.menuBarSymbol)
            }
        }
        .accessibilityLabel("Коммутатор: \(model.status.protection.russianTitle)")
    }
}

extension OpenVPNRemote {
    /// «vpn.corp.com:1194 · UDP»
    var title: String {
        host + (port.map { ":\($0)" } ?? "") + (proto.map { " · \($0.uppercased())" } ?? "")
    }
}

extension ProtectionState {
    /// The menu bar's «Коммутатор» symbol from Config/Symbols.xcassets.
    var menuBarSymbol: String {
        switch self {
        case .off, .starting: "kommutator.bar.off"
        case .protected, .degraded: "kommutator.bar.on"
        case .error: "kommutator.bar.error"
        }
    }

    /// Off and connecting stay a plain template that follows the menu bar's theme;
    /// once up, the lever takes the state's colour over a base in the bar's text colour.
    var leverColor: Color? {
        switch self {
        case .off, .starting: nil
        case .protected: .green
        case .degraded: .yellow
        case .error: .red
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
        case .milliseconds(let value): value < 150 ? .green : .secondary
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
            guard let rest = settings.activeDefault, rest.path != .direct else { return "Сайты из направлений — по своим VPN, остальной трафик — напрямую" }
            return "Сайты из направлений — по своим VPN, остальной трафик — через «\(rest.name)»"
        case .degraded:
            let down = settings.activeDirections.filter { direction in
                tunnels[direction.id].map { $0.phase != .connected } ?? false
            }
            guard !down.isEmpty else { return "VPN подключены не полностью" }
            return down.map { direction in
                "«\(direction.name)»: " + (direction.blockWhenDown ? "заблокировано" : "напрямую")
            }.joined(separator: ", ") + " — пока VPN не подключится"
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

private let linkFormats = "Подходит файл .ovpn (OpenVPN), файл .conf AmneziaWG или WireGuard, ссылка vpn:// из Amnezia («Поделиться VPN»), ссылка vless://, hysteria2://, trojan://, ss://, vmess:// или адрес подписки https://…, как в Happ. Подписка обновляется сама; зашифрованные happ://crypt не поддерживаются."

// MARK: - Menu bar

/// Stacks, not a grouped Form: a Form's insets and section gaps are sized for a
/// settings window and made the menu twice as tall. The spacing is set here by
/// hand for the same reason, and rows go through MenuRowStyle to line the
/// switches up in one column.
private struct MenuContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            LabeledContent {
                PowerSwitch(model: model)
            } label: {
                Text("Коммутатор").font(.headline)
            }
            .padding(12)

            notices

            Divider()
            VStack(alignment: .leading, spacing: 8) {
                header("Направления")
                ForEach(model.settings.directions) { direction in
                    DirectionRows.row(model, direction, inWindow: false)
                }
                if model.statusLoaded, model.connections.isEmpty {
                    Button("Добавить VPN…") {
                        model.addingConnection = true
                        show(.profiles)
                    }
                }
            }
            .padding(12)

            // The connection check in brief: which country foreign and Russian
            // sites see you from. Details are left to the window.
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    header("Как вас видят сайты")
                    Spacer()
                    if model.checking {
                        ProgressView().controlSize(.small)
                    } else if let report = model.report {
                        Text(report.checkedAt.formatted(date: .omitted, time: .shortened))
                            .font(.caption).foregroundStyle(.secondary)
                            .help("Время проверки")
                    }
                    Button("Проверить", systemImage: "arrow.clockwise", action: model.runChecks)
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .help("Проверить ещё раз")
                        .disabled(model.checking)
                }
                seenAs("Зарубежные сайты", model.report?.cloudflare)
                seenAs("Российские сайты", model.report?.yandex)
            }
            .padding(12)

            Divider()
            HStack {
                Button("Открыть Коммутатор…") { show(nil) }
                Spacer()
                Button("Выйти") { NSApp.terminate(nil) }
            }
            .padding(12)
        }
        .labeledContentStyle(MenuRowStyle())
        .frame(width: 340)
    }

    private func header(_ title: String) -> some View {
        Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
    }

    /// What the window says in alerts and its toolbar, as rows in the menu:
    /// an alert from the menu bar would open behind other windows.
    @ViewBuilder
    private var notices: some View {
        if let error = model.visibleError {
            LabeledContent {
                Button("Скрыть", action: model.dismissError)
            } label: {
                Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            }
            .padding([.horizontal, .bottom], 12)
        } else if let message = model.systemComponentMessage {
            VStack(alignment: .leading) {
                Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                if let fix = model.componentFix {
                    Button(fix == .install ? "Установить…" : "Открыть настройки", action: model.fixSystemComponent)
                }
            }
            .padding([.horizontal, .bottom], 12)
        } else if model.update != nil {
            UpdateControl(model: model)
                .fixedSize()
                .padding([.horizontal, .bottom], 12)
        }
    }

    private func seenAs(_ title: String, _ result: EchoResult?) -> some View {
        LabeledContent(title) {
            if model.report == nil {
                Text(model.checking ? "…" : "—")
            } else if let result {
                Text(result.country.map(countryName) ?? result.ip ?? "ответили")
                    .textSelection(.enabled)
            } else {
                Label("нет ответа", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
    }

    private func show(_ page: Page?) {
        if let page { model.page = page }
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "main")
    }
}

/// LabeledContent outside a Form hugs its label, so each row's switch stood
/// wherever its text ended. This pushes the content to the trailing edge.
private struct MenuRowStyle: LabeledContentStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) { configuration.label }
            Spacer(minLength: 8)
            configuration.content
        }
    }
}

// MARK: - Main window

enum Page: String, CaseIterable, Identifiable {
    case overview, rules, profiles, general, diagnostics
    var id: Self { self }

    var title: String {
        switch self {
        case .overview: "Обзор"
        case .profiles: "VPN"
        case .rules: "Маршруты"
        case .general: "Общие"
        case .diagnostics: "Диагностика"
        }
    }

    var icon: Image {
        switch self {
        case .overview: Image("kommutator.off")
        case .profiles: Image(systemName: "key")
        case .rules: Image(systemName: "arrow.triangle.branch")
        case .general: Image(systemName: "gearshape")
        case .diagnostics: Image(systemName: "stethoscope")
        }
    }
}

private struct MainWindow: View {
    @ObservedObject var model: AppModel
    /// Asked once per message: some only inform, such as an update waiting for a reboot.
    @State private var dismissedComponent: String?

    var body: some View {
        GeometryReader { viewport in
            navigation
                .frame(width: viewport.size.width, height: viewport.size.height)
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

    private var navigation: some View {
        NavigationSplitView {
            List(Page.allCases, selection: $model.page) { page in
                Label {
                    Text(verbatim: page.title)
                } icon: {
                    page.icon
                }
                .labelStyle(.titleAndIcon)
                .tag(page)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 190, ideal: 200, max: 250)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(spacing: 0) {
                    Divider()
                    HStack {
                        VStack(alignment: .leading) {
                            Text("VPN")
                            Text(model.status.protection.russianTitle).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        PowerSwitch(model: model)
                    }
                    .padding()
                }
                .background(.bar)
            }
        } detail: {
            VStack(spacing: 0) {
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
            .toolbar {
                if model.update != nil {
                    ToolbarItem(placement: .automatic) { UpdateControl(model: model) }
                }
            }
        }
        // A failure the page has no better place for; a connection's own
        // failure shows next to it instead (see visibleError).
        .alert("Ошибка", isPresented: Binding(
            get: { model.visibleError != nil },
            set: { if !$0 { model.dismissError() } }
        )) {
            Button("OK") { model.dismissError() }
        } message: {
            Text(model.visibleError ?? "")
        }
        .alert("Системный компонент", isPresented: Binding(
            get: { model.systemComponentMessage.map { $0 != dismissedComponent } ?? false },
            set: { if !$0 { dismissedComponent = model.systemComponentMessage } }
        )) {
            if let fix = model.componentFix {
                Button(fix == .install ? "Установить…" : "Открыть настройки") { model.fixSystemComponent() }
            }
            Button(model.componentFix == nil ? "OK" : "Позже", role: .cancel) {}
        } message: {
            Text(model.systemComponentMessage ?? "")
        }
    }
}

private struct OverviewPage: View {
    @ObservedObject var model: AppModel
    @State private var checkHost = ""

    var body: some View {
        if model.statusLoaded, model.connections.isEmpty {
            ContentUnavailableView {
                Label("Сначала добавьте VPN", systemImage: "key")
            } description: {
                Text("Файл .ovpn или .conf, ссылка или подписка — на странице «VPN».")
            } actions: {
                Button("Добавить VPN…") {
                    model.page = .profiles
                    model.addingConnection = true
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Form {
                // No big status block: the state is already by the switch in the
                // sidebar, and what it means for traffic fits under the routes.
                Section {
                    ForEach(model.settings.directions) { direction in
                        DirectionRows.row(model, direction, inWindow: true)
                    }
                } header: {
                    Text("Направления")
                } footer: {
                    Note(model.status.summary(model.settings))
                }
                Section {
                    CheckRow(title: "Зарубежные сайты", result: echo(model.report?.cloudflare, url: NetworkProbes.cloudflareCheck))
                    CheckRow(title: "Российские сайты", result: echo(model.report?.yandex, url: NetworkProbes.yandexCheck))
                    HStack {
                        TextField("Сайт или IP", text: $checkHost, prompt: Text("site.org"))
                            .labelsHidden()
                            .onSubmit { model.checkRoute(checkHost) }
                        Button("Проверить сайт") { model.checkRoute(checkHost) }
                            .disabled(checkHost.trimmingCharacters(in: .whitespaces).isEmpty || model.checkingRoute)
                        if model.checkingRoute { ProgressView().controlSize(.small) }
                    }
                    if let check = model.routeCheck {
                        RouteCheckRow(check: check, via: model.via(check.interface))
                        HStack {
                            Spacer()
                            AddRuleMenu(model: model, host: check.host)
                        }
                        .controlSize(.small)
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
                    Note("cloudflare.com и yandex.ru отвечают, с каким адресом вас видят, — так же, как их видит браузер, с VPN и без. Страна, город и провайдер определяются по этому адресу через ipinfo.io. «Проверить сайт» открывает настоящее соединение и показывает, через что оно прошло, по применённым правилам. Какие соединения идут через что прямо сейчас — в «Диагностике», вкладка «Трафик».")
                }
            }
            .formStyle(.grouped)
        }
    }

    private func echo(_ result: EchoResult?, url: URL) -> CheckResult {
        var rows = [("Запрос", (url.host() ?? "") + url.path())]
        guard model.report != nil else { return .init(ok: false, rows: rows + [("Ответ", model.checking ? "проверка…" : "ещё не проверялось")]) }
        guard let result else { return .init(ok: false, rows: rows + [("Ответ", "не пришёл за 8 секунд")]) }
        if let ip = result.ip { rows.append(("Видят адрес", ip)) }
        if let place = place(result) { rows.append(("Откуда", place)) }
        if let org = result.org { rows.append(("Провайдер", org)) }
        rows.append(("Маршрут", model.via(result.interface)))
        rows.append(("Время", "\(result.milliseconds) мс"))
        return .init(ok: true, rows: rows)
    }
}

private struct CheckResult {
    var ok: Bool
    var rows: [(String, String)]
}

private struct CheckRow: View {
    let title: String
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
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
        }
    }
}

/// Every saved VPN, each with what belongs to it alone: its login, its first
/// server, its subscription. Which sites go through it is «Маршруты»' business.
private struct ProfilesPage: View {
    @ObservedObject var model: AppModel
    @State private var editing: EditedProfile?
    @State private var dropping = false
    @State private var dropError: String?

    var body: some View {
        Group {
            if model.statusLoaded, model.connections.isEmpty {
                ContentUnavailableView {
                    Label("VPN не добавлены", systemImage: "key")
                } description: {
                    Text("Файлы .ovpn и .conf можно просто перетащить в это окно.")
                } actions: {
                    Button("Добавить VPN…") { model.addingConnection = true }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Form {
                    ForEach(model.connections) { item in
                        ConnectionSection(model: model, item: item, onEdit: edit)
                    }
                    if let dropError {
                        Section { Label(dropError, systemImage: "xmark.octagon.fill").foregroundStyle(.red) }
                    }
                }
                .formStyle(.grouped)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack {
                    if dropping { ProgressView().controlSize(.small) }
                    Button { model.addingConnection = true } label: { Label("Добавить VPN", systemImage: "plus") }
                        .help("Добавить VPN: файл .ovpn или .conf, ссылку или подписку")
                }
            }
        }
        .sheet(item: $editing) { ProfileEditor(model: model, file: $0) }
        .sheet(isPresented: $model.addingConnection) { AddConnectionSheet(model: model) }
        .dropDestination(for: URL.self) { urls, _ in importDropped(urls) }
    }

    private func edit(_ item: ConnectionSummary) {
        guard item.kind != .xray else { return }
        Task {
            if let text = await model.profileText(item.id) {
                editing = .init(kind: item.kind == .openVPN ? .openVPN : .amneziaWG, text: text, connection: item.id)
            }
        }
    }

    private func importDropped(_ urls: [URL]) -> Bool {
        let accepted = urls.filter { AppModel.kind(of: $0) != nil }
        guard !accepted.isEmpty, !dropping else { return false }
        Task {
            dropping = true
            defer { dropping = false }
            dropError = nil
            for url in accepted {
                if let message = await model.addProfile(at: url) {
                    dropError = message
                    return
                }
            }
        }
        return true
    }
}

private struct ConnectionSection: View {
    @ObservedObject var model: AppModel
    let item: ConnectionSummary
    let onEdit: (ConnectionSummary) -> Void

    private var busy: Bool { model.busyConnection == item.id }
    private var users: [Direction] { model.settings.directions.filter { $0.connection == item.id } }

    var body: some View {
        Section {
            LabeledContent("Протокол", value: item.protocolTitle ?? item.kind.title)
            LabeledContent("Направления") {
                Text(users.isEmpty ? "не используется" : users.map { "«\($0.name)»" }.joined(separator: ", "))
                    .foregroundStyle(.secondary)
            }
            switch item.kind {
            case .openVPN: openVPNRows
            case .amneziaWG:
                hostPingRows(item.title)
            case .xray:
                if let xray = item.xray { xrayRows(xray) }
            }
            if let error = model.connectionErrors[item.id] {
                Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            }
            // In sight, not behind a menu: editing and removing a VPN were not
            // found there. Last row, as «Забыть эту сеть…» in System Settings.
            HStack {
                Spacer()
                if item.kind != .xray { Button("Изменить профиль…") { onEdit(item) } }
                Button("Удалить VPN…", role: .destructive) { model.deleteConnection(item) }
            }
            .disabled(busy)
        } header: {
            HStack {
                Text(item.title).lineLimit(1).truncationMode(.middle)
                Spacer()
                DelayedProgressView(active: busy)
            }
        }
    }

    /// A server of its own, not a subscription's list: ICMP to it, or with the
    /// VPN up, through the tunnel to 1.1.1.1, which answers.
    @ViewBuilder
    private func hostPingRows(_ host: String) -> some View {
        PingRow(ping: model.ping(host: host), checking: model.pinging.contains(host)) {
            model.pingHost(host, through: model.connectedInterface(of: item.id))
        }
        Note(model.connectedInterface(of: item.id).map { "Через туннель \($0) до 1.1.1.1: задержка до сервера и дальше, как её видит ваш трафик." }
            ?? "ICMP до сервера. Многие серверы и хостинги не отвечают на ping, хотя VPN через них работает: тогда здесь будет «нет ответа». Когда VPN подключён, ping идёт через туннель — это точнее.")
    }

    @ViewBuilder
    private var openVPNRows: some View {
        if let remotes = item.remotes, remotes.count > 1 {
            Picker("Сначала подключаться к", selection: Binding(
                get: { item.preferredRemote.flatMap { remotes.contains($0) ? $0 : nil } ?? remotes[0] },
                set: { model.preferRemote($0, for: item.id) }
            )) {
                ForEach(remotes, id: \.self) { remote in Text(remote.title).tag(remote) }
            }
            .disabled(busy)
            Note("Если выбранный сервер не ответит, OpenVPN попробует остальные по порядку из профиля.")
        }
        // The server it tries first, as the route editor pings it.
        if let host = (item.preferredRemote ?? item.remotes?.first)?.host { hostPingRows(host) }
        if item.needsLogin {
            LabeledContent("Логин") {
                TextField("Логин", text: Binding(
                    get: { model.usernames[item.id] ?? item.username ?? "" },
                    set: { model.usernames[item.id] = $0 }
                ))
                .labelsHidden()
                .onSubmit { model.saveCredentials(item.id) }
            }
        }
        LabeledContent("Пароль") {
            HStack {
                SecureField("Пароль", text: Binding(
                    get: { model.passwords[item.id] ?? "" },
                    set: { model.passwords[item.id] = $0 }
                ), prompt: Text(item.hasPassword ? "Сохранён" : "Не задан"))
                .labelsHidden()
                .onSubmit { model.saveCredentials(item.id) }
                .disabled(busy)
                Button("Сохранить") { model.saveCredentials(item.id) }
                    .disabled(!model.credentialsChanged(item.id) || busy)
            }
        }
    }

    @ViewBuilder
    private func xrayRows(_ xray: XraySummary) -> some View {
        if xray.fromSubscription {
            LabeledContent("Подписка") {
                HStack {
                    CompactSubscriptionStatus(xray: xray, status: SubscriptionAnnouncement(xray.announce).status)
                    Spacer()
                    Menu {
                        Button("Обновить") { model.updateXray(.init(connection: item.id, refresh: true)) }
                        if let url = xray.supportURL { Link("Поддержка", destination: url) }
                        if let url = xray.webPageURL { Link("Сайт", destination: url) }
                        if let updated = xray.updatedAt {
                            Text("Обновлена \(updated.formatted(Calendar.current.isDateInToday(updated) ? .dateTime.hour().minute() : .dateTime.day().month().hour().minute()))")
                        }
                    } label: {
                        Text("Подписка")
                    }
                    .fixedSize()
                    .disabled(busy)
                }
            }
            if let details = SubscriptionAnnouncement(xray.announce).details { Note(details) }
            if let warning = xray.warning {
                Label(warning, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
        HStack {
            Text(xray.servers.count == 1 ? "Сервер" : "Серверы: \(xray.servers.count)")
            Spacer()
            if model.pingingServers == item.id {
                Text("Проверено \(model.pingedServerCount) из \(model.pingableServerCount)").foregroundStyle(.secondary)
            }
            Button("Проверить ping") { model.pingServers(item.id) }
                .disabled(model.pingingServers != nil)
        }
        // Ids unique across the page: the Form is one table, and two
        // subscriptions both numbering their rows from 0 broke its layout.
        ForEach(xray.servers.indices.map { (id: "\(item.id)#\($0)", server: xray.servers[$0]) }, id: \.id) { row in
            LabeledContent(row.server.name, value: row.server.protocolTitle + " · " + (model.ping(of: row.server)?.text ?? "—"))
                .help(row.server.endpoint ?? "Адрес не указан")
        }
    }
}

private struct EditedProfile: Identifiable {
    let id = UUID()
    let kind: VPNKind
    let text: String
    let connection: UUID
}

/// The stored profile as text. The file it once came from is not involved.
private struct ProfileEditor: View {
    @ObservedObject var model: AppModel
    let file: EditedProfile
    @State private var text: String
    @State private var failure: String?
    @State private var saving = false
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, file: EditedProfile) {
        self.model = model
        self.file = file
        _text = State(initialValue: file.text)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                PlainTextEditor(text: $text)
                if let failure {
                    Divider()
                    Label(failure, systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
            }
            .navigationTitle("Профиль \(file.kind.title)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                        .disabled(saving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    HStack {
                        if saving { ProgressView().controlSize(.small) }
                        Button("Сохранить и применить") {
                            guard !saving else { return }
                            saving = true
                            Task {
                                failure = await model.saveProfile(text, as: file.kind, connection: file.connection)
                                saving = false
                                if failure == nil { dismiss() }
                            }
                        }
                        .keyboardShortcut("s")
                        .disabled(text == file.text || saving)
                    }
                }
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

/// Every way to add a VPN, in one place. The kind is read from what was
/// given. A failed link stays in the field, so a mistyped address can be fixed
/// rather than retyped.
private struct AddConnectionSheet: View {
    @ObservedObject var model: AppModel
    @State private var source = ""
    @State private var dropTargeted = false
    @State private var failure: String?
    @State private var saving = false
    /// The OpenVPN just added asks for a login: the sheet asks for it next.
    @State private var credentialsFor: UUID?
    @Environment(\.dismiss) private var dismiss

    private var trimmed: String { source.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        NavigationStack {
            if let id = credentialsFor {
                CredentialsStep(model: model, id: id) { dismiss() }
            } else {
                addForm
            }
        }
        .frame(width: 500)
        .frame(minHeight: 360)
        // A slot picked on «Маршруты» is for this one VPN only.
        .onDisappear { model.adoptSlot = nil }
    }

    private var addForm: some View {
            Form {
                Section {
                    GroupBox {
                        VStack(spacing: 8) {
                            Image(systemName: dropTargeted ? "arrow.down.doc.fill" : "arrow.down.doc")
                                .font(.largeTitle)
                                .foregroundStyle(dropTargeted ? Color.accentColor : Color.secondary)
                            Text(dropTargeted ? "Отпустите файл" : "Перетащите сюда файл .ovpn или .conf")
                                .foregroundStyle(dropTargeted ? Color.accentColor : Color.secondary)
                            Button("Выбрать файл…", action: chooseFile)
                                .disabled(saving)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .dropDestination(for: URL.self) { urls, _ in
                        importDropped(urls)
                    } isTargeted: { dropTargeted = $0 }
                }
                Section {
                    TextField("Ссылка", text: $source, prompt: Text("Ссылка из Amnezia или Happ"))
                        .onSubmit(add)
                        .disabled(saving)
                    DisclosureGroup("Что подходит") { Note(linkFormats) }
                }
                if let failure {
                    Section {
                        Label(failure, systemImage: "xmark.octagon.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Новый VPN")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                        .disabled(saving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    HStack {
                        if saving { ProgressView().controlSize(.small) }
                        Button("Добавить", action: add)
                            .keyboardShortcut(.defaultAction)
                            .disabled(trimmed.isEmpty || saving)
                    }
                }
            }
    }

    private func add() {
        guard !trimmed.isEmpty, !saving else { return }
        save { await model.addLink(trimmed) }
    }

    private func chooseFile() {
        guard let url = model.chooseProfileFile(nil) else { return }
        save { await model.addProfile(at: url) }
    }

    private func importDropped(_ urls: [URL]) -> Bool {
        guard let url = urls.first(where: { AppModel.kind(of: $0) != nil }), !saving else { return false }
        save { await model.addProfile(at: url) }
        return true
    }

    private func save(_ operation: @escaping @MainActor () async -> String?) {
        saving = true
        failure = nil
        Task {
            failure = await operation()
            saving = false
            guard failure == nil else { return }
            if let id = model.lastAdded, model.needsCredentials(id) { credentialsFor = id } else { dismiss() }
        }
    }
}

/// Right after an OpenVPN profile that asks for a login: asked while the user
/// still has it at hand, rather than later as a connection that failed.
private struct CredentialsStep: View {
    @ObservedObject var model: AppModel
    let id: UUID
    let done: () -> Void
    @State private var failure: String?
    @State private var saving = false

    private var password: String { model.passwords[id] ?? "" }

    var body: some View {
        Form {
            Section {
                TextField("Логин", text: Binding(
                    get: { model.usernames[id] ?? model.connection(id)?.username ?? "" },
                    set: { model.usernames[id] = $0 }
                ))
                SecureField("Пароль", text: Binding(get: { password }, set: { model.passwords[id] = $0 }))
                    .onSubmit(save)
            } footer: {
                Note("Профиль спрашивает логин и пароль — те же, что в официальном клиенте OpenVPN. Поменять их можно на странице «VPN».")
            }
            if let failure {
                Section { Label(failure, systemImage: "xmark.octagon.fill").foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Логин и пароль")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Позже", action: done)
                    .keyboardShortcut(.cancelAction)
                    .disabled(saving)
            }
            ToolbarItem(placement: .confirmationAction) {
                HStack {
                    if saving { ProgressView().controlSize(.small) }
                    Button("Сохранить", action: save)
                        .keyboardShortcut(.defaultAction)
                        .disabled(saving || password.isEmpty)
                }
            }
        }
    }

    private func save() {
        guard !saving, !password.isEmpty else { return }
        saving = true
        failure = nil
        Task {
            failure = await model.storeCredentials(id)
            saving = false
            if failure == nil { done() }
        }
    }
}

/// Status, expiry and traffic in two short lines — just enough to pick a
/// server by. Everything else about the subscription is in the ⋯ menu.
private struct CompactSubscriptionStatus: View {
    let xray: XraySummary
    let status: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                if let status { Text(status) }
                if let expires = xray.expiresAt {
                    if status != nil { Text("·").foregroundStyle(.secondary) }
                    Text(expires < .now ? "истекла" : "до \(expires.formatted(date: .abbreviated, time: .omitted))")
                        .foregroundStyle(expires.timeIntervalSinceNow < 3 * 86_400 ? .orange : .secondary)
                }
            }
            .font(.callout)
            if let used = xray.usedBytes {
                Text(trafficText(used)).font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private func trafficText(_ used: Int64) -> String {
        let usedText = ByteCountFormatter.string(fromByteCount: used, countStyle: .file)
        guard let total = xray.totalBytes, total > 0 else { return "\(usedText), без лимита" }
        return "\(usedText) из \(ByteCountFormatter.string(fromByteCount: total, countStyle: .file))"
    }
}

/// Shared by every ping value: the value plus a check on request, since a lost
/// packet or a still-settling tunnel can flip one check to «нет ответа» that
/// the next one answers fine. Laid out as a System Settings row with an action.
private struct PingRow: View {
    let ping: PingState?
    let checking: Bool
    let retry: () -> Void

    var body: some View {
        LabeledContent("Ping") {
            HStack {
                if checking {
                    ProgressView().controlSize(.small)
                } else if let ping {
                    Text(ping.text).foregroundStyle(ping.color)
                } else {
                    Text("—").foregroundStyle(.secondary)
                }
                Button("Проверить", action: retry)
                    .disabled(checking)
            }
        }
    }
}

/// Some providers put a human-readable status in the first announcement line.
/// Keep arbitrary provider text intact, but present that common field as metadata.
private struct SubscriptionAnnouncement {
    let status: String?
    let details: String?

    init(_ raw: String?) {
        guard let raw else {
            status = nil
            details = nil
            return
        }
        var lines = raw.split(whereSeparator: \.isNewline).map(String.init)
        var parsedStatus: String?
        if let first = lines.first {
            for marker in ["Подписка:", "Subscription:"] {
                guard let range = first.range(of: marker, options: .caseInsensitive) else { continue }
                let value = first[range.upperBound...].trimmingCharacters(in: .whitespaces)
                if !value.isEmpty {
                    switch value.lowercased() {
                    case "active": parsedStatus = "Активна"
                    case "inactive": parsedStatus = "Неактивна"
                    case "expired": parsedStatus = "Истекла"
                    default: parsedStatus = value
                    }
                    lines.removeFirst()
                }
                break
            }
        }
        let remaining = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        status = parsedStatus
        details = remaining.isEmpty ? nil : remaining
    }
}

/// The routes, in the order that settles a site two of them claim, and the
/// one picked for editing. Everything here is a draft until «Применить».
private struct RulesPage: View {
    @ObservedObject var model: AppModel
    @State private var exported = false

    var body: some View {
        VStack(spacing: 0) {
            HSplitView {
                DirectionList(model: model)
                    .frame(minWidth: 180, idealWidth: 240, maxWidth: 400)
                // A container of its own, not a Group: a Group hands the split view the
                // editor itself, which is replaced on every pick and reset the divider.
                ZStack {
                    if let id = model.selectedDirection, model.routing.directions.contains(where: { $0.id == id }) {
                        DirectionEditor(model: model, id: id)
                            .id(id)
                    } else {
                        ContentUnavailableView("Выберите направление", systemImage: "arrow.triangle.branch", description: Text("Или добавьте новое кнопкой «+»."))
                    }
                }
                .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
            }
            // At the foot of the page, as in the old Network pane: always in place,
            // active only once there is something to apply. Under the split view,
            // not a safe-area inset over it: the inset does not reach the forms
            // inside, and it hid their last rows.
            Divider()
            HStack {
                if model.rulesError != nil {
                    Label("Ошибка в правилах", systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                } else if model.rulesChanged {
                    Label("Есть неприменённые изменения", systemImage: "exclamationmark.circle.fill").foregroundStyle(.orange)
                } else {
                    Text("Маршруты применены").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Отменить", action: model.revertRules)
                    .disabled(!model.rulesChanged)
                Button("Применить", action: model.saveRules)
                    .keyboardShortcut("s")
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.rulesChanged || model.rulesError != nil)
            }
            .padding()
            .background(.bar)
        }
        .sheet(isPresented: $model.addingConnection) { AddConnectionSheet(model: model) }
        .onAppear {
            if model.selectedDirection == nil { model.selectedDirection = model.routing.directions.first?.id }
        }
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                Button {
                    model.exportRules()
                    exported = true
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        exported = false
                    }
                } label: {
                    // Words, not an icon: the icons said nothing, and icon with title drew broken.
                    Text(exported ? "Скопировано в буфер обмена" : "Скопировать маршруты")
                }
                .help("Скопировать в буфер обмена названия направлений и их списки сайтов — чтобы вставить на другом Mac или отправить кому-то. Сами VPN не копируются")
                Button("Вставить маршруты", action: model.importRules)
                .help("Вставить направления и списки сайтов, скопированные кнопкой «Скопировать маршруты». Применить их останется кнопкой «Применить»")
            }
        }
    }
}

/// Over a list of sites: what it is for, with how to write it right by it.
private struct RuleHeader: View {
    let title: String
    @Binding var showsFormat: Bool

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            HelpLink { showsFormat.toggle() }
                .popover(isPresented: $showsFormat, arrowEdge: .trailing) { FormatHelp() }
                .help("Как записывать")
        }
    }
}

private struct DirectionList: View {
    @ObservedObject var model: AppModel

    var body: some View {
        List(selection: $model.selectedDirection) {
            ForEach(model.routing.directions) { direction in
                // A line each, not side by side: in a narrow list they were cut to «…».
                VStack(alignment: .leading, spacing: 2) {
                    Text(direction.name).lineLimit(1)
                        .foregroundStyle(direction.enabled ? .primary : .secondary)
                    Text(model.vpnTitle(direction))
                        .font(.subheadline).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    let notes = [direction.enabled ? nil : "Выключено", model.routing.defaultDirection == direction.id ? "Остальной трафик" : nil].compactMap { $0 }
                    if !notes.isEmpty {
                        Text(notes.joined(separator: " · ")).font(.subheadline).foregroundStyle(.tertiary)
                    }
                }
                .padding(.vertical, 2)
                .tag(direction.id)
                .contextMenu {
                    Button("Удалить направление…", role: .destructive) { model.deleteDirection(direction.id) }
                }
            }
            .onMove(perform: model.moveDirections)
        }
        .listStyle(.inset)
        // The list's own add and remove, under it as in System Settings.
        .safeAreaInset(edge: .bottom) {
            HStack {
                ControlGroup {
                    Button(action: model.addDirection) { Label("Добавить направление", systemImage: "plus") }
                    Button {
                        if let id = model.selectedDirection { model.deleteDirection(id) }
                    } label: { Label("Удалить направление", systemImage: "minus") }
                        .disabled(model.selectedDirection == nil)
                }
                .fixedSize()
                Spacer()
            }
            .padding()
        }
    }
}

private struct DirectionEditor: View {
    @ObservedObject var model: AppModel
    let id: UUID

    /// By id, not index: a route removed or moved under the editor must not
    /// leave it writing into its neighbour.
    private var direction: Binding<Direction> {
        Binding(
            get: { model.routing.directions.first { $0.id == id } ?? Direction(id: id, name: "", path: .unset) },
            set: { value in
                guard let index = model.routing.directions.firstIndex(where: { $0.id == id }) else { return }
                model.routing.directions[index] = value
            }
        )
    }
    private var connection: ConnectionSummary? { model.connection(direction.wrappedValue.connection) }

    var body: some View {
        Form {
            if let error = model.rulesError {
                Section { Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red) }
            }
            Section {
                TextField("Название", text: direction.name)
                Picker("VPN", selection: Binding(
                    get: { direction.wrappedValue.path },
                    set: { path in
                        var value = direction.wrappedValue
                        // The server of another subscription means nothing here. A route
                        // waiting for its VPN is off for want of one, so picking one turns it on.
                        value.server = nil
                        if case .vpn = path, value.path == .unset { value.enabled = true }
                        value.path = path
                        direction.wrappedValue = value
                    }
                )) {
                    Text("Без VPN").tag(Direction.Path.direct)
                    ForEach(model.connections) { item in
                        Text("\(item.title) · \(item.protocolTitle ?? item.kind.title)").tag(Direction.Path.vpn(item.id))
                    }
                    if direction.wrappedValue.path == .unset || (direction.wrappedValue.connection != nil && connection == nil) {
                        Text("Не выбран").tag(direction.wrappedValue.path)
                    }
                }
                if let connection, let xray = connection.xray, xray.servers.count > 1 {
                    Picker("Сервер", selection: Binding(
                        get: { model.serverIndex(direction.wrappedValue, xray) },
                        set: { index in
                            guard xray.servers.indices.contains(index) else { return }
                            direction.wrappedValue.server = .init(xray.servers[index])
                        }
                    )) {
                        ForEach(Array(xray.servers.enumerated()), id: \.offset) { index, server in
                            Text("\(server.name) · \(server.protocolTitle)").tag(index)
                        }
                    }
                }
                pingRow
                // «Без VPN» is a choice made, not a VPN missing.
                if direction.wrappedValue.path != .direct {
                    HStack {
                        Spacer()
                        Button("Добавить новый VPN…") { model.addVPN(for: id) }
                    }
                }
                Toggle(isOn: Binding(
                    get: { model.routing.defaultDirection == id },
                    set: { model.routing.defaultDirection = $0 ? id : (model.routing.defaultDirection == id ? nil : model.routing.defaultDirection) }
                )) {
                    Text("Для остального трафика")
                    Text("Сюда пойдёт всё, чего нет в правилах других направлений, поэтому своих правил ему не нужно")
                }
                if direction.wrappedValue.path != .direct {
                    Toggle(isOn: direction.blockWhenDown) {
                        Text("Блокировать, если VPN отключился")
                        Text("Пока VPN не подключён, сайты направления не открываются. Выключено — идут напрямую")
                    }
                }
            } header: {
                HStack {
                    Text(direction.wrappedValue.name.isEmpty ? "Направление" : direction.wrappedValue.name)
                    Spacer()
                    // On/off belongs to the whole route, so it sits by its name, as in System Settings.
                    Toggle("Включено", isOn: direction.enabled)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                        .labelsHidden()
                        .help(direction.wrappedValue.enabled ? "Включено. Выключено — его сайты идут туда же, куда остальной трафик" : "Выключено: его сайты идут туда же, куда остальной трафик")
                }
            }
            // The rest comes here anyway: rules of its own would change nothing.
            if model.routing.defaultDirection != id {
                Section {
                    RuleEditor(text: Binding(
                        get: { model.routing.texts[id] ?? "" },
                        set: { model.routing.texts[id] = $0 }
                    ), placeholder: "site.org\n10.0.0.0/8")
                } header: {
                    RuleHeader(title: "Правила", showsFormat: $model.showsRuleFormat)
                } footer: {
                    Note("Сайты, IP-адреса и диапазоны, по одному в строке. Записей: \(entries(model.routing.texts[id] ?? ""))."
                        + (model.routing.directions.count > 1 ? " Если сайт есть в правилах нескольких направлений, он пойдёт через то, что выше в списке, даже если ниже правило точнее. Порядок меняется перетаскиванием." : ""))
                }
            }
            if let connection, connection.kind == .openVPN { ServerSentSection(connection: connection) }
        }
        .formStyle(.grouped)
    }

    private func entries(_ text: String) -> Int {
        text.split(whereSeparator: \.isNewline).filter { !$0.allSatisfy(\.isWhitespace) }.count
    }

    /// Of the server the route actually uses, so a slow one is seen before switching.
    @ViewBuilder
    private var pingRow: some View {
        if let connection {
            switch connection.kind {
            case .xray:
                if let xray = connection.xray, xray.servers.indices.contains(model.serverIndex(direction.wrappedValue, xray)) {
                    let server = xray.servers[model.serverIndex(direction.wrappedValue, xray)]
                    if let endpoint = server.endpoint {
                        PingRow(ping: model.ping(of: server), checking: model.pinging.contains(endpoint)) { model.pingServer(server) }
                    }
                }
            case .amneziaWG:
                hostPing(connection.title, connection.id)
            case .openVPN:
                if let host = (connection.preferredRemote ?? connection.remotes?.first)?.host { hostPing(host, connection.id) }
            }
        }
    }

    private func hostPing(_ host: String, _ connection: UUID) -> some View {
        PingRow(ping: model.ping(host: host), checking: model.pinging.contains(host)) {
            model.pingHost(host, through: model.connectedInterface(of: connection))
        }
    }
}

/// What an OpenVPN profile and its server route by themselves: seen here, it
/// is clear what needs no rule and what still does. Kept from the last
/// connection, so it is there with the VPN off too.
private struct ServerSentSection: View {
    let connection: ConnectionSummary

    var body: some View {
        Section {
            if let routes = connection.profileRoutes, !routes.isEmpty {
                LabeledContent("Сети из профиля", value: routes.joined(separator: "\n"))
            }
            if let pushed = connection.pushed {
                LabeledContent("Сети", value: pushed.routes.isEmpty ? "—" : pushed.routes.joined(separator: "\n"))
                LabeledContent("Домены", value: pushed.domains.isEmpty ? "—" : pushed.domains.joined(separator: "\n"))
                LabeledContent("DNS", value: pushed.dns.isEmpty ? "—" : pushed.dns.joined(separator: "\n"))
            } else {
                Text("Появится после первого подключения").foregroundStyle(.secondary)
            }
        } header: {
            HStack {
                Text("От сервера")
                if let received = connection.pushed?.receivedAt {
                    Text("· получено \(received.formatted(Calendar.current.isDateInToday(received) ? .dateTime.hour().minute() : .dateTime.day().month().hour().minute()))")
                        .foregroundStyle(.secondary)
                }
            }
        } footer: {
            Note("Эти сети и домены сервер присылает сам — вписывать их в правила не нужно. Рабочие сайты с обычными интернет-адресами сервер не присылает: их впишите в правила.")
        }
    }
}

/// «Добавить в «Работа»» for any route: the site lands in its rules, applied.
private struct AddRuleMenu: View {
    @ObservedObject var model: AppModel
    let host: String

    var body: some View {
        Menu("Добавить в направление") {
            // Not the rest's route: applying drops its rules, so the site would not be kept.
            ForEach(model.settings.directions.filter { $0.id != model.settings.defaultDirection }) { direction in
                Button("«\(direction.name)»") { model.addRule(host, to: direction.id) }
            }
        }
        .fixedSize()
        .help("Сайт попадёт в правила направления, и они сразу применятся")
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
                    .map { $0.contains("://") ? RoutingDraft.site($0.trimmingCharacters(in: .whitespaces)) : $0 }
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
    @State private var showsResolving = false
    @State private var showsBypasses = false

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
                UserAgentRow(model: model)
            } header: {
                Text("Подписки")
            }
            Section {
                DisclosureGroup(isExpanded: $showsResolving) {
                    VStack(alignment: .leading, spacing: 10) {
                        Limitation(
                            title: "DNS направления",
                            text: "Имя сайта из направления Коммутатор спрашивает у DNS его VPN через туннель: у OpenVPN — тот, что прислал сервер, у AmneziaWG — «DNS =» из профиля, у Xray — 1.1.1.1 и 8.8.8.8. Если у VPN своего DNS нет, спрашивается DNS текущей сети, иначе направление не работало бы вовсе. Пока VPN не подключён и включено «Блокировать, если VPN отключился», имена его сайтов не узнаются."
                        )
                        Limitation(
                            title: "Сети и домены от рабочего сервера",
                            text: "Сервер OpenVPN при подключении сам сообщает свои внутренние сети и домены, а в профиле бывают строки route. Всё это сразу идёт через его направление, вписывать в правила не нужно, — список виден на «Маршрутах» в блоке «От сервера». Если два рабочих VPN называют своими одни и те же сети, их получает то направление, что выше в списке."
                        )
                    }
                } label: {
                    // On macOS only the chevron of a DisclosureGroup toggles it: the title
                    // is made a button too, so clicking the words opens it as well.
                    Button("Как направления узнают адреса и сети") { withAnimation { showsResolving.toggle() } }
                        .buttonStyle(.plain)
                }
            }
            Section {
                // Folded: it matters once a site goes the wrong way, not every visit.
                DisclosureGroup(isExpanded: $showsBypasses) {
                    VStack(alignment: .leading, spacing: 10) {
                        Note("Коммутатор видит, какой адрес DNS вернул для сайта, и направляет трафик на этот адрес. Всё, что узнаёт адрес мимо него, идёт по общему правилу. Правил для IP-адресов и диапазонов это не касается.")
                        Limitation(
                            title: "Безопасный DNS в браузере (DoH)",
                            text: "Браузер спрашивает адреса у своего DNS по шифрованному каналу, мимо Коммутатора: сайт из направления пойдёт туда же, куда остальной трафик. Выключите: Chrome — Настройки → Конфиденциальность и безопасность → Безопасность → «Использовать безопасный DNS»; Edge — Настройки → Конфиденциальность, поиск и службы → Безопасность; Firefox — Настройки → Приватность и защита → «DNS через HTTPS»."
                        )
                        Limitation(
                            title: "Частный узел iCloud (Private Relay)",
                            text: "Safari и часть трафика системы идут через серверы Apple, правила к ним не применяются. Выключите: Системные настройки → ваше имя → iCloud → Частный узел."
                        )
                        Limitation(
                            title: "Адреса, которые приложение уже помнит",
                            text: "Сайт, открытый до включения VPN или до изменения правил, может до минуты идти прежним путём, а уже открытое соединение — до своего закрытия."
                        )
                        Limitation(
                            title: "Общие адреса CDN",
                            text: "Трафик разводится по адресу, а не по имени сайта. Если сайты из разных направлений получили один адрес (так бывает у Cloudflare и других CDN), оба пойдут через то направление, что выше в списке, — пока открыто соединение и ещё минуту после. «Проверить сайт» на «Обзоре» показывает, какой сайт занял адрес."
                        )
                    }
                } label: {
                    Button("Что обходит правила для сайтов") { withAnimation { showsBypasses.toggle() } }
                        .buttonStyle(.plain)
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
    }
}

/// One User-Agent for every subscription: providers tell clients apart by it,
/// and some hand a list only to the client they know.
private struct UserAgentRow: View {
    @ObservedObject var model: AppModel
    @State private var agent = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("User-Agent") {
                HStack {
                    TextField("User-Agent", text: $agent, prompt: Text(XrayProfileParser.defaultUserAgent))
                        .labelsHidden()
                        .onAppear { agent = model.settings.subscriptionUserAgent ?? "" }
                        .onSubmit(apply)
                    Button("Применить", action: apply)
                        .disabled(agent.trimmingCharacters(in: .whitespaces) == (model.settings.subscriptionUserAgent ?? ""))
                }
            }
            Note("С ним Коммутатор загружает все подписки; после изменения они сразу обновятся. Пусто — \(XrayProfileParser.defaultUserAgent).")
        }
    }

    private func apply() {
        let value = agent.trimmingCharacters(in: .whitespaces)
        model.settings.subscriptionUserAgent = value.isEmpty ? nil : value
        model.updateGeneralSettings()
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
    }
}

private struct DiagnosticsPage: View {
    @ObservedObject var model: AppModel
    @State private var showsTraffic = false
    @State private var logQuery = ""
    @State private var trafficFilter = ""

    var body: some View {
        Group {
            if showsTraffic {
                TrafficView(model: model, traffic: model.traffic, filter: trafficFilter)
            } else {
                LogView(model: model, query: logQuery)
            }
        }
        // The toolbar holds only what both tabs share: the switcher, centred, and
        // one search field. With each tab's own buttons there, the switcher sat
        // centred between different widths and jumped on every switch; those
        // buttons are in each tab's bar instead.
        .searchable(
            text: showsTraffic ? $trafficFilter : $logQuery,
            placement: .toolbar,
            prompt: showsTraffic ? "Сайт, адрес или приложение" : "Поиск по журналу"
        )
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

/// A tab's own controls, over its content and under the shared toolbar.
private struct DiagnosticsBar<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) {
            HStack { content }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            Divider()
        }
    }
}

/// The daemon's log as it is written, the way a terminal tail shows it.
private struct LogView: View {
    @ObservedObject var model: AppModel
    let query: String
    @State private var follow = true
    @State private var copied = false
    @State private var limit = 20

    private var lines: [String] {
        let needle = query.trimmingCharacters(in: .whitespaces)
        return (needle.isEmpty ? model.logLines : model.logLines.filter { $0.localizedCaseInsensitiveContains(needle) }).suffix(limit)
    }

    var body: some View {
        VStack(spacing: 0) {
            DiagnosticsBar {
                Toggle("Прокручивать к новым", isOn: $follow).toggleStyle(.checkbox)
                Picker("Показывать", selection: $limit) {
                    ForEach([20, 50, 100, 200], id: \.self) { Text("Последние \($0)").tag($0) }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .fixedSize()
                Spacer()
                Button(copied ? "Скопировано" : "Скопировать") {
                    model.copyDiagnostics(lines)
                    copied = true
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        copied = false
                    }
                }
                .help("Показанные строки журнала вместе со сведениями о Mac и приложении для разбора. Пароли в журнал не попадают")
            }
            Text(model.diagnostics)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            Divider()
            LogText(lines: lines, follow: follow)
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
    let filter: String
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
            DiagnosticsBar {
                Toggle("Записывать соединения", isOn: $model.settings.watchTraffic).toggleStyle(.checkbox)
                Spacer()
                Button("Очистить", action: traffic.clear)
                    .disabled(traffic.entries.isEmpty)
                Button { showsHelp.toggle() } label: {
                    Label("Как читать", systemImage: "questionmark.circle")
                }
                .popover(isPresented: $showsHelp, arrowEdge: .bottom) { TrafficHelp() }
            }
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
                            Image(systemName: "circle.fill")
                                .font(.caption2)
                                .foregroundStyle(Self.color(entry.via))
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
                        Menu("Добавить \(host) в направление") {
                            // Not the rest's route: applying drops its rules, so the site would not be kept.
                            ForEach(model.settings.directions.filter { $0.id != model.settings.defaultDirection }) { direction in
                                Button("«\(direction.name)»") { model.addRule(host, to: direction.id) }
                            }
                        }
                        Divider()
                        Button("Скопировать \(host)") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(host, forType: .string)
                        }
                    }
                }
            }
        }
        .onChange(of: model.settings.watchTraffic) { _, _ in model.updateGeneralSettings() }
    }

    private static func color(_ via: String) -> Color {
        if via.hasPrefix("Чужой") { return .orange }
        if via.hasPrefix("Напрямую") || via.hasPrefix("Закрытый") { return .gray }
        return .purple
    }
}

/// Why a row reads as it does, for the tooltip over it: a direct row or a
/// bare address looked like a leak when it was only older than the tunnel.
private extension TrafficEntry {
    /// The daemon's own lookups. Each route's names are asked of its own
    /// resolver, through its own tunnel, so the path names it.
    var routerDNS: (label: String, help: String)? {
        guard owner.process == "VPNRouterDaemon", flow.port == "53" else { return nil }
        if via.hasPrefix("Напрямую") { return ("DNS текущей сети", "Коммутатор спрашивает имя у DNS вашей сети") }
        if via.hasPrefix("Чужой") || via.hasPrefix("Закрытый") { return nil }
        return ("DNS «\(via)»", "Коммутатор спрашивает имя сайта у DNS этого направления через его туннель")
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
                    (Color.purple, "Через VPN направления — его название"),
                    (.gray, "Напрямую — по правилам или потому, что открыто раньше VPN; «Закрытый интерфейс» — прежний туннель"),
                    (.orange, "Чужой туннель — его создала другая программа"),
                ], id: \.1) { color, meaning in
                    GridRow {
                        Image(systemName: "circle.fill")
                            .font(.caption2)
                            .foregroundStyle(color)
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
                    Text("DNS «Работа»").font(.callout.weight(.medium))
                    Text("Запрос имени от самого Коммутатора. Имя сайта он спрашивает у DNS того направления, которому сайт принадлежит, через его туннель; для направлений без VPN — у DNS вашей сети.")
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
            if let shared = check.sharedWith {
                Note("Этот адрес последним получил сайт \(shared): у сайтов общий адрес, и путь выбрал тот, чьё правило выше в списке направлений.")
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


// MARK: - Shared pieces

/// Fast daemon replies should feel immediate, not flash a spinner for one frame.
/// The standard progress control appears only when an operation is perceptible.
private struct DelayedProgressView: View {
    let active: Bool
    @State private var visible = false

    var body: some View {
        Group {
            if visible {
                ProgressView().controlSize(.small)
            }
        }
        .task(id: active) {
            visible = false
            guard active else { return }
            do {
                try await Task.sleep(for: .milliseconds(200))
                guard !Task.isCancelled else { return }
                visible = true
            } catch {
                // A completed operation cancels the delay before it becomes visible.
            }
        }
    }
}

private struct PowerSwitch: View {
    @ObservedObject var model: AppModel

    var body: some View {
        HStack {
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

/// Marks the route that takes what no rule claims.
/// Every route, each with the switch that keeps it on or off.
private struct DirectionRows: View {
    @ObservedObject var model: AppModel
    /// The window adds the way to a missing VPN and to the log.
    var inWindow = false

    var body: some View {
        ForEach(model.settings.directions) { direction in Self.row(model, direction, inWindow: inWindow) }
    }

    /// A grouped Form wants the ForEach itself in its Section: behind a view of
    /// its own, the last row fell out of the section's box.
    @MainActor
    static func row(_ model: AppModel, _ direction: Direction, inWindow: Bool) -> DirectionRow {
        DirectionRow(
            direction: direction,
            status: model.tunnel(of: direction),
            vpn: model.vpnTitle(direction),
            isDefault: model.settings.defaultDirection == direction.id,
            routingOn: model.displayedEnabled,
            broken: model.isBroken(direction),
            warning: model.connection(direction.connection)?.xray?.warning,
            onToggle: { model.setDirection(direction.id, enabled: $0) },
            onFix: inWindow ? { model.selectedDirection = direction.id; model.page = .rules } : nil,
            onShowLog: inWindow ? { model.page = .diagnostics } : nil
        )
    }
}

private struct DirectionRow: View {
    let direction: Direction
    let status: TunnelStatus?
    let vpn: String
    let isDefault: Bool
    /// The main switch: with it off, an enabled route only waits for it.
    let routingOn: Bool
    let broken: Bool
    let warning: String?
    let onToggle: (Bool) -> Void
    var onFix: (() -> Void)?
    var onShowLog: (() -> Void)?

    /// LabeledContent, not a hand-made row: a grouped Form lays out its own
    /// rows, and a custom HStack as the last one fell out of the section.
    var body: some View {
        LabeledContent {
            HStack {
                if direction.enabled, status?.phase == .error, !broken, let onShowLog {
                    Button("Журнал", action: onShowLog)
                }
                if broken, let onFix { Button("Выбрать VPN…", action: onFix) }
                Toggle("«\(direction.name)»", isOn: Binding(get: { direction.enabled }, set: { onToggle($0) }))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    // Grey while VPN is off: on, but not carrying anything yet.
                    .tint(routingOn ? nil : .gray)
                    .help(direction.enabled ? "Выключить направление: его сайты пойдут туда же, куда остальной трафик" : "Включить направление")
            }
        } label: {
            Text(direction.name)
            // Styled here, not left to the container: the menu's MenuRowStyle
            // has no subtitle look of its own.
            Group {
                (live
                    ? Text(Image(systemName: "circle.fill")).foregroundStyle(status!.phase.color) + Text(" " + subtitle)
                    : Text(subtitle))
                    .foregroundStyle(.secondary)
                if direction.enabled, let warning { Text(warning).foregroundStyle(.orange) }
            }
            .font(.subheadline)
        }
        .help(subtitle)
    }

    /// A tunnel that is meant to be up right now, so its phase is worth a dot.
    private var live: Bool {
        routingOn && direction.enabled && !broken && direction.path != .direct && status != nil
    }

    /// One scheme for every row: where the traffic goes, then its state, then
    /// whether it takes the rest. The switch already says on or off.
    private var subtitle: String {
        ([vpn, state] + [isDefault ? "остальной трафик" : nil]).compactMap { $0 }.joined(separator: " · ")
    }

    private var state: String? {
        guard direction.enabled, !broken, direction.path != .direct else { return nil }
        guard routingOn else { return "включится с VPN" }
        guard let status else { return nil }
        // The daemon says why; «Ошибка» alone sent people to the log for it.
        if status.phase == .error, let message = status.message { return message }
        guard status.phase == .connected else { return status.phase.russianTitle.lowercased() }
        let time: Date.FormatStyle = Calendar.current.isDateInToday(status.changedAt)
            ? .dateTime.hour().minute()
            : .dateTime.day().month().hour().minute()
        return "подключён с \(status.changedAt.formatted(time))"
    }
}

/// Two clicks, each the user's: download, then install, which takes VPN down.
private struct UpdateControl: View {
    @ObservedObject var model: AppModel

    var body: some View {
        if let update = model.update {
            let version = update.release.version
            switch update {
            case .available:
                Menu("Доступна версия \(version)") {
                    Button("Скачать", action: model.downloadUpdate)
                    Button("Что нового", action: model.showReleaseNotes)
                }
            case .downloading:
                ProgressView("Скачивается \(version)…").controlSize(.small)
            case .ready:
                Menu("Обновление \(version) скачано") {
                    Button("Обновить и перезапустить…", action: model.installUpdate)
                    Button("Что нового", action: model.showReleaseNotes)
                }
                .help("VPN выключится на время обновления, Коммутатор перезапустится")
            case .installing:
                ProgressView("Устанавливается \(version)…").controlSize(.small)
            }
        }
    }
}

private struct Note: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

/// Under every «Ping» column and row: what it actually measures, so a good
/// ping on a server that will not connect reads as expected, not as a bug.
private struct PingHonestyNote: View {
    var body: some View {
        Note("Ping — это ICMP до хоста, отдельно от протокола VPN. Показывает, что хост в сети, но не проверяет, что сам VPN через него работает: провайдер может пропускать ping и при этом глушить именно QUIC (Hysteria2) или WireGuard/AmneziaWG.")
    }
}
