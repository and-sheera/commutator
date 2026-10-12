# Project
Commutator — оконное приложение для macOS 14+ со значком в строке меню (Apple Silicon): сколько угодно VPN (OpenVPN, AmneziaWG, Xray) одновременно. Трафик раскладывается по направлениям: у каждого своё название, свой VPN и свои правила, а приоритет задаёт порядок направлений. Пользователи — не разработчики. Раздаётся неподписанным .pkg через GitHub Releases, без Apple Developer ID.
README.md — для пользователей, DEVELOP.md — сборка, релизы, устройство.

# Commands
Тесты: make test. Сборка: make app. Пакет: make installer.
make release публикует релиз — агенту не запускать.
make app требует полный Xcode: actool собирает Config/Symbols.xcassets (свои SF Symbols: kommutator.bar.* — строка меню, kommutator.off — «Обзор»).
После замены Config/IconArtwork.png или правки scripts/make-icon.swift — make icon, результат коммитится.

# Conventions
- Имя в интерфейсе и текстах — «Коммутатор» (склоняется), его задаёт Config/ru.lproj/InfoPlist.strings. Латиницей — Commutator: файл .app, pkg, репозиторий. CFBundleDisplayName в AppInfo.plist совпадает с именем файла, иначе Finder не подставит русское имя.
- Не переименовывать, иначе сломается обновление установленных копий: com.vpnrouter.*, VPNRouter*, VPNROUTER_*, PF-anchor com.apple/vpn-router, /var/log/vpn-router.log, /var/run/vpn-router-pf.conf.
- Specs, планы, todo, разборы кладём в local/ (в .gitignore).
- VPNRouterCore — чистая логика без системных вызовов, всё тестируемое здесь. Маршруты, PF и DNS меняет только VPNRouterDaemon (root) и только через CommandRunner. VPNRouterApp — UI и XPC-клиент без root.
- Тексты для пользователя — по-русски, комментарии в коде — по-английски и объясняют «почему».
- Интерфейс — по максимуму из готового SwiftUI: стандартные контролы, стили и раскладки (Form, List, Table, Picker, Toggle, `.bordered`/`.borderedProminent`, системные листы и меню). Своё — только если готового нет: без самодельных кнопок, значков-бейджей, хитбоксов (`contentShape`), подобранных вручную размеров и отступов. Прежде чем писать своё, объясни, почему стандартное не подходит. В одной Form id строк во всех ForEach должны быть уникальны на всю страницу: Form — одна таблица, и совпавшие id разных секций ломают раскладку.
- Версия живёт в Config/AppInfo.plist и VPNRouterVersion.current, меняет обе make version. Разойдутся — приложение будет просить пароль при каждом запуске.
- Config/com.vpnrouter.daemon*.plist — пара: меняешь один, поправь второй. scripts/build-app.sh переписывает их env при сборке.
- Профили и пароли хранит только daemon в /var/db/com.vpnrouter. Пароль в приложение не отдаётся, Keychain не используется.
- Журнал обезличен: LogRedactor прячет серверы, публичные адреса, почту, поля сертификатов и ключи. Имена сайтов, которые резолвит пользователь, не пишем никогда. Названия направлений пишем как есть — это решение пользователя. Новое имя сервера регистрируй через TunnelLog.register(host:). VPNROUTER_LOG_RAW=1 и VPNROUTER_ALLOW_UNSIGNED=1 — только в ad-hoc dev-сборке. Проверку XPC-клиента не ослаблять.
- AdminAuthorization в AppModel должен жить, пока daemon не восстановит его из external form, иначе daemon отклонит.
- VPNROUTER_DEMO=1 — выдуманные данные для скриншота README (AppModel.fillDemo). В этом режиме XPCClient не обращается к daemon, а настройки не сохраняются. Новый путь к daemon или к UserDefaults закрывай так же.
- Новый системный файл установщика добавляй в scripts/uninstall.sh.
- Обновление из приложения ставит daemon без пароля (RouterDaemon.installUpdate): только та же подпись и только новее, скрипты pkg не выполняются, работает scripts/install-update.sh из проверенного бандла. Эти проверки не ослаблять. Удаление без пароля (RouterDaemon.uninstall) проверяется так же и запускает uninstall.sh только из /Library/PrivilegedHelperTools/com.vpnrouter. Новый daemon обязан читать /var/db/com.vpnrouter/state.json старого: новые поля только необязательные. Настройки из версий до направлений переводятся под фиксированные LegacyIDs — не менять их, иначе приложение и daemon разойдутся.
- Режим один. Новая установка начинается с трёх направлений под LegacyIDs work/personal/direct (RouterSettings()): «Работа» и «Личный» без VPN — .unset и выключены, не «напрямую». Список направления для остального трафика не применяется и живёт в UserDefaults simple-parked, не в RouterSettings.
- Версии движков меняются синхронно в scripts/build-vpn-tools.sh и THIRD_PARTY_NOTICES.md.
- Тесты — swift-testing, все в Tests/VPNRouterCoreTests/CoreTests.swift.

# Boundaries
MUST: отвечать кратко и по делу
MUST: после изменений swift build и make test — без ошибок
MUST: держать актуальными AGENTS.md, README.md и DEVELOP.md
MUST NOT: подключать новые пакеты (SwiftPM, brew) без обсуждения
MUST NOT: выполнять любые команды git
MUST NOT: открывать личные VPN-профили и ключи (.ovpn, .conf, ссылки подписок) — спрашивай пользователя
MUST NOT: без явной просьбы запускать то, что меняет сеть или систему (sudo, pfctl, route, networksetup, make install, сам daemon)
