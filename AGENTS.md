# Project
Commutator — оконное приложение для macOS 14+ со значком в строке меню (Apple Silicon): рабочий OpenVPN и личный VPN (AmneziaWG или Xray) одновременно, трафик раскладывается по доменным правилам. Пользователи — не разработчики. Раздаётся неподписанным .pkg через GitHub Releases, без Apple Developer ID.
README.md — для пользователей, DEVELOP.md — сборка, релизы, устройство.

# Commands
Тесты: make test. Сборка: make app. Пакет: make installer.
make release публикует релиз — агенту не запускать.
После замены Config/IconArtwork.png или правки scripts/make-icon.swift — make icon, результат коммитится.

# Conventions
- Имя в интерфейсе и текстах — «Коммутатор» (склоняется), его задаёт Config/ru.lproj/InfoPlist.strings. Латиницей — Commutator: файл .app, pkg, репозиторий. CFBundleDisplayName в AppInfo.plist совпадает с именем файла, иначе Finder не подставит русское имя.
- Не переименовывать, иначе сломается обновление установленных копий: com.vpnrouter.*, VPNRouter*, VPNROUTER_*, PF-anchor com.apple/vpn-router, /var/log/vpn-router.log, /var/run/vpn-router-pf.conf.
- Specs, планы, todo, разборы кладём в local/ (в .gitignore).
- VPNRouterCore — чистая логика без системных вызовов, всё тестируемое здесь. Маршруты, PF и DNS меняет только VPNRouterDaemon (root) и только через CommandRunner. VPNRouterApp — UI и XPC-клиент без root.
- Тексты для пользователя — по-русски, комментарии в коде — по-английски и объясняют «почему».
- Версия живёт в Config/AppInfo.plist и VPNRouterVersion.current, меняет обе make version. Разойдутся — приложение будет просить пароль при каждом запуске.
- Config/com.vpnrouter.daemon*.plist — пара: меняешь один, поправь второй. scripts/build-app.sh переписывает их env при сборке.
- Профили и пароли хранит только daemon в /var/db/com.vpnrouter. Пароль в приложение не отдаётся, Keychain не используется.
- Журнал обезличен: LogRedactor прячет серверы, публичные адреса, почту, поля сертификатов и ключи. Имена сайтов, которые резолвит пользователь, не пишем никогда. Новое имя сервера регистрируй через TunnelLog.register(host:). VPNROUTER_LOG_RAW=1 и VPNROUTER_ALLOW_UNSIGNED=1 — только в ad-hoc dev-сборке. Проверку XPC-клиента не ослаблять.
- AdminAuthorization в AppModel должен жить, пока daemon не восстановит его из external form, иначе daemon отклонит.
- VPNROUTER_DEMO=1 — выдуманные данные для скриншота README (AppModel.fillDemo). В этом режиме XPCClient не обращается к daemon, а настройки не сохраняются. Новый путь к daemon или к UserDefaults закрывай так же.
- Новый системный файл установщика добавляй в scripts/uninstall.sh.
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
