#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${1:-$ROOT/Build/Commutator.app}"
DESTINATION="/Applications/Commutator.app"

[[ -d "$SOURCE" ]] || { print -u2 "Не найдено приложение: $SOURCE"; exit 1; }
[[ -x "$SOURCE/Contents/Resources/install-system-component.sh" ]] || {
    print -u2 "В бандле нет установщика системного компонента. Пересоберите: make app"
    exit 1
}

# A running copy keeps its old code, and `open` below would only bring it
# forward. Asked to quit the normal way, so VPN goes off with its own dialog.
if /usr/bin/pgrep -xq VPNRouterApp; then
    print "Закрываю запущенный Коммутатор, чтобы открыть новую сборку."
    /usr/bin/osascript -e 'tell application id "com.vpnrouter.app" to quit' >/dev/null || true
    for _ in {1..60}; do /usr/bin/pgrep -xq VPNRouterApp || break; sleep 1; done
    if /usr/bin/pgrep -xq VPNRouterApp; then
        print -u2 "Коммутатор не закрылся. Выйдите из него и повторите make install"
        exit 1
    fi
fi

print "Установка Коммутатора. Пароль администратора будет запрошен один раз."
print "Она снимает карантин Gatekeeper с приложения — ставьте только ту сборку, которой доверяете."

# Копирование, снятие карантина и регистрация daemon идут одной привилегированной
# командой: иначе пароль спрашивается на копирование, потом Gatekeeper уводит в
# System Settings, потом приложение снова просит пароль на системный компонент.
sudo /bin/zsh -c '
    set -euo pipefail
    /usr/bin/ditto "$1" "$2"
    # ditto over an existing bundle keeps its old date, and macOS keeps
    # showing the icon it cached for that date.
    /usr/bin/touch "$2"
    /usr/bin/xattr -dr com.apple.quarantine "$2" 2>/dev/null || true
    "$2/Contents/Resources/install-system-component.sh"
' install-local "$SOURCE" "$DESTINATION"

/usr/bin/open "$DESTINATION"
print "Готово. Приложение запущено, системный компонент работает, пароль больше не нужен."
