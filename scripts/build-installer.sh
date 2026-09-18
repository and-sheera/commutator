#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/Build/Commutator.app"
WORK="$ROOT/.build/installer"
STAGING="$WORK/root"
SCRIPTS="$WORK/scripts"
COMPONENT="$WORK/component.plist"
# A fixed ASCII name: GitHub mangles spaces and Cyrillic in release assets, and
# releases/latest/download/Commutator.pkg stays a valid link across versions.
OUTPUT="$ROOT/Build/Commutator.pkg"

[[ -d "$APP" ]] || { print -u2 "Нет собранного приложения. Сначала выполните: make app"; exit 1; }
[[ -x "$APP/Contents/Resources/install-system-component.sh" ]] || {
    print -u2 "В бандле нет установщика системного компонента. Пересоберите: make app"
    exit 1
}

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")"

# The app compares its own version with the daemon's; when they differ it
# reinstalls the component, and asks for a password, on every launch.
CORE_VERSION="$(sed -n 's/.*static let current = "\(.*\)".*/\1/p' "$ROOT/Sources/VPNRouterCore/Models.swift")"
[[ "$CORE_VERSION" == "$VERSION" ]] || {
    print -u2 "Версии расходятся: Config/AppInfo.plist — $VERSION, VPNRouterVersion.current — $CORE_VERSION. Поднимите обе и пересоберите."
    exit 1
}

# An ad-hoc build lets the root daemon take commands from any local program.
# Fine on the machine it was built on, not in a package handed to others.
ALLOW_UNSIGNED="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:VPNROUTER_ALLOW_UNSIGNED' "$APP/Contents/Resources/com.vpnrouter.daemon.legacy.plist")"
[[ "$ALLOW_UNSIGNED" == "0" ]] || {
    print -u2 "Это ad-hoc сборка: daemon в ней примет команды от любой программы. Для раздачи нужна подпись:"
    print -u2 "    make setup-signing && make app"
    exit 1
}

rm -rf -- "$WORK"
mkdir -p "$STAGING" "$SCRIPTS"
/usr/bin/ditto "$APP" "$STAGING/Commutator.app"

cat > "$SCRIPTS/postinstall" <<'POSTINSTALL'
#!/bin/zsh
set -euo pipefail
APP="/Applications/Commutator.app"

# Installer.app already authenticated as root, so the system component is
# registered here instead of the app asking the user for a second password.
/usr/bin/xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
# An upgrade can keep the bundle's old date, and macOS would keep showing the
# icon it cached for that date.
/usr/bin/touch "$APP"
"$APP/Contents/Resources/install-system-component.sh"

# Launch it for the person at the keyboard, not for root.
CONSOLE_USER="$(/usr/bin/stat -f%Su /dev/console)"
if [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]]; then
    /bin/launchctl asuser "$(/usr/bin/id -u "$CONSOLE_USER")" /usr/bin/open "$APP" || true
fi
exit 0
POSTINSTALL
chmod 0755 "$SCRIPTS/postinstall"

# Relocatable is the pkgbuild default: with it, an old copy sitting in Downloads
# would win and the payload would land there instead of /Applications.
/usr/bin/pkgbuild --analyze --root "$STAGING" "$COMPONENT" >/dev/null
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$COMPONENT"

rm -f -- "$OUTPUT"
/usr/bin/pkgbuild \
    --root "$STAGING" \
    --component-plist "$COMPONENT" \
    --scripts "$SCRIPTS" \
    --identifier "$IDENTIFIER.installer" \
    --version "$VERSION" \
    --install-location /Applications \
    "$OUTPUT"

print "Готово: $OUTPUT ($VERSION)"
print "Выложить в GitHub Release: make release"
