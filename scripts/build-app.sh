#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME="Commutator"
OUTPUT="$ROOT/Build/$APP_NAME.app"
BUNDLE_ID="${BUNDLE_ID:-com.vpnrouter.app}"
TEAM_ID="${TEAM_ID:-}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
LOCAL_SIGN_IDENTITY="Commutator Local Development"
TOOLS="$ROOT/Vendor/bin/arm64"

if [[ "$SIGN_IDENTITY" == "-" ]] && security find-identity -v -p codesigning | grep -Fq "\"$LOCAL_SIGN_IDENTITY\""; then
    SIGN_IDENTITY="$LOCAL_SIGN_IDENTITY"
fi

# Without a team ID or a certificate pin the daemon refuses every client, so a
# pure ad-hoc build has to opt into the unsigned mode explicitly.
ALLOW_UNSIGNED="0"
[[ "$SIGN_IDENTITY" == "-" ]] && ALLOW_UNSIGNED="1"

# SHA-1 because that is the hash the code-signing requirement language pins a
# certificate by: certificate leaf = H"…".
CERT_SHA1=""
if [[ "$SIGN_IDENTITY" != "-" && -z "$TEAM_ID" ]]; then
    CERT_SHA1="$(security find-certificate -c "$SIGN_IDENTITY" -p | openssl x509 -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
    [[ ${#CERT_SHA1} == 40 ]] || { print -u2 "Не удалось получить SHA-1 сертификата подписи"; exit 1; }
fi

for tool in openvpn amneziawg-go awg xray; do
    [[ -x "$TOOLS/$tool" ]] || {
        print -u2 "Нет $TOOLS/$tool. Сначала запустите scripts/build-vpn-tools.sh"
        exit 1
    }
done

cd "$ROOT"
mkdir -p "$ROOT/.build/module-cache"
export CLANG_MODULE_CACHE_PATH="$ROOT/.build/module-cache"
export SWIFT_MODULECACHE_PATH="$ROOT/.build/module-cache"
swift build --disable-sandbox -c release --arch arm64
BIN_DIR="$(swift build --disable-sandbox -c release --arch arm64 --show-bin-path)"

[[ "$OUTPUT" == "$ROOT/Build/$APP_NAME.app" ]] || { print -u2 "Некорректный путь сборки"; exit 1; }
rm -rf -- "$OUTPUT"
mkdir -p "$OUTPUT/Contents/MacOS" "$OUTPUT/Contents/Resources/VPNTools" "$OUTPUT/Contents/Library/LaunchDaemons"
cp "$ROOT/Config/AppInfo.plist" "$OUTPUT/Contents/Info.plist"
cp "$ROOT/Config/com.vpnrouter.daemon.plist" "$OUTPUT/Contents/Library/LaunchDaemons/com.vpnrouter.daemon.plist"
cp "$ROOT/Config/com.vpnrouter.daemon.legacy.plist" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"
cp "$ROOT/scripts/install-system-component.sh" "$OUTPUT/Contents/Resources/install-system-component.sh"
cp "$ROOT/scripts/uninstall.sh" "$OUTPUT/Contents/Resources/uninstall.sh"
cp "$ROOT/scripts/install-update.sh" "$OUTPUT/Contents/Resources/install-update.sh"
chmod 0755 "$OUTPUT/Contents/Resources/install-system-component.sh" "$OUTPUT/Contents/Resources/uninstall.sh" "$OUTPUT/Contents/Resources/install-update.sh"
cp "$ROOT/Config/AppIcon.icns" "$OUTPUT/Contents/Resources/AppIcon.icns"
# The Russian name macOS shows; the non-localized one has to match the file name.
cp -R "$ROOT/Config/ru.lproj" "$OUTPUT/Contents/Resources/"
cp "$BIN_DIR/VPNRouterApp" "$BIN_DIR/VPNRouterDaemon" "$OUTPUT/Contents/MacOS/"
cp "$TOOLS/openvpn" "$TOOLS/amneziawg-go" "$TOOLS/awg" "$TOOLS/xray" "$OUTPUT/Contents/Resources/VPNTools/"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$OUTPUT/Contents/Resources/"
if [[ -f "$ROOT/Vendor/SHA256SUMS" ]]; then cp "$ROOT/Vendor/SHA256SUMS" "$OUTPUT/Contents/Resources/"; fi
SOURCE_ARCHIVES=("$ROOT"/Vendor/sources/*.tar.gz(N))
if (( ${#SOURCE_ARCHIVES} )); then
    mkdir -p "$OUTPUT/Contents/Resources/ThirdPartySources"
    cp "${SOURCE_ARCHIVES[@]}" "$OUTPUT/Contents/Resources/ThirdPartySources/"
fi

/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$OUTPUT/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_ALLOWED_CLIENT_ID $BUNDLE_ID" "$OUTPUT/Contents/Library/LaunchDaemons/com.vpnrouter.daemon.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_TEAM_ID $TEAM_ID" "$OUTPUT/Contents/Library/LaunchDaemons/com.vpnrouter.daemon.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_CERT_SHA1 $CERT_SHA1" "$OUTPUT/Contents/Library/LaunchDaemons/com.vpnrouter.daemon.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_ALLOW_UNSIGNED $ALLOW_UNSIGNED" "$OUTPUT/Contents/Library/LaunchDaemons/com.vpnrouter.daemon.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_ALLOWED_CLIENT_ID $BUNDLE_ID" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_TEAM_ID $TEAM_ID" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_CERT_SHA1 $CERT_SHA1" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:VPNROUTER_ALLOW_UNSIGNED $ALLOW_UNSIGNED" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"
# So Login Items and the «background item added» notice name the app, not VPNRouterDaemon.
/usr/libexec/PlistBuddy -c "Add :AssociatedBundleIdentifiers string $BUNDLE_ID" "$OUTPUT/Contents/Resources/com.vpnrouter.daemon.legacy.plist"

codesign --force --options runtime --timestamp=none --sign "$SIGN_IDENTITY" "$OUTPUT/Contents/Resources/VPNTools/amneziawg-go"
codesign --force --options runtime --timestamp=none --sign "$SIGN_IDENTITY" "$OUTPUT/Contents/Resources/VPNTools/awg"
codesign --force --options runtime --timestamp=none --sign "$SIGN_IDENTITY" "$OUTPUT/Contents/Resources/VPNTools/xray"
codesign --force --options runtime --timestamp=none --entitlements "$ROOT/Config/OpenVPN.entitlements" --sign "$SIGN_IDENTITY" "$OUTPUT/Contents/Resources/VPNTools/openvpn"
codesign --force --options runtime --timestamp=none --sign "$SIGN_IDENTITY" "$OUTPUT/Contents/MacOS/VPNRouterDaemon"
codesign --force --options runtime --timestamp=none --sign "$SIGN_IDENTITY" "$OUTPUT"
codesign --verify --deep --strict "$OUTPUT"

print "Готово: $OUTPUT"
if [[ "$SIGN_IDENTITY" == "-" ]]; then
    print "Это ad-hoc сборка. Для рабочего SMAppService задайте SIGN_IDENTITY и TEAM_ID Developer ID."
    print -u2 "ВНИМАНИЕ: daemon собран с VPNROUTER_ALLOW_UNSIGNED=1 и примет XPC-запрос от любой локальной программы."
    print -u2 "Для нормальной проверки подписи выполните make setup-signing и пересоберите."
elif [[ "$SIGN_IDENTITY" == "$LOCAL_SIGN_IDENTITY" ]]; then
    print "Использована постоянная локальная подпись: $LOCAL_SIGN_IDENTITY"
fi
