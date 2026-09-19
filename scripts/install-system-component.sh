#!/bin/zsh
set -euo pipefail

[[ "$EUID" == 0 ]] || { print -u2 "Требуются права администратора"; exit 1; }

CONTENTS="$(cd "$(dirname "$0")/.." && pwd -P)"
TARGET="/Library/PrivilegedHelperTools/com.vpnrouter"
TARGET_TOOLS="$TARGET/VPNTools"
PLIST="/Library/LaunchDaemons/com.vpnrouter.daemon.plist"

[[ -x "$CONTENTS/MacOS/VPNRouterDaemon" ]] || { print -u2 "VPNRouterDaemon не найден"; exit 1; }
for tool in openvpn amneziawg-go awg xray; do
    [[ -x "$CONTENTS/Resources/VPNTools/$tool" ]] || { print -u2 "$tool не найден"; exit 1; }
done

/bin/launchctl bootout system/com.vpnrouter.daemon >/dev/null 2>&1 || true
# bootout can return while the old daemon is still tearing down its tunnels,
# PF and DNS; a bootstrap during that fails with "5: Input/output error".
# launchd kills a daemon that is still running after 20 s, so 30 s is enough.
for _ in {1..150}; do
    /bin/launchctl print system/com.vpnrouter.daemon >/dev/null 2>&1 || break
    sleep 0.2
done
/usr/bin/install -d -o root -g wheel -m 0755 "$TARGET" "$TARGET_TOOLS"
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/MacOS/VPNRouterDaemon" "$TARGET/VPNRouterDaemon"
# Run by the daemon for «Удалить Коммутатор…»: from here, where only root writes.
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/Resources/uninstall.sh" "$TARGET/uninstall.sh"
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/Resources/VPNTools/openvpn" "$TARGET_TOOLS/openvpn"
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/Resources/VPNTools/amneziawg-go" "$TARGET_TOOLS/amneziawg-go"
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/Resources/VPNTools/awg" "$TARGET_TOOLS/awg"
/usr/bin/install -o root -g wheel -m 0755 "$CONTENTS/Resources/VPNTools/xray" "$TARGET_TOOLS/xray"
/usr/bin/install -o root -g wheel -m 0644 "$CONTENTS/Resources/com.vpnrouter.daemon.legacy.plist" "$PLIST"
/bin/launchctl bootstrap system "$PLIST"
/bin/launchctl enable system/com.vpnrouter.daemon
