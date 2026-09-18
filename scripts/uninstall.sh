#!/bin/zsh
set -euo pipefail

[[ "$EUID" == 0 ]] || { print -u2 "Требуются права администратора"; exit 1; }

APP="$(cd "$(dirname "$0")/../.." && pwd -P)"

# On SIGTERM the daemon takes its tunnels down and puts DNS, PF and routes
# back, so stopping it is what returns the network to its pre-install state.
/bin/launchctl bootout system/com.vpnrouter.daemon >/dev/null 2>&1 || true
for _ in {1..150}; do
    /bin/launchctl print system/com.vpnrouter.daemon >/dev/null 2>&1 || break
    sleep 0.2
done
/bin/rm -rf -- /Library/PrivilegedHelperTools/com.vpnrouter /Library/LaunchDaemons/com.vpnrouter.daemon.plist \
    /var/db/com.vpnrouter /var/run/com.vpnrouter /var/log/vpn-router.log
/usr/sbin/pkgutil --forget com.vpnrouter.app.installer >/dev/null 2>&1 || true
# Only ever a bundle: a copy of this script elsewhere must not take its parent folder along.
if [[ "$APP" == *.app ]]; then /bin/rm -rf -- "$APP"; fi
