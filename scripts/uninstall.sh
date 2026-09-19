#!/bin/zsh
set -euo pipefail

[[ "$EUID" == 0 ]] || { print -u2 "Требуются права администратора"; exit 1; }

# The daemon runs the copy installed next to it and names the app; the app's
# own copy, run with a password, finds the bundle it sits in.
APP="${1:-$(cd "$(dirname "$0")/../.." && pwd -P)}"

# On SIGTERM the daemon takes its tunnels down and puts DNS, PF and routes
# back, so stopping it is what returns the network to its pre-install state.
/bin/launchctl bootout system/com.vpnrouter.daemon >/dev/null 2>&1 || true
# Loaded by the last update from the app until a reboot.
/bin/launchctl bootout system/com.vpnrouter.update >/dev/null 2>&1 || true
for _ in {1..150}; do
    /bin/launchctl print system/com.vpnrouter.daemon >/dev/null 2>&1 || break
    sleep 0.2
done
/bin/rm -rf -- /Library/PrivilegedHelperTools/com.vpnrouter /Library/LaunchDaemons/com.vpnrouter.daemon.plist \
    /var/db/com.vpnrouter /var/db/com.vpnrouter.trusted-profiles /var/db/com.vpnrouter.resolver-backup.json \
    /var/run/com.vpnrouter /var/log/vpn-router.log
# Left by an update interrupted mid-way, a reboot say: the old app inside.
/bin/rm -rf -- /Applications/.Commutator-update.*(N)
/usr/sbin/pkgutil --forget com.vpnrouter.app.installer >/dev/null 2>&1 || true
# Only ever a bundle: a copy of this script elsewhere must not take its parent folder along.
if [[ "$APP" == *.app ]]; then /bin/rm -rf -- "$APP"; fi
# Last: when the daemon started this script, this ends the script's own job.
/bin/launchctl bootout system/com.vpnrouter.uninstall >/dev/null 2>&1 || true
