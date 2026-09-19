#!/bin/zsh
# install-update.sh <new Commutator.app> <work folder>: a one-shot launchd job
# that RouterDaemon.installUpdate starts once it has checked the new bundle's
# signature and version. It runs from that verified bundle, never from the pkg.
set -euo pipefail

[[ "$EUID" == 0 ]] || { print -u2 "Требуются права администратора"; exit 1; }
[[ $# == 2 ]] || { print -u2 "Нужны новое приложение и рабочая папка"; exit 1; }
NEW="$1"
APP="/Applications/Commutator.app"
# Any admin process can write to /Applications: a fixed name there could be
# planted in advance, a random one made by mktemp cannot.
STAGE="$(/usr/bin/mktemp -d /Applications/.Commutator-update.XXXXXX)"
trap '/bin/rm -rf -- "$2" "$STAGE"' EXIT

# A full disk fails here, with the old app still in place.
/usr/bin/ditto "$NEW" "$STAGE/Commutator.app"
# Moved aside rather than deleted: a failure past this point puts it back.
if [[ -e "$APP" ]]; then /bin/mv -- "$APP" "$STAGE/old.app"; fi
/bin/mv -- "$STAGE/Commutator.app" "$APP" || { /bin/mv -- "$STAGE/old.app" "$APP"; exit 1; }
# An upgrade can keep the bundle's old date, and macOS would keep showing the
# icon it cached for that date.
/usr/bin/touch "$APP"
# From the verified root-only copy, not from /Applications, where an admin
# process could swap it after the move. It installs the daemon from the bundle
# it sits in, and boots out the daemon that started this job; the job runs on.
"$NEW/Contents/Resources/install-system-component.sh"
