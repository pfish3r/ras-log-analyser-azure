#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
require_root
[[ -L $BASE/current && -f $STATE/appsettings.json ]] || { echo 'Install the analyser first.' >&2; exit 1; }
old=$(readlink -f "$BASE/current")
[[ $old == "$BASE/releases/"* ]] || { echo 'Unexpected release location.' >&2; exit 1; }
build_release
backup_data
cp /etc/systemd/system/ras-log-analyser.service "$backup/ras-log-analyser.service"
rollback() {
  trap - ERR
  activate_release "$old"
  cp "$backup/ras-log-analyser.service" /etc/systemd/system/ras-log-analyser.service
  systemctl daemon-reload
  systemctl restart "$SERVICE" || true
  echo 'Update failed. Previous code restored; database and settings were not replaced.' >&2
  exit 1
}
trap rollback ERR
systemctl stop "$SERVICE"
activate_release "$release"
install -m 644 "$PACKAGE/linux/ras-log-analyser.service" /etc/systemd/system/ras-log-analyser.service
systemctl daemon-reload
systemctl start "$SERVICE"
health_check
trap - ERR
echo "Updated. Previous release retained: $old"
