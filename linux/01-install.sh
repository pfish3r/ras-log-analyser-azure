#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
require_root
[[ ! -e $BASE/current && ! -e $STATE/appsettings.json && ! -e /etc/systemd/system/ras-log-analyser.service ]] || { echo 'Existing analyser detected; use 03-update.sh.' >&2; exit 1; }
# Never modify the existing log-dashboard service, shares, configuration or database.
python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1',8766))
PY
apt-get update
apt-get install -y python3-venv curl
id ras-log-analyser >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin ras-log-analyser
install -d -m 750 -o ras-log-analyser -g ras-log-analyser "$STATE" /var/log/ras-log-analyser
install -d -m 755 "$BASE/releases"
build_release
python3 - "$PACKAGE/appsettings.json" "$STATE/appsettings.json" <<'PY'
import json,sys
from pathlib import Path
config=json.loads(Path(sys.argv[1]).read_text())
config.update(Database='/var/lib/ras-log-analyser/issues.sqlite3',LocalLog='/var/log/ras-log-analyser/analyser.log')
Path(sys.argv[2]).write_text(json.dumps(config,indent=2)+'\n')
PY
chown ras-log-analyser:ras-log-analyser "$STATE/appsettings.json"
chmod 600 "$STATE/appsettings.json"
activate_release "$release"
install -m 644 "$PACKAGE/linux/ras-log-analyser.service" /etc/systemd/system/ras-log-analyser.service
systemctl daemon-reload
systemctl enable --now "$SERVICE"
health_check
echo 'Ready on 127.0.0.1:8766. Use an SSH tunnel; no firewall opening is needed.'
