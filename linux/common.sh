#!/usr/bin/env bash
set -Eeuo pipefail
PACKAGE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BASE=/opt/ras-log-analyser
STATE=/var/lib/ras-log-analyser
SERVICE=ras-log-analyser
require_root() { [[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }; }
build_release() {
  release="$BASE/releases/$(date -u +%Y%m%dT%H%M%S)-$$"
  install -d -m 755 "$release"
  for file in log_index.py parser-defaults.json VERSION version_stamp.py app.py production.py bundle.py import_issues.py requirements-server.txt appsettings.json; do
    install -m 644 "$PACKAGE/$file" "$release/$file"
  done
  cp -R "$PACKAGE/static" "$release/static"
  python3 "$PACKAGE/version_stamp.py" "$PACKAGE" "$release/static/index.html"
  python3 -m venv "$release/.venv"
  "$release/.venv/bin/pip" install --disable-pip-version-check -r "$release/requirements-server.txt"
  "$release/.venv/bin/python" -m compileall -q "$release"
  chmod -R go-w "$release"
}
activate_release() { ln -sfn "$1" "$BASE/current.next"; mv -Tf "$BASE/current.next" "$BASE/current"; }
health_check() {
  for attempt in {1..20}; do
    if systemctl is-active --quiet "$SERVICE" && curl --max-time 3 --fail --silent http://127.0.0.1:8766/api/known-issues >/dev/null; then return 0; fi
    sleep 1
  done
  echo 'Health check failed; inspect journalctl -u ras-log-analyser.' >&2
  return 1
}
backup_data() {
  backup="$STATE/backups/$(date -u +%Y%m%dT%H%M%S)-$$"
  install -d -m 700 "$backup"
  cp "$STATE/appsettings.json" "$backup/appsettings.json"
  if [[ -f $STATE/issues.sqlite3 ]]; then
    python3 - "$STATE/issues.sqlite3" "$backup/issues.sqlite3" <<'PY'
import sqlite3,sys
from contextlib import closing
from pathlib import Path
with closing(sqlite3.connect(Path(sys.argv[1]).as_uri()+'?mode=ro',uri=True)) as src, closing(sqlite3.connect(sys.argv[2])) as dst:
    src.backup(dst)
PY
  fi
  echo "Backup: $backup"
}
