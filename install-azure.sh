#!/usr/bin/env bash
# Install or update the Azure container edition. Run with sudo on the VM.
set -Eeuo pipefail

repo=https://github.com/pfish3r/ras-log-analyser-azure.git
checkout=/opt/ras-log-analyser-azure
bind=
case "${1:-}" in
  --lan) bind=0.0.0.0 ;;
  --local) bind=127.0.0.1 ;;
  --help|-h) echo "Usage: sudo bash install-azure.sh [--lan|--local]"; exit 0 ;;
  '') ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac
[[ $# -le 1 && $EUID -eq 0 ]] || { echo "Run with sudo, with at most one bind option." >&2; exit 2; }
source /etc/os-release
case "$ID:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:22.04|debian:12|debian:13) ;;
  *) echo "This installer targets Ubuntu 22.04/24.04 and Debian 12/13." >&2; exit 1 ;;
esac
exec 9>/run/lock/ras-log-analyser-azure.lock
flock -n 9 || { echo "Another installation is running." >&2; exit 1; }

if ! command -v git >/dev/null || ! command -v curl >/dev/null; then
  apt-get update
  apt-get install -y --no-remove git curl ca-certificates
fi
if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y --no-remove ca-certificates curl
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod 0644 /etc/apt/keyrings/docker.asc
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update
  apt-get install -y --no-remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
elif ! docker compose version >/dev/null 2>&1; then
  apt-get update
  if apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    apt-get install -y --no-remove docker-compose-plugin
  else
    apt-get install -y --no-remove docker-compose-v2
  fi
fi
systemctl enable --now docker
docker info >/dev/null
if [[ -e $checkout ]]; then
  [[ -d $checkout/.git && $(git -C "$checkout" remote get-url origin) == "$repo" ]] || {
    echo "Unexpected existing directory at $checkout." >&2; exit 1;
  }
  [[ $(git -C "$checkout" branch --show-current) == main && -z $(git -C "$checkout" status --porcelain --untracked-files=no) ]] || {
    echo "The installed checkout has local changes or is on another branch. Inspect $checkout." >&2; exit 1;
  }
  git -C "$checkout" pull --ff-only origin main
else
  git clone --branch main "$repo" "$checkout"
fi
cd "$checkout"
# Only installer-managed bind address is changed. Preserve other local settings.
if [[ -n $bind ]]; then
  touch .env
  sed -i '/^RAS_ANALYSER_BIND=/d' .env
  echo "RAS_ANALYSER_BIND=$bind" >> .env
fi
docker compose config --quiet
if [[ -n $(docker compose ps -q --status running analyser) ]]; then
  docker compose exec -T analyser python container_backup.py
fi
docker compose build --pull
docker compose up -d --wait --wait-timeout 180
docker compose ps
echo "Installed $(git rev-parse --short HEAD) in $checkout"
echo "Published address: $(docker compose port analyser 8766)"
