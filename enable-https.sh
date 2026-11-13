#!/usr/bin/env bash
# Enable TLS on an installed Azure analyser.
set -Eeuo pipefail
[[ $EUID == 0 && $# == 0 ]] || { echo "Usage: sudo bash enable-https.sh"; exit 2; }
read -rp "DNS name (for example logview.example.com): " host </dev/tty
host=${host,,}
[[ ${#host} -le 253 && $host =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || { echo "Invalid hostname"; exit 2; }
cd /opt/ras-log-analyser-azure
exec 9>/run/lock/ras-log-analyser-azure.lock
flock -n 9 || { echo "Another installation is running"; exit 1; }
state=/etc/ras-log-analyser-azure/tls
umask 077
install -d -m 700 "$state" "$state/acme"
read_secret() {
  local file=$1 label=$2 value
  if [[ -s $file ]]; then label+=" (Enter to reuse saved value)"; fi
  read -rsp "$label: " value </dev/tty
  echo
  if [[ -z $value && -s $file ]]; then return 0; fi
  [[ -n $value ]] || { echo "Empty credential"; exit 1; }
  printf '%s' "$value" > "$file"
}
read_secret "$state/key" "GoDaddy production API key"
read_secret "$state/secret" "GoDaddy production API secret"
if [[ ! -s $state/email ]]; then
  read -rp "Let's Encrypt contact email: " email </dev/tty
  [[ $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "Invalid email"; exit 2; }
  printf '%s' "$email" > "$state/email"
fi
email=$(cat "$state/email")
# Use the default Compose override so ordinary updates keep HTTPS enabled.
override=compose.override.yaml
marker='# Managed by enable-https.sh'
if [[ -e $override ]] && [[ $(head -1 "$override") != "$marker" ]]; then
  echo "Existing custom $override requires manual integration"; exit 1
fi
temp=$(mktemp ./https-override.XXXXXX)
trap 'rm -f "$temp"' EXIT
cat > "$temp" <<EOF
$marker
services:
  analyser:
    ports: !reset []
  https:
    image: traefik:v3.6
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./https-router.yml:/etc/traefik/router.yml:ro
      - $state/acme:/acme
      - $state/key:/run/secrets/gd-key:ro
      - $state/secret:/run/secrets/gd-secret:ro
    environment:
      GODADDY_API_KEY_FILE: /run/secrets/gd-key
      GODADDY_API_SECRET_FILE: /run/secrets/gd-secret
      GODADDY_PROPAGATION_TIMEOUT: "600"
    command:
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.transport.respondingtimeouts.readtimeout=900s"
      - "--providers.file.filename=/etc/traefik/router.yml"
      - "--certificatesresolvers.le.acme.email=$email"
      - "--certificatesresolvers.le.acme.storage=/acme/acme.json"
      - "--certificatesresolvers.le.acme.caserver=https://acme-v02.api.letsencrypt.org/directory"
      - "--certificatesresolvers.le.acme.dnschallenge.provider=godaddy"
EOF
docker compose -f compose.yaml -f "$temp" config --quiet
cat > https-router.yml.tmp <<EOF
http:
  routers:
    analyser:
      rule: "Host(\`$host\`)"
      entryPoints: [websecure]
      service: analyser
      tls:
        certResolver: le
  services:
    analyser:
      loadBalancer:
        servers:
          - url: "http://analyser:8766"
EOF
docker compose -f compose.yaml -f "$temp" pull https
mv https-router.yml.tmp https-router.yml
mv "$temp" "$override"
docker compose up -d --wait analyser
# Recreate to pick up replaced bind-mounted files on repeated runs.
docker compose up -d --force-recreate --no-deps https
echo "Waiting for the trusted certificate for $host ..."
for attempt in {1..75}; do
  if curl --silent --fail --max-time 5 --noproxy '*' --resolve "$host:443:127.0.0.1" "https://$host/api/settings" >/dev/null; then
    echo "Verified https://$host/ on this VM. Check client DNS and Azure inbound TCP 443."
    exit 0
  fi
  sleep 10
done
echo "Certificate or routing check failed. Inspect docker compose logs --tail=100 https." >&2
exit 1
