# Docker and Compose deployment on Debian

## Prerequisites

Install Docker Engine, Buildx and the Compose plugin using [Docker's Debian instructions](https://docs.docker.com/engine/install/debian/). Verify `sudo docker version` and `sudo docker compose version`. This uses modern `docker compose`, not the legacy `docker-compose` command. Install Git if needed: `sudo apt-get update && sudo apt-get install -y git`.

The image is built locally from source, using `python:3.12-slim-bookworm` (Debian Bookworm). It runs Waitress as UID/GID 10001, with dropped capabilities and no-new-privileges. There is no systemd inside the container, no SMB mounting and no Docker socket access. Building needs access to Docker Hub and PyPI. Both amd64 and arm64 are supported by the base image; CI currently exercises amd64 only.

## Deploy

```bash
git clone https://github.com/pfish3r/ras-log-analyser.git
cd ras-log-analyser
sudo docker compose up -d --build --wait
sudo docker compose ps
```

If you already cloned the repository, use that checkout and `git pull --ff-only origin main` first. Do not run linux/01-install.sh for a container deployment.

The host listens on **127.0.0.1:8767**, forwarded to container port 8766. This avoids the standalone analyser's port 8766. From your Windows computer:

```powershell
ssh -N -L 8767:127.0.0.1:8767 YOUR_SSH_USER@YOUR_DEBIAN_SERVER
```

Open http://127.0.0.1:8767. There is no user authentication; retain the localhost binding and use an SSH tunnel. For a different host port, create a local `.env` containing `RAS_ANALYSER_PORT=8768`; do not commit that file. Update the tunnel to match. An existing systemd installation and its issue library are separate; Docker does not import them automatically.

## What persists

The explicit named volume **ras-log-analyser-data** is mounted at `/data`:

- `/data/issues.sqlite3`: shared common-issue library, including matching phrases, KB URLs and resolution notes.
- `/data/appsettings.json`: parsing settings, created only on first startup and never replaced during an update.
- `/data/logs/analyser.log`: rotated application logs.
- `/data/backups/`: backups created by the backup command.

The Compose project and volume names are stable even if the checkout directory changes. Use one deployment per volume; do not run multiple independent analyser deployments against it. Fresh named-volume ownership is initialized from the image, allowing the service to remain non-root. Existing hand-created or bind-mounted data needs UID/GID 10001 ownership; the entrypoint deliberately does not change host-file ownership.

Rebuilds, container replacement, restart and normal `docker compose down` retain the volume. **Do not use `docker compose down --volumes`, `docker volume rm ras-log-analyser-data`, or prune this volume if you want to keep the library.**

Uploads and bundle sessions are temporary, are not included in library backups and disappear when a container is replaced. Large archives use container writable-layer disk space, not an in-memory tmpfs. Existing upload and archive limits are unchanged. Large concurrent analyses can still consume substantial RAM; ensure the Debian host has enough RAM and Docker disk space.

## Back up, then update

From the checkout, create a consistent SQLite snapshot and settings archive:

```bash
sudo docker compose exec -T analyser python container_backup.py
```

This prints a timestamped `/data/backups/ras-log-analyser-....tar.gz` path. Copy that exact path off the volume, substituting the printed filename:

```bash
mkdir -p backups
sudo docker compose cp analyser:/data/backups/PRINTED-FILENAME.tar.gz ./backups/
```

Keep an off-host copy. Backups in the same Docker volume do not protect against loss of that volume. The backup uses SQLite's backup API, so it is safe while the app is running; avoid editing parsing settings during backup for a coherent configuration snapshot.

After the backup succeeds:

```bash
git pull --ff-only origin main &&
sudo docker compose build --pull &&
sudo docker compose up -d --wait
```

The build completes before the running container is replaced. The same named volume is reused; no database reset or schema deletion occurs. Check `sudo docker compose ps` and `sudo docker compose logs --tail=100` afterwards. This workflow builds from GitHub source; `docker compose pull` alone does not update it. If activation fails, it reports an error rather than automatically rolling back. Check out a previous known-good tag, rebuild and run `up -d --wait` to return to that version while retaining data. Container startup does not run database migrations or erase history tables.

## Import an existing issue library

Optional: import issues from a standalone analyser or the earlier log-dashboard. Do not mount its live data directory into the container and do not copy a live SQLite database without its WAL. On the host holding the source database, create a consistent snapshot (adjust the source path for the standalone analyser):

```bash
sudo python3 - /var/lib/log-dashboard/logs.sqlite3 "$PWD/legacy-library.sqlite3" <<'PY'
import sqlite3, sys
from contextlib import closing
from pathlib import Path
with closing(sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True)) as source, closing(sqlite3.connect(sys.argv[2])) as destination:
    source.backup(destination)
Path(sys.argv[2]).chmod(0o600)
PY
sudo docker compose cp ./legacy-library.sqlite3 analyser:/tmp/legacy-library.sqlite3
sudo docker compose exec -u 0 analyser chown 10001:10001 /tmp/legacy-library.sqlite3
sudo docker compose exec -T analyser python import_issues.py /tmp/legacy-library.sqlite3 /data/issues.sqlite3
sudo docker compose exec -T analyser rm /tmp/legacy-library.sqlite3
```

If the old app is on another machine, transfer its consistent snapshot privately to the Docker host first. The importer copies only known_issues, merges without overwriting existing entries, skips identical content, and backs up the destination database. The original database/history and service remain untouched. Keep the host snapshot private or remove it after confirming the import. Parsing settings are independent; configure them through the new app rather than importing live-watcher settings.

## Restore a backup

Restoring replaces the container library and settings with the saved version. First take a fresh backup if the current data is useful, then copy a trusted archive made by container_backup.py to `restore.tar.gz` in the checkout. Stop the app before restoring so there are no open SQLite writers:

```bash
sudo docker compose stop analyser
sudo docker compose run --rm --no-deps --user 0 --entrypoint sh \
  --volume "$PWD/restore.tar.gz:/restore.tar.gz:ro" analyser -c '
  tar -tzf /restore.tar.gz &&
  rm -f /data/issues.sqlite3-wal /data/issues.sqlite3-shm &&
  tar -xzf /restore.tar.gz -C /data &&
  chown 10001:10001 /data/appsettings.json /data/issues.sqlite3 &&
  chmod 600 /data/appsettings.json /data/issues.sqlite3'
sudo docker compose up -d --wait
```

Use only your own backup archive containing `appsettings.json` and `issues.sqlite3`. Other volume contents, such as logs and backups, are retained. Verify the issue library in the UI after restoring.

## Verification

Unit tests cover first startup, preservation of existing settings/library, backup contents, and rejection of a database path outside the persistent volume. GitHub CI builds and starts the real Debian-based Docker image, tests uploads and nested archives, confirms removed live routes return 404 and the process runs as UID 10001, creates a backup, removes/recreates the container without deleting its volume, and confirms the saved issue and parsing settings survive. The host CI runner is Ubuntu; deployment on your particular Debian host and maximum-size uploads still require runtime validation.
