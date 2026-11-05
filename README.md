# RAS Log Analyser — upload-only edition

Standalone upload-only RAS log analysis. This edition can run alongside the original log-dashboard application.

## What is included

Individual uploads, large decoded logs, nested RAS ZIP/TAR.GZ support bundles, server/file inventory, severity/date/text/file filters, paginated full-log viewing, frequent issues and latest-occurrence navigation, copy-message and Google AI actions, and the editable persistent common-issue library (phrases, KB URLs and resolution notes). Upload parsing settings retain error phrases and activity/user/host rules.

The upload analyser is the main screen. Collector/watcher code, polling, live endpoints, live statistics and server filters, watched-folder settings, broker passwords, SMB mounts and the root share helper are removed. New databases contain only known_issues. Existing events/checkpoints tables are never migrated, pruned or deleted. No production database is included.

Google AI opens Google with the selected message as its query; use it only when that message is appropriate to send externally. The app has no user authentication. Anyone who can access it can upload logs, edit parsing settings and edit the shared issue library. The supplied deployment binds only to 127.0.0.1 and is intended for an SSH tunnel. It does not open Azure NSG or Ubuntu firewall ports.

## Docker and Compose on Debian

See [CONTAINERS.md](CONTAINERS.md) for Docker installation prerequisites, deployment, updates, backup/restore and importing an existing issue library. The image uses Debian Bookworm with Python 3.12 and runs as an unprivileged user.

With Docker Engine and the Compose plugin installed:

```bash
git clone https://github.com/pfish3r/ras-log-analyser.git
cd ras-log-analyser
sudo docker compose up -d --build --wait
```

Compose binds to **127.0.0.1:8767** on the host; the systemd installation remains on 8766. The named volume **ras-log-analyser-data** retains the issue library and parsing settings across container rebuilds, replacement and normal `docker compose down`. Do not use `down --volumes` on your deployment; that deletes the volume.

To update:

```bash
sudo docker compose exec -T analyser python container_backup.py
git pull --ff-only origin main &&
sudo docker compose build --pull &&
sudo docker compose up -d --wait
```

Run the backup successfully before updating. The image is built locally from GitHub source; no registry login or prebuilt image is required. Keep the service private using an SSH tunnel; it has no user authentication.

## Windows development

Python 3.11+; double-click start.cmd or run `python app.py`. Open http://127.0.0.1:8766 directly in your browser. State defaults to data/issues.sqlite3 and data/analyser.log. For Waitress, install requirements-server.txt into your own virtual environment and run `python production.py --config appsettings.json`. Do not point the new deployment at the original app's data/configuration.

Run `python -m unittest discover -v` for regression tests. The large-file test uses more than 100 MiB of input and takes additional RAM/time.

## Separate Ubuntu 24.04 deployment

Service/user: ras-log-analyser
Code: /opt/ras-log-analyser/releases/<release>, with current symlink
Settings: /var/lib/ras-log-analyser/appsettings.json
Issue library: /var/lib/ras-log-analyser/issues.sqlite3
Logs: /var/log/ras-log-analyser/analyser.log
Backups: /var/lib/ras-log-analyser/backups
Listen address: 127.0.0.1:8766

No log-dashboard units, /etc/log-dashboard/server.env, broker mounts, original logs or original database are changed. The new service does not read LOGWATCH_HOST. Installation requires apt/PyPI access and sudo. No SMB/CIFS packages or share-management service are installed.

## Install and update directly from GitHub

On Ubuntu, clone the public repository into your normal user's home directory:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/pfish3r/ras-log-analyser.git
cd ras-log-analyser
python3 -m unittest discover -v
sudo bash linux/01-install.sh
```

For later updates, in the same checkout:

```bash
cd ~/ras-log-analyser
git pull --ff-only origin main
python3 -m unittest discover -v
sudo bash linux/03-update.sh
```

Run each command only after the previous one succeeds. Keep the checkout free of local edits; runtime settings and the issue library live separately in /var/lib/ras-log-analyser. `git pull` downloads code; the update script activates it. To deploy a specific version instead, fetch tags and check out the desired release tag before running the installer/updater.

Updates build a new release and virtual environment, take a consistent SQLite backup, preserve the installed configuration/database, and restore the previous code/unit if startup health checking fails. Only the new analyser is restarted. Releases/backups are retained; review disk use periodically. In-memory uploads and temporary bundle tokens do not survive a restart. The installer refuses an existing analyser; if an initial install fails, inspect the journal and existing state before retrying or use the update script once current/config exist.

### Packaged deployment

A source/deployment tarball and SHA256 file are available from [GitHub Releases](https://github.com/pfish3r/ras-log-analyser/releases). Download both assets for the same release, verify with `sha256sum -c <archive>.sha256`, extract to a fresh directory and run `sudo bash linux/01-install.sh` from the extracted ras-log-analyser directory. Use `03-update.sh` for an existing analyser.

To build your own package from the checkout:

```bash
python3 build_package.py dist/ras-log-analyser-upload-only.tar.gz
```

Connect from a second Windows PowerShell window and keep it open:

```powershell
ssh -N -L 8766:127.0.0.1:8766 YOUR_SSH_USER@YOUR_SERVER
```

Open http://127.0.0.1:8766 directly in the browser. If Windows port 8766 is occupied, use `-L 8767:127.0.0.1:8766` and browse port 8767. The server's port 8766 must be free; the installer checks this before installation. Existing app ports are unaffected.

```bash
sudo systemctl status ras-log-analyser --no-pager
sudo journalctl -u ras-log-analyser -n 80 --no-pager
curl -fsS http://127.0.0.1:8766/api/known-issues
sudo bash linux/04-backup.sh
```

## Transfer only the existing issue library

Optional, after installing. Do NOT replace the old database, copy its appsettings.json, or stop the original log-dashboard service. The importer opens the source SQLite database read-only, copies only known_issues, assigns new IDs, keeps existing destination records, and skips identical content. Different versions of an issue are retained as separate records; review them in the library. An existing destination is backed up beside the database before the transaction.

Run on Ubuntu:

```bash
sudo systemctl stop ras-log-analyser
sudo /opt/ras-log-analyser/current/.venv/bin/python /opt/ras-log-analyser/current/import_issues.py \
  /var/lib/log-dashboard/logs.sqlite3 /var/lib/ras-log-analyser/issues.sqlite3
sudo chown ras-log-analyser:ras-log-analyser /var/lib/ras-log-analyser/issues.sqlite3*
sudo systemctl start ras-log-analyser
```

Check the import result before proceeding if it reports an error; restart the analyser even if no import is needed. Source history and checkpoint rows are never copied or deleted. Keep backups private: they contain your issue notes and examples. For transfer between machines, create a consistent SQLite backup with SQLite's backup API rather than copying a live .sqlite3 file without its WAL.

## Limits and verification

Preserved protections: 10 individual files; 512 MiB total decoded text; 768 MiB HTTP request cap; 5 million lines; 1 MiB per line; result cap and pagination; bundles up to 512 MiB compressed / 2 GiB expanded, bounded entry counts and nesting, random temporary paths, three active bundles, one-hour expiration checked on the next bundle request, and explicit Clear bundle. Binary entries such as EVTX are skipped. Temporary bundle data uses the service's private /tmp, not persistent library storage.

Large logs are parsed in memory; multiple simultaneous requests can use substantial RAM. The browser also holds uploaded text. This is not a streaming or background job system. Size limits are unchanged, and testing over 100 MiB does not prove maximum-size operation on your VM. Check available RAM and temporary disk space before large concurrent uploads.

Local Windows validation: retained regression tests plus new removal/migration/safety tests; actual Waitress 3.0.2 HTTP smoke test; JavaScript syntax and DOM-ID reference checks; Bash syntax checks. Browser automation was rejected by the existing cross-site request protection, so full interactive browser validation remains outstanding. No protection was relaxed to accommodate automation.

Ubuntu apt installation, systemd hardening/startup/rollback, SSH tunnel and VM memory/disk behaviour have not been exercised on the target VM. No remote deployment was performed. SMB runtime testing is no longer applicable because this edition contains no mount management.
