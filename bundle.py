"""Bounded nested RAS bundle inspection; archive paths are never used on disk."""
import codecs
import json
from pathlib import Path
import re
import secrets
import tarfile
import tempfile
import threading
import time
import zipfile

MAX_INSPECTED_ENTRIES = 20_000
MAX_ENTRY_BYTES = 1024**3
MAX_BUNDLE_BYTES = 1024**3
MAX_INSPECTION_BYTES = 8 * 1024**3


class BundleStore:
    def __init__(self):
        self.sessions = {}
        self.indexes = {}
        self.index_locks = {}
        self.jobs = {}
        self.progress_lock = threading.Lock()
        self.timer = None
        self.ttl = 3600
        self.sweep_seconds = 15
        self.lock = threading.RLock()

    def upload(self, stream, length):
        if not 0 < length <= MAX_BUNDLE_BYTES:
            raise ValueError('Support bundles must be between 1 byte and 1 GiB compressed')
        with self.lock:
            self.prune()
            if sum(records is not None for _, _, records in self.sessions.values()) >= 3:
                raise ValueError('Three bundles are already open. Clear an existing bundle before uploading another.')
            temp = tempfile.TemporaryDirectory(prefix='ras-support-')
            root = Path(temp.name)
            records, servers = [], {}
            budget = [0, 0]
            skipped = [0]
            def count_entry():
                budget[1] += 1
                if budget[1] > MAX_INSPECTED_ENTRIES:
                    raise ValueError(
                        f'Inspection reached entry {budget[1]:,}. The limit is '
                        f'{MAX_INSPECTED_ENTRIES:,} across the upload and its nested archives. '
                        'Upload one server archive or a smaller selection of logs.'
                    )
            def save(source, size, display):
                count_entry()
                if size > MAX_ENTRY_BYTES:
                    # Error text is also used by the local HTTP server as a status reason.
                    label = ascii(display[-240:])[1:-1]
                    raise ValueError(
                        f'Entry "{label}" is {size:,} bytes before compression. '
                        f'The per-entry limit is {MAX_ENTRY_BYTES:,} bytes. '
                        'Choose a smaller server archive or split the affected log.'
                    )
                target = root / secrets.token_hex(16)
                with target.open('wb') as output:
                    remaining = size
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError('Truncated bundle entry')
                        remaining -= len(chunk)
                        budget[0] += len(chunk)
                        if budget[0] > MAX_INSPECTION_BYTES:
                            raise ValueError(
                                f'Bundle exceeds the {MAX_INSPECTION_BYTES / 1024**3:g} GiB '
                                'expanded inspection limit. Upload a smaller selection of server archives.'
                            )
                        output.write(chunk)
                return target
            def visit(path, display, server, depth):
                if depth > 8:
                    raise ValueError('Bundle nesting exceeds 8 archive levels')
                with path.open('rb') as source:
                    signature = source.read(4)
                if signature.startswith(b'PK') and zipfile.is_zipfile(path):
                    base = display.replace('\\', '/').split('/')[-1]
                    match = re.match(r'(.+)_DebugLog\.zip$', base, re.I)
                    if match:
                        server = match.group(1).strip()
                        servers.setdefault(server, [])
                    with zipfile.ZipFile(path) as archive:
                        for member in archive.infolist():
                            if member.is_dir():
                                continue
                            # ZIP metadata lets us skip the RAS performance capture
                            # without expanding it or losing the neighbouring logs.
                            if member.filename.replace('\\', '/').rsplit('/', 1)[-1].casefold() == 'perf.dat':
                                count_entry()
                                skipped[0] += 1
                                continue
                            with archive.open(member) as source:
                                child = save(source, member.file_size, display + ' / ' + member.filename)
                            visit(child, display + ' / ' + member.filename, server, depth + 1)
                    path.unlink()
                elif signature.startswith(b'\x1f\x8b') or display.lower().endswith('.tar'):
                    with tarfile.open(path, 'r:*') as archive:
                        for member in archive:
                            if not member.isfile():
                                skipped[0] += 1
                                continue
                            with archive.extractfile(member) as source:
                                child = save(source, member.size, display + ' / ' + member.name)
                            visit(child, display + ' / ' + member.name, server, depth + 1)
                    path.unlink()
                elif display.lower().endswith(('.log', '.txt', '.out')):
                    server = server or 'Farm-level files'
                    record = {'id': str(len(records)), 'server': server, 'path': display,
                              'name': display.split(' / ')[-1], 'size': path.stat().st_size,
                              'disk': path}
                    records.append(record)
                    servers.setdefault(server, []).append(record)
                else:
                    skipped[0] += 1
                    path.unlink()
            try:
                uploaded = save(stream, length, "Support bundle")
                with uploaded.open('rb') as source:
                    magic = source.read(4)
                if not (magic.startswith(b'PK') or magic.startswith(b'\x1f\x8b')):
                    raise ValueError('Choose a ZIP or TAR.GZ support bundle')
                visit(uploaded, 'Support bundle', '', 0)
                token, expiry = self.register(temp, records)
                return {'token': token, 'expires_at': expiry, 'skipped': skipped[0], 'servers': [
                    {'name': name, 'logs': [{k: v for k, v in record.items() if k != 'disk'}
                                           for record in logs]} for name, logs in servers.items()]}
            except (zipfile.BadZipFile, tarfile.TarError, RuntimeError, EOFError, OSError) as exc:
                temp.cleanup()
                raise ValueError(f'Could not read bundle: {exc}') from exc
            except Exception:
                temp.cleanup()
                raise

    def register(self, temp, records):
        with self.lock:
            self.prune()
            if len(self.sessions) >= 16:
                raise ValueError("Temporary investigation capacity reached. Clear a finished investigation.")
            token = secrets.token_urlsafe(32)
            self.sessions[token] = (time.monotonic(), temp, records)
            self.indexes[token] = {}
            self.index_locks[token] = {}
            if self.timer is None:
                self.schedule()
            return token, time.time() + self.ttl

    def schedule(self):
        self.timer = threading.Timer(self.sweep_seconds, self.sweep)
        self.timer.daemon = True
        self.timer.start()

    def sweep(self):
        with self.lock:
            self.timer = None
            try:
                self.prune()
            finally:
                if self.sessions:
                    self.schedule()

    def prune(self):
        with self.lock:
            for token, (created, _, _) in list(self.sessions.items()):
                if time.monotonic() - created >= self.ttl:
                    if all(not guard.locked() for guard in self.index_locks[token].values()):
                        self.clear(token)

    def clear(self, token):
        with self.lock:
            if token in self.sessions:
                guards = list(self.index_locks[token].values())
                for guard in guards:
                    guard.acquire()
                try:
                    self.sessions[token][1].cleanup()
                    self.jobs.pop(token, None)
                    del self.sessions[token], self.indexes[token], self.index_locks[token]
                finally:
                    for guard in reversed(guards):
                        guard.release()
        return {'cleared': True}

    def individual(self, payload, analyser):
        if not isinstance(payload, dict):
            raise ValueError("Choose one or more log files")
        if not payload.get("Indexed"):
            with tempfile.TemporaryDirectory() as folder:
                return analyser.build_index(payload, Path(folder)/"index.sqlite3").query(payload, 5000)
        temp = tempfile.TemporaryDirectory(prefix="ras-investigation-")
        try:
            token, _ = self.register(temp, None)
        except Exception:
            temp.cleanup()
            raise
        try:
            return self.index_query(token, "", payload, analyser, files=payload)
        except Exception:
            self.clear(token)
            raise

    def index_query(self, token, log_id, payload, analyser, files=None, overview=None):
        with self.lock:
            self.prune()
            if token not in self.sessions:
                raise ValueError("Investigation expired or cleared. Upload it again.")
            created, temp, records = self.sessions[token]
            if not isinstance(log_id, str) or (log_id and not re.fullmatch(r"[0-9]{1,6}", log_id)):
                raise ValueError("Invalid log selection")
            guard = self.index_locks[token].setdefault(log_id, threading.Lock())
            cache = self.indexes[token]
        guard.acquire()
        try:
            remaining = created + self.ttl - time.monotonic()
            if remaining <= 0:
                raise ValueError("Investigation expired. Upload it again.")
            if token not in self.sessions:
                raise ValueError("Investigation expired or cleared.")
            record = None
            if records is not None:
                record = next((r for r in records if r["id"] == log_id), None)
                if record is None:
                    raise ValueError("Select a log from this bundle")
            elif log_id:
                raise ValueError("Invalid log selection")
            if log_id not in cache:
                if record is not None:
                    files = {"Files": [{"Name": record["name"], "Content": self.decode(record)}]}
                if files is None:
                    raise ValueError("Missing uploaded files")
                path = Path(temp.name) / ("index-" + log_id + ".sqlite3")
                try:
                    cache[log_id] = analyser.build_index(files, path)
                except Exception:
                    path.unlink(missing_ok=True)
                    raise
            if overview is not None:
                cache[log_id].add_overview(overview, self.is_controller(record))
                return
            result = cache[log_id].query(payload, 5000)
            result.update(investigation=token, expires_at=time.time() + created + self.ttl - time.monotonic())
            if record is not None:
                result["bundle_source"] = {"server":record["server"], "path":record["path"]}
            return result
        finally:
            guard.release()

    @staticmethod
    def decode(record):
        raw = record["disk"].read_bytes()
        if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encoding = 'utf-16'
        elif b'\x00' in raw[:200]:
            encoding = 'utf-16-le' if raw[:200][1::2].count(0) >= raw[:200][::2].count(0) else 'utf-16-be'
        else:
            encoding = 'utf-8-sig'
        try:
            content = raw.decode(encoding)
        except UnicodeDecodeError:
            content = raw.decode('cp1252', errors='replace')
        return content

    @staticmethod
    def is_controller(record):
        name = record["name"].replace(chr(92), "/").rsplit("/", 1)[-1]
        return bool(re.match(r"^controller(?:$|[._ -])", name, re.I))

    def overview_status(self, token, analyser):
        with self.lock:
            self.prune()
            session = self.sessions.get(token)
            if session is None or session[2] is None:
                raise ValueError("Bundle expired or cleared.")
            job = self.jobs.get(token)
            if job is None:
                records = sorted(session[2], key=lambda r: (not self.is_controller(r), r["size"]))
                job = {"done": False, "processed": 0, "count": len(records), "included": 0,
                       "omitted": 0, "current": "", "top_logs": [],
                       "stats": dict.fromkeys(("total","errors","logins","failed","users","hosts"), 0)}
                self.jobs[token] = job
                threading.Thread(target=self.run_overview, args=(token, analyser, records, job),
                                 name="bundle-overview", daemon=True).start()
            with self.progress_lock:
                return dict(job)

    def run_overview(self, token, analyser, records, job):
        totals = dict(total=0, logins=0, failed=0, errors=0, users=set(), hosts=set())
        ranked = []
        try:
            for record in records:
                if token not in self.sessions:
                    return
                with self.progress_lock:
                    job["current"] = record["name"]
                previous = totals["errors"]
                try:
                    self.index_query(token, record["id"], {}, analyser, overview=totals)
                except ValueError:
                    included = 0
                else:
                    included = 1
                    errors = totals["errors"] - previous
                    if errors:
                        ranked.append({key:record[key] for key in ("id","name","server","path")} | {"errors":errors})
                        ranked.sort(key=lambda log: (-log["errors"],log["server"].casefold(),log["path"].casefold()))
                        del ranked[5:]
                with self.progress_lock:
                    job["processed"] += 1
                    job["included"] += included
                    job["omitted"] += 1-included
                    job["top_logs"] = list(ranked)
                    job["stats"] = dict(totals, users=len(totals["users"]), hosts=len(totals["hosts"]))
        except Exception:
            import logging
            logging.exception("Bundle overview failed")
            with self.progress_lock:
                job["error"] = "Overview stopped. Totals shown are partial."
        finally:
            with self.progress_lock:
                job.update(done=True,current="")

    def analyze(self, payload, analyser):
        return self.index_query(payload.get("token"), payload.get("log_id"), payload, analyser)

    def request(self, path, stream, length, content_type, authorized, analyser):
        if authorized != '1':
            raise PermissionError('Analysis request header required')
        if path == '/api/bundle':
            if content_type != 'application/octet-stream':
                raise ValueError('Binary bundle upload required')
            result = self.upload(stream, length)
            analyser.usage.add(bundles=1, uploaded_bytes=length)
            return result
        if not content_type.startswith('application/json') or not 0 < length <= 65536:
            raise ValueError('Invalid bundle request')
        payload = json.loads(stream.read(length))
        if not isinstance(payload, dict):
            raise ValueError('Invalid bundle selection')
        if not isinstance(payload.get('token'), str):
            raise ValueError('Invalid investigation token')
        if path == '/api/bundle/overview':
            return self.overview_status(payload['token'], analyser)
        if path in ('/api/bundle/clear', '/api/investigation/clear'):
            return self.clear(payload.get('token'))
        if path == "/api/investigation/query":
            return self.index_query(payload["token"], payload.get("log_id", ""), payload, analyser)
        return self.analyze(payload, analyser)
