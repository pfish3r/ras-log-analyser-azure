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


class BundleStore:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.RLock()

    def upload(self, stream, length):
        if not 0 < length <= MAX_BUNDLE_BYTES:
            raise ValueError('Support bundles must be between 1 byte and 1 GiB compressed')
        with self.lock:
            self.prune()
            if len(self.sessions) >= 3:
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
                        if budget[0] > 2 * 1024**3:
                            raise ValueError('Bundle exceeds the 2 GiB expanded inspection limit')
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
                token = secrets.token_urlsafe(32)
                self.sessions[token] = (time.monotonic(), temp, records)
                return {'token': token, 'skipped': skipped[0], 'servers': [
                    {'name': name, 'logs': [{k: v for k, v in record.items() if k != 'disk'}
                                           for record in logs]} for name, logs in servers.items()]}
            except (zipfile.BadZipFile, tarfile.TarError, RuntimeError, EOFError, OSError) as exc:
                temp.cleanup()
                raise ValueError(f'Could not read bundle: {exc}') from exc
            except Exception:
                temp.cleanup()
                raise

    def prune(self):
        for token, (created, temp, _) in list(self.sessions.items()):
            if time.monotonic() - created > 3600:
                temp.cleanup()
                del self.sessions[token]

    def clear(self, token):
        with self.lock:
            session = self.sessions.pop(token, None)
            if session:
                session[1].cleanup()
        return {'cleared': True}

    def analyze(self, payload, analyser):
        with self.lock:
            self.prune()
            session = self.sessions.get(payload.get('token'))
            if not session:
                raise ValueError('Bundle expired or was cleared. Upload it again.')
            record = next((r for r in session[2] if r['id'] == payload.get('log_id')), None)
            if record is None:
                raise ValueError('Select a log from this bundle')
            raw = record['disk'].read_bytes()
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
        result = analyser.analyze_logs({'Files': [{'Name': record['name'], 'Content': content}],
                                         **{key: payload[key] for key in ('Since', 'Until', 'Severity', 'Query', 'FileId', 'Offset', 'PageSize') if key in payload}})
        result['bundle_source'] = {'server': record['server'], 'path': record['path']}
        return result

    def request(self, path, stream, length, content_type, authorized, analyser):
        if authorized != '1':
            raise PermissionError('Analysis request header required')
        if path == '/api/bundle':
            if content_type != 'application/octet-stream':
                raise ValueError('Binary bundle upload required')
            return self.upload(stream, length)
        if not content_type.startswith('application/json') or not 0 < length <= 65536:
            raise ValueError('Invalid bundle request')
        payload = json.loads(stream.read(length))
        if not isinstance(payload, dict):
            raise ValueError('Invalid bundle selection')
        if path == '/api/bundle/clear':
            return self.clear(payload.get('token'))
        return self.analyze(payload, analyser)
