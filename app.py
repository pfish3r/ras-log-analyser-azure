"""Upload-only RAS log analyser. Python 3.11+, no third-party dependencies."""
from __future__ import annotations

import argparse
import codecs
import copy
import json
import logging
import os
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from bundle import BundleStore
from version_stamp import stamp

ROOT = Path(__file__).resolve().parent
KINDS = {"login", "login_failed", "logout", "connection", "error", "warning", "info"}
ACTIVITY_KINDS = {"login", "connection", "logout"}
ANALYSIS_MAX_REQUEST = 1536 * 1024**2
ANALYSIS_MAX_TEXT = 1024**3
LOG_UPLOAD_TYPE = "application/vnd.ras.logs"
ANALYSIS_MAX_FILES = 10
ANALYSIS_MAX_LINES = 5_000_000
ANALYSIS_MAX_RESULTS = 5_000


def read_analysis_body(stream, length, mime):
    if not 1 <= length <= ANALYSIS_MAX_REQUEST:
        raise ValueError("Analysis request is empty or too large")
    if mime != LOG_UPLOAD_TYPE:
        return json.loads(stream.read(length))
    # Four-byte manifest length, UTF-8 JSON metadata, then original file bytes.
    prefix = stream.read(4)
    header = int.from_bytes(prefix, "big")
    if len(prefix) != 4 or not 0 < header <= min(65536, length - 4):
        raise ValueError("Invalid upload header")
    payload = json.loads(stream.read(header))
    if not isinstance(payload, dict):
        raise ValueError("Invalid upload metadata")
    files = payload.get("Files")
    if not isinstance(files, list) or not 1 <= len(files) <= ANALYSIS_MAX_FILES:
        raise ValueError("Choose between 1 and 10 files")
    total = 0
    for item in files:
        if not isinstance(item, dict) or type(item.get("Size")) is not int or item["Size"] < 0:
            raise ValueError("Invalid file size")
        total += item["Size"]
    if total > ANALYSIS_MAX_TEXT or total + header + 4 != length:
        raise ValueError("File sizes must match the upload and total at most 1 GiB")
    encoding = payload.pop("Encoding", "auto")
    if encoding not in ("auto", "utf-8", "utf-16le", "utf-16be", "windows-1252"):
        raise ValueError("Invalid file encoding")
    decoded_bytes = 0
    for item in files:
        remaining = item["Size"]
        first = stream.read(min(remaining, 200))
        codec = encoding
        if codec == "auto":
            if first.startswith(codecs.BOM_UTF16_BE):
                codec = "utf-16be"
            elif first.startswith(codecs.BOM_UTF16_LE) or first[1::2].count(0) > 20:
                codec = "utf-16le"
            else:
                codec = "utf-8"
        decoder = codecs.getincrementaldecoder(codec)(errors="replace")
        pieces = []
        chunk = first
        while True:
            if remaining and not chunk:
                raise ValueError("Truncated log upload")
            remaining -= len(chunk)
            text = decoder.decode(chunk, final=not remaining)
            if not pieces:
                text = text.removeprefix("\ufeff")
            decoded_bytes += len(text.encode("utf-8"))
            if decoded_bytes > ANALYSIS_MAX_TEXT:
                raise ValueError("The decoded log files exceed the 1 GiB analysis limit")
            pieces.append(text)
            if not remaining:
                break
            chunk = stream.read(min(remaining, 1024**2))
        item["Content"] = "".join(pieces)
    return payload


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS known_issues (
                    id INTEGER PRIMARY KEY, title TEXT NOT NULL, phrase TEXT NOT NULL,
                    severity TEXT NOT NULL, notes TEXT NOT NULL, links TEXT NOT NULL,
                    sample TEXT NOT NULL, updated TEXT NOT NULL);

            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def known_issues(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM known_issues ORDER BY title COLLATE NOCASE")]

    def save_issue(self, payload):
        if not isinstance(payload, dict):
            raise ValueError("Invalid issue")
        fields = {}
        for key, limit in (("title", 200), ("phrase", 2000), ("severity", 20), ("notes", 20000), ("links", 10000), ("sample", 10000)):
            value = payload.get(key, "")
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError(f"Invalid or oversized {key}")
            fields[key] = value.strip()
        if not fields['title'] or not fields['phrase']:
            raise ValueError("Title and matching phrase are required")
        if fields['severity'] not in ('all', 'error', 'warning', 'info'):
            raise ValueError("Invalid severity")
        for link in fields['links'].splitlines():
            parsed = urlsplit(link.strip())
            if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                raise ValueError("Links must be full http:// or https:// URLs, one per line")
        issue_id = payload.get('id')
        if issue_id is not None and (type(issue_id) is not int or issue_id < 1):
            raise ValueError("Invalid issue ID")
        values = [fields[k] for k in ('title', 'phrase', 'severity', 'notes', 'links', 'sample')] + [now()]
        with self.connect() as db:
            if issue_id is None:
                issue_id = db.execute("INSERT INTO known_issues(title,phrase,severity,notes,links,sample,updated) VALUES(?,?,?,?,?,?,?)", values).lastrowid
            elif db.execute("UPDATE known_issues SET title=?,phrase=?,severity=?,notes=?,links=?,sample=?,updated=? WHERE id=?", values + [issue_id]).rowcount != 1:
                raise ValueError("Issue no longer exists")
        return {'id': issue_id, 'issues': self.known_issues()}

class Parser:
    def __init__(self, config):
        self.error_strings = [str(value).casefold() for value in
                              config.get("ErrorSearchStrings", ["error", "exception", "fatal"])]
        self.rules = []
        for rule in config.get("ParseRules", []):
            if rule["Kind"] not in KINDS:
                raise ValueError("Unknown ParseRules Kind")
            self.rules.append((rule["Kind"], re.compile(rule["Pattern"], re.I)))

    def parse(self, line, source, host=""):
        fields, kind = {}, "info"
        for rule_kind, pattern in self.rules:
            match = pattern.search(line)
            if match:
                fields, kind = match.groupdict(), rule_kind
                break
        else:
            if re.search(r"\b(?:logon|login) failed\b", line, re.I):
                kind = "login_failed"
            elif re.search(r"^\[E", line, re.I) or any(value in line.casefold() for value in self.error_strings):
                kind = "error"
            elif re.search(r"^\[W|\bwarn(?:ing)?\b", line, re.I):
                kind = "warning"
        return {"received": now(), "timestamp": fields.get("timestamp") or "",
                "kind": kind, "user": fields.get("user") or "",
                "host": fields.get("host") or host, "ip": fields.get("ip") or "",
                "source": source, "raw": line}


class Analyser:
    def __init__(self, config, base, config_path=None):
        self.config, self.base = config, Path(base)
        self.config_path = Path(config_path) if config_path else None
        self.config_lock = threading.RLock()
        self.store = Store(self.resolve(config.get("Database", "data/issues.sqlite3")))
        self.parser = Parser(config)
        self.bundles = BundleStore()

    def resolve(self, value):
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.base / path

    def parser_defaults(self):
        defaults = json.loads((ROOT / "parser-defaults.json").read_text(encoding="utf-8"))
        return {"ErrorSearchStrings": defaults["ErrorSearchStrings"],
                "ActivityRules": [rule for rule in defaults["ParseRules"] if rule["Kind"] in ACTIVITY_KINDS]}

    def admin_settings(self):
        with self.config_lock:
            return {"ErrorSearchStrings": list(self.config.get("ErrorSearchStrings", ["error", "exception", "fatal"])),
                    "ActivityRules": [copy.deepcopy(rule) for rule in self.config.get("ParseRules", [])
                                      if rule.get("Kind") in ACTIVITY_KINDS],
                    "CanSave": self.config_path is not None}

    @staticmethod
    def validate_admin_settings(payload):
        if not isinstance(payload, dict):
            raise ValueError("Settings must be a JSON object")
        if set(payload) - {"ErrorSearchStrings", "ActivityRules"}:
            raise ValueError("Only upload parsing settings can be changed")
        raw_errors = payload.get("ErrorSearchStrings", [])
        if not isinstance(raw_errors, list) or len(raw_errors) > 100:
            raise ValueError("Error search strings must be a list of at most 100 values")
        errors = []
        for value in raw_errors:
            value = str(value).strip()
            if not value or len(value) > 200 or "\x00" in value:
                raise ValueError("Error search strings must contain 1 to 200 characters")
            if value.casefold() not in {item.casefold() for item in errors}:
                errors.append(value)
        settings = {"ErrorSearchStrings": errors}
        if "ActivityRules" in payload:
            raw_rules = payload["ActivityRules"]
            if not isinstance(raw_rules, list) or len(raw_rules) > 50:
                raise ValueError("User activity rules must be a list of at most 50 rules")
            activity_rules = []
            for number, rule in enumerate(raw_rules, 1):
                if not isinstance(rule, dict) or rule.get("Kind") not in ACTIVITY_KINDS:
                    raise ValueError(f"User activity rule {number} has an invalid event type")
                pattern = str(rule.get("Pattern", "")).strip()
                if not pattern or len(pattern) > 1000 or "\x00" in pattern:
                    raise ValueError(f"User activity rule {number} needs a pattern of at most 1000 characters")
                try:
                    compiled = re.compile(pattern, re.I)
                except re.error as exc:
                    raise ValueError(f"User activity rule {number} is not valid: {exc}") from exc
                if "user" not in compiled.groupindex:
                    raise ValueError(f"User activity rule {number} must contain a named user group: (?P<user>...)")
                if rule["Kind"] == "connection" and "host" not in compiled.groupindex:
                    raise ValueError(f"Connection rule {number} must contain a named host group: (?P<host>...)")
                activity_rules.append({"Kind": rule["Kind"], "Pattern": pattern})
            settings["ActivityRules"] = activity_rules
        return settings

    def update_admin_settings(self, payload):
        if self.config_path is None:
            raise PermissionError("Settings cannot be saved in this instance")
        settings = self.validate_admin_settings(payload)
        with self.config_lock:
            updated = copy.deepcopy(self.config)
            activity_rules = settings.pop("ActivityRules", None)
            updated.update(settings)
            if activity_rules is not None:
                preserved_rules = [rule for rule in updated.get("ParseRules", [])
                                   if rule.get("Kind") not in ACTIVITY_KINDS]
                updated["ParseRules"] = preserved_rules + activity_rules
            parser = Parser(updated)
            temporary = self.config_path.with_name(self.config_path.name + ".tmp")
            try:
                temporary.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
                os.replace(temporary, self.config_path)
            finally:
                if temporary.exists():
                    temporary.unlink()
            self.config = updated
            self.parser = parser
        return self.admin_settings()

    def build_index(self, payload, path):
        from log_index import LogIndex
        if not isinstance(payload, dict) or not isinstance(payload.get("Files"), list):
            raise ValueError("Choose one or more log files")
        raw_files = payload["Files"]
        if not 1 <= len(raw_files) <= ANALYSIS_MAX_FILES:
            raise ValueError(f"Choose between 1 and {ANALYSIS_MAX_FILES} log files")
        with self.config_lock:
            event_parser = self.parser
        files, total_text = [], 0
        for number, uploaded in enumerate(raw_files, 1):
            if not isinstance(uploaded, dict):
                raise ValueError(f"Uploaded file {number} is invalid")
            name = Path(str(uploaded.get("Name", ""))).name.strip()
            content = uploaded.get("Content")
            if not name or len(name) > 255 or not isinstance(content, str):
                raise ValueError(f"Uploaded file {number} is invalid")
            total_text += sum(len(content[pos:pos + 1024**2].encode("utf-8", errors="replace"))
                              for pos in range(0, len(content), 1024**2))
            if total_text > ANALYSIS_MAX_TEXT:
                raise ValueError("The decoded log files exceed the 1 GiB analysis limit")
            files.append((name, content))

        return LogIndex(path, [name for name, _ in files], self.parsed_rows(files, event_parser))

    def parsed_rows(self, files, event_parser):
        total_lines = 0
        marker_severity = {"e": "error", "w": "warning", "i": "info"}
        for file_index, (name, content) in enumerate(files):
            file_id = str(file_index)
            # Avoid allocating a second full list of log lines.
            lines = (m.group(0) for m in re.finditer(r"[^\r\n]*(?:\r\n|\r|\n|$)", content) if m.group(0))
            for line_number, original in enumerate(lines, 1):
                line = original.rstrip("\r\n").lstrip("\ufeff")
                total_lines += 1
                if total_lines > ANALYSIS_MAX_LINES:
                    raise ValueError(f"The upload exceeds the {ANALYSIS_MAX_LINES:,} line analysis limit")
                if len(line) > 1024 * 1024:
                    raise ValueError(f"{name} line {line_number} exceeds the 1 MiB line limit")
                event = event_parser.parse(line, name)
                marker = re.match(r"^\[([EWI])", line, re.I)
                if marker:
                    severity = marker_severity[marker.group(1).casefold()]
                elif event["kind"] in ("error", "login_failed"):
                    severity = "error"
                elif event["kind"] == "warning":
                    severity = "warning"
                else:
                    severity = "info"
                timestamp_match = re.search(r"\b\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b", line)
                timestamp = timestamp_match.group(0) if timestamp_match else event["timestamp"]
                sort_time = ""
                if timestamp:
                    try:
                        sort_time = datetime.strptime(timestamp, "%d-%m-%y %H:%M:%S").isoformat()
                    except ValueError:
                        try:
                            sort_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).isoformat()
                        except ValueError:
                            pass
                signature = None
                if severity in ("error", "warning"):
                    signature = re.sub(r"^\[[EWI][^\]]*\]\s*", "", line, flags=re.I)
                    signature = re.sub(r"^\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+-\s+", "", signature)
                    signature = signature.strip() or line
                yield (file_id, line_number, timestamp, sort_time, severity, event["kind"], name,
                       event["user"], event["host"], event["ip"], line, signature,
                       signature.casefold() if signature else None, int(not line.strip()),
                       datetime.fromisoformat(sort_time).replace(tzinfo=None).isoformat(timespec="microseconds") if sort_time else None)

    def analyze_logs(self, payload):
        return self.bundles.individual(payload, self)

def handler_for(analyser):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def request_allowed(self):
            allowed_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            return self.headers.get("Host", "") in allowed_hosts and self.headers.get("Sec-Fetch-Site") != "cross-site"

        def send_content(self, status, content, mime="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            # Reject cross-origin browser requests to this local service.
            if not self.request_allowed():
                self.send_error(403)
                return
            parts = urlsplit(self.path)
            try:
                if parts.path == "/api/known-issues":
                    content, mime = json.dumps(analyser.store.known_issues()).encode(), "application/json"
                elif parts.path == "/api/settings/defaults":
                    content, mime = json.dumps(analyser.parser_defaults()).encode(), "application/json"
                elif parts.path == "/api/settings":
                    content, mime = json.dumps(analyser.admin_settings()).encode(), "application/json"
                elif parts.path in ("/", "/app.js", "/style.css", "/admin.css", "/parallels-logo.png"):
                    name = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css", "/admin.css": "admin.css", "/parallels-logo.png": "parallels-logo.png"}[parts.path]
                    content = (ROOT / "static" / name).read_bytes()
                    if name == "index.html" and b"__APP_VERSION__" in content:
                        content = stamp(content, ROOT)
                    mime = {"index.html": "text/html", "app.js": "text/javascript", "style.css": "text/css", "admin.css": "text/css", "parallels-logo.png": "image/png"}[name]
                else:
                    self.send_error(404)
                    return
                self.send_content(200, content, mime)
            except ValueError as exc:
                self.send_error(400, str(exc))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                logging.exception("Dashboard request failed")
                self.send_error(500)

        def do_POST(self):
            if not self.request_allowed():
                self.send_error(403)
                return
            path = urlsplit(self.path).path
            if path in ("/api/bundle", "/api/bundle/analyze", "/api/bundle/clear", "/api/investigation/query", "/api/investigation/clear"):
                try:
                    result = analyser.bundles.request(path, self.rfile, int(self.headers.get("Content-Length", "0")),
                        self.headers.get("Content-Type", ""), self.headers.get("X-Logwatch-Analyze"), analyser)
                    self.send_content(200, json.dumps(result).encode())
                except PermissionError as exc:
                    self.send_error(403, str(exc))
                except ValueError as exc:
                    self.send_error(400, str(exc))
                return
            if path not in ("/api/settings", "/api/analyze", "/api/known-issues"):
                self.send_error(404)
                return
            required_header = "X-Logwatch-Admin" if path in ("/api/settings", "/api/known-issues") else "X-Logwatch-Analyze"
            mime = self.headers.get("Content-Type", "").lower().split(";")[0]
            if (not (mime == "application/json" or (path == "/api/analyze" and mime == LOG_UPLOAD_TYPE)) or
                    self.headers.get(required_header) != "1"):
                self.send_error(415)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                limit = 65536 if path != "/api/analyze" else ANALYSIS_MAX_REQUEST
                if not 1 <= length <= limit:
                    raise ValueError("Request is empty or too large")
                payload = read_analysis_body(self.rfile, length, mime) if path == "/api/analyze" else json.loads(self.rfile.read(length))
                result = analyser.store.save_issue(payload) if path == "/api/known-issues" else analyser.update_admin_settings(payload) if path == "/api/settings" else analyser.analyze_logs(payload)
                content = json.dumps(result).encode()
                self.send_content(200, content)
            except PermissionError as exc:
                self.send_error(403, str(exc))
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_error(400, str(exc))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                logging.exception("Saving dashboard settings failed")
                self.send_error(500, "Could not save settings")
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(ROOT / "appsettings.json"))
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    log_path = config_path.parent / config.get("LocalLog", "data/analyser.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")])
    analyser = Analyser(config, config_path.parent, config_path)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(analyser))
    print(f"RAS log analyser: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
