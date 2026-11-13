"""Waitress server for the upload-only RAS analyser."""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app import ANALYSIS_MAX_REQUEST, Analyser, ROOT, stamp, LOG_UPLOAD_TYPE, read_analysis_body


def application_for(analyser):
    def application(environ, start_response):
        status, content, mime = "200 OK", b"", "text/plain"
        try:
            method = environ.get("REQUEST_METHOD")
            path = environ.get("PATH_INFO")
            if environ.get("HTTP_SEC_FETCH_SITE") == "cross-site":
                status, content = "403 Forbidden", b"Cross-site access denied"
            elif method == "POST" and path in ("/api/bundle", "/api/bundle/analyze", "/api/bundle/overview", "/api/bundle/clear", "/api/investigation/query", "/api/investigation/clear"):
                result = analyser.bundles.request(path, environ["wsgi.input"], int(environ.get("CONTENT_LENGTH") or "0"),
                    environ.get("CONTENT_TYPE", ""), environ.get("HTTP_X_LOGWATCH_ANALYZE"), analyser)
                content, mime = json.dumps(result).encode(), "application/json"
            elif method == "GET" and path == "/api/known-issues":
                content, mime = json.dumps(analyser.store.known_issues()).encode(), "application/json"
            elif method == "GET" and path == "/api/usage":
                content, mime = json.dumps(analyser.usage.totals()).encode(), "application/json"
            elif method == "POST" and path == "/api/usage/session":
                result = analyser.usage.visit(environ.get("HTTP_X_LOGWATCH_ANALYZE"), int(environ.get("CONTENT_LENGTH") or 0), environ.get("HTTP_X_USAGE_EVENT"))
                content, mime = json.dumps(result).encode(), "application/json"
            elif method == "GET" and path in ("/stats", "/stats.js"):
                name, mime = ("stats.html", "text/html") if path == "/stats" else ("stats.js", "text/javascript")
                content = (ROOT / "static" / name).read_bytes()
            elif method == "GET" and path == "/api/settings/defaults":
                content, mime = json.dumps(analyser.parser_defaults()).encode(), "application/json"
            elif method == "GET" and path == "/api/settings":
                content, mime = json.dumps(analyser.admin_settings()).encode(), "application/json"
            elif method == "POST" and path in ("/api/settings", "/api/known-issues"):
                if (not environ.get("CONTENT_TYPE", "").lower().startswith("application/json") or
                        environ.get("HTTP_X_LOGWATCH_ADMIN") != "1"):
                    status, content = "415 Unsupported Media Type", b"JSON admin request required"
                else:
                    length = int(environ.get("CONTENT_LENGTH") or "0")
                    if not 1 <= length <= 65536:
                        raise ValueError("Settings request is empty or too large")
                    payload = json.loads(environ["wsgi.input"].read(length))
                    content, mime = json.dumps(analyser.store.save_issue(payload) if path == "/api/known-issues" else analyser.update_admin_settings(payload)).encode(), "application/json"
            elif method == "POST" and path == "/api/analyze":
                mime_type = environ.get("CONTENT_TYPE", "").lower().split(";")[0]
                if (mime_type not in ("application/json", LOG_UPLOAD_TYPE) or
                        environ.get("HTTP_X_LOGWATCH_ANALYZE") != "1"):
                    status, content = "415 Unsupported Media Type", b"JSON analysis request required"
                else:
                    length = int(environ.get("CONTENT_LENGTH") or "0")
                    if not 1 <= length <= ANALYSIS_MAX_REQUEST:
                        raise ValueError("Analysis request is empty or too large")
                    payload = read_analysis_body(environ["wsgi.input"], length, mime_type)
                    content, mime = json.dumps(analyser.analyze_logs(payload)).encode(), "application/json"
            elif method == "GET" and path in ("/", "/app.js", "/style.css", "/admin.css", "/parallels-logo.png"):
                name, mime = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                              "/style.css": ("style.css", "text/css"), "/admin.css": ("admin.css", "text/css"),
                              "/parallels-logo.png": ("parallels-logo.png", "image/png")}[path]
                content = (ROOT / "static" / name).read_bytes()
                if name == "index.html" and b"__APP_VERSION__" in content:
                    content = stamp(content, ROOT)
            elif method not in ("GET", "POST"):
                status, content = "405 Method Not Allowed", b"Method not allowed"
            else:
                status, content = "404 Not Found", b"Not found"
        except PermissionError as exc:
            status, content = "403 Forbidden", str(exc).encode()
        except (ValueError, json.JSONDecodeError) as exc:
            status, content = "400 Bad Request", str(exc).encode()
        except Exception:
            logging.exception("Dashboard request failed")
            status, content = "500 Internal Server Error", b"Request failed"
        headers = [("Content-Type", mime + "; charset=utf-8"), ("Content-Length", str(len(content))),
                   ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                   ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")]
        if status.startswith("405"):
            headers.append(("Allow", "GET"))
        start_response(status, headers)
        return [content]
    return application


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    log = config_path.parent / config.get("LocalLog", "data/analyser.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[RotatingFileHandler(log, maxBytes=2_000_000, backupCount=3, encoding="utf-8")])
    from waitress import serve
    analyser = Analyser(config, config_path.parent, config_path)
    logging.info("RAS analyser starting on %s:%s", args.host, args.port)
    serve(application_for(analyser), host=args.host, port=args.port, threads=8,
          max_request_body_size=ANALYSIS_MAX_REQUEST, clear_untrusted_proxy_headers=True)


if __name__ == "__main__":
    main()
