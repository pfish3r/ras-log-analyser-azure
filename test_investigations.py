from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from app import Analyser, ROOT
from test_bundle import make_zip
import io


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config_path = self.root / "appsettings.json"
        self.config = {"Database": "issues.sqlite3", "ErrorSearchStrings": ["custom"]}
        self.config_path.write_text(json.dumps(self.config))
        self.app = Analyser(self.config, self.root, self.config_path)
        self.store = self.app.bundles

    def tearDown(self):
        for token in list(self.store.sessions):
            self.store.clear(token)
        if self.store.timer:
            self.store.timer.cancel()
        self.temp.cleanup()

    def upload(self, text):
        return self.app.analyze_logs({"Indexed": True, "Files": [{"Name": "test.log", "Content": text}]})

    def query(self, token, **params):
        return self.store.index_query(token, "", params, self.app)

    def test_usage_persists_and_cached_queries_do_not_recount(self):
        self.app.usage.visit("1", 0, "visit")
        result = self.upload("[E] test")
        self.query(result["investigation"], Severity="error")
        self.app.usage.visit("1", 0, "upload")
        blob = make_zip([("controller.log", "[I] café".encode())])
        opened = self.store.request("/api/bundle", io.BytesIO(blob), len(blob),
                                    "application/octet-stream", "1", self.app)
        for _ in range(2):
            self.store.analyze({"token":opened["token"],"log_id":"0"}, self.app)
        expected = dict(sessions=1, upload_sessions=1, bundles=1, files=1, logs=2,
                        uploaded_bytes=len(blob)+8, processed_bytes=8+len("[I] café".encode()))
        self.assertEqual(self.app.usage.totals(), expected)
        restored = Analyser(self.config, self.root, self.config_path)
        self.assertEqual(restored.usage.totals(), expected)

    def test_filters_page_context_and_cleanup_are_isolated(self):
        first = self.upload("[E] failed\n[I] retry\n[E] failed")
        second = self.upload("[W] different case")
        token = first["investigation"]
        folder = Path(self.store.sessions[token][1].name)
        with patch.object(self.app.parser, "parse", side_effect=AssertionError("reparsed")):
            page = self.query(token, Severity="all", PageSize=1, Offset=1)
            self.assertEqual(page["issues"][0]["raw"], "[I] retry")
            self.assertEqual(self.query(token, Query="FAILED")["matched"], 2)
            self.assertEqual(page["groups"][0]["latest"]["line"], 3)
        self.store.clear(token)
        self.store.clear(token)
        self.assertFalse(folder.exists())
        with self.assertRaisesRegex(ValueError, "expired or cleared"):
            self.query(token)
        self.assertEqual(self.query(second["investigation"])["matched"], 1)

    def test_bundle_lazily_builds_once_and_expires_without_requests(self):
        self.store.ttl = .25
        self.store.sweep_seconds = .025
        archive = make_zip([("first.log", "[E] failure"), ("second.log", "[W] warning")])
        opened = self.store.upload(io.BytesIO(archive), len(archive))
        token = opened["token"]
        folder = Path(self.store.sessions[token][1].name)
        logs = opened["servers"][0]["logs"]
        with patch.object(self.app, "build_index", wraps=self.app.build_index) as build:
            payload = {"token": token, "log_id": logs[0]["id"]}
            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(lambda _: self.store.analyze(payload, self.app), range(2)))
            self.assertEqual(build.call_count, 1)
            self.assertEqual(results[0]["stats"]["errors"], 1)
        deadline = time.monotonic()+3
        while folder.exists() and time.monotonic()<deadline:
            time.sleep(.02)
        self.assertFalse(folder.exists())

    def test_defaults_survive_edits_and_require_explicit_save(self):
        shipped = json.loads((ROOT/"appsettings.json").read_text())
        defaults = self.app.parser_defaults()
        self.assertEqual(defaults["ErrorSearchStrings"], shipped["ErrorSearchStrings"])
        self.assertEqual(self.app.admin_settings()["ErrorSearchStrings"], ["custom"])
        self.app.update_admin_settings(defaults)
        restored = json.loads(self.config_path.read_text())
        self.assertEqual(restored["Database"], "issues.sqlite3")
        self.assertEqual(restored["ErrorSearchStrings"], defaults["ErrorSearchStrings"])
        self.assertEqual(restored["ParseRules"], defaults["ActivityRules"])
