import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request
from urllib.request import urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer
from app import Analyser, Parser, ROOT, handler_for


class AnalyserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.config = json.loads((ROOT / "appsettings.json").read_text())
        self.config.update(Database="db.sqlite3", Sources=[{"Folder": ".", "Files": ["input.log"], "Encoding": "utf-8", "Host": "RDS-01"}])
        self.collector = Analyser(self.config, self.base)
        self.file = self.base / "input.log"

    def tearDown(self):
        self.temp.cleanup()


    def test_analysis_date_range_before_cap_and_groups(self):
        content = '[E x] 01-09-26 10:00:00 - Old error\n' * 5001
        content += '[E x] 17-09-26 00:00:00 - Recent error\n'
        content += '[W x] 17-09-26 12:00:00 - Recent warning\n'
        content += '[I x] 17-09-26 12:00:01 - Information\n'
        content += '[E x] 18-09-26 00:00:00 - Future error\nERROR undated\n'
        payload = {'Files': [{'Name': 'test.log', 'Content': content}],
                   'Since': '2026-09-17T00:00:00', 'Until': '2026-09-17T12:00:01'}
        result = self.collector.analyze_logs(payload)
        self.assertEqual(result['stats']['total'], 3)
        self.assertEqual(result['stats']['errors'], 1)
        self.assertEqual(result['stats']['warnings'], 1)
        self.assertEqual(result['stats']['information'], 1)
        self.assertEqual(result['unknown_timestamps'], 1)
        self.assertEqual(result['omitted'], 0)
        self.assertEqual(result['issues'][0]['line'], 5002)
        self.assertEqual(len(result['groups']), 2)
        self.assertEqual(len(result['file_groups']['0']), 2)
        payload.pop('Since'); payload.pop('Until')
        self.assertEqual(self.collector.analyze_logs(payload)['stats']['total'], 5006)

    def test_all_log_paging_and_severity(self):
        content = '[I x] routine information\n' * 5001 + '[E x] error detail\n[W x] warning detail\n\ncontinuation'
        payload = {'Files': [{'Name': 'test.log', 'Content': content}], 'Severity': 'all', 'PageSize': 2, 'Offset': 5001}
        result = self.collector.analyze_logs(payload)
        self.assertEqual(result['matched'], 5005)
        self.assertEqual([r['severity'] for r in result['issues']], ['error', 'warning'])
        payload['Offset'] = 5003
        result = self.collector.analyze_logs(payload)
        self.assertEqual([r['raw'] for r in result['issues']], ['', 'continuation'])
        self.assertEqual([r['line'] for r in result['issues']], [5004, 5005])
        payload.update(Severity='error', Offset=0)
        result = self.collector.analyze_logs(payload)
        self.assertEqual(result['matched'], 1)
        self.assertEqual(result['issues'][0]['line'], 5002)
        payload.update(Severity='info', Query='routine')
        self.assertEqual(self.collector.analyze_logs(payload)['matched'], 5001)
        payload.update(FileId='1')
        self.assertEqual(self.collector.analyze_logs(payload)['matched'], 0)

    def test_analysis_invalid_date_range(self):
        with self.assertRaises(ValueError):
            self.collector.analyze_logs({'Files': [{'Name': 'test.log', 'Content': 'ERROR'}],
                                         'Since': 'bad', 'Until': '2026-09-17'})








    def test_failed_login_without_username(self):
        event = self.collector.parser.parse("[W 06/test] 10-09-26 12:41:43 - Logon failed user '' client IP '192.0.2.5'", "controller.log")
        self.assertEqual(event["kind"], "login_failed")
        self.assertEqual(event["user"], "")

    def test_admin_settings_persist_and_apply(self):
        config_path = self.base / "appsettings.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.collector = Analyser(self.config, self.base, config_path)
        settings = {"ErrorSearchStrings": ["custom failure"],
                    "ActivityRules": [
                        {"Kind": "login", "Pattern": r"signed in: (?P<user>\S+) from (?P<ip>\S+)"},
                        {"Kind": "connection", "Pattern": r"(?P<user>\S+) opened (?P<host>\S+)"},
                        {"Kind": "logout", "Pattern": r"signed out: (?P<user>\S+)"},
                    ]}
        saved = self.collector.update_admin_settings(settings)
        self.assertTrue(saved["CanSave"])
        self.assertEqual(saved["ActivityRules"], settings["ActivityRules"])
        self.assertEqual(json.loads(config_path.read_text())["ErrorSearchStrings"], ["custom failure"])
        self.assertEqual(self.collector.parser.parse("CUSTOM FAILURE happened", "test")["kind"], "error")
        connection = self.collector.parser.parse("alice opened RDS-07", "test")
        self.assertEqual((connection["kind"], connection["user"], connection["host"]),
                         ("connection", "alice", "RDS-07"))
        self.assertEqual(self.collector.parser.parse("ordinary message", "test")["kind"], "info")



    def test_admin_settings_reject_invalid_activity_rules(self):
        source = [{"Folder": str(self.base), "Files": ["*.log"], "Encoding": "utf-8"}]
        for rules in (
            [{"Kind": "login", "Pattern": "("}],
            [{"Kind": "login", "Pattern": r"user \S+"}],
            [{"Kind": "connection", "Pattern": r"user (?P<user>\S+)"}],
            [{"Kind": "warning", "Pattern": r"(?P<user>\S+)"}],
        ):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                self.collector.validate_admin_settings(
                    {"ErrorSearchStrings": [], "ActivityRules": rules})

    def test_uploaded_log_analysis_uses_ras_severity_prefixes(self):
        result = self.collector.analyze_logs({"Files": [{"Name": "controller.log", "Content": "\n".join((
            "[E01] 10-09-26 12:00:00 - Broker service failed",
            "[W02] 10-09-26 12:00:01 - Logon failed user 'alice' client IP '192.0.2.8'",
            "[I03] 10-09-26 12:00:02 - Service started",
            "[W04] 10-09-26 12:00:03 - User 'alice' connected to host 'RDS-02'",
        ))}]})
        self.assertEqual(result["stats"]["total"], 4)
        self.assertEqual((result["stats"]["errors"], result["stats"]["warnings"],
                          result["stats"]["information"]), (1, 2, 1))
        self.assertEqual(result["stats"]["failed"], 1)
        self.assertEqual(result["stats"]["connections"], 1)
        self.assertEqual(result["stats"]["users"], 1)
        self.assertEqual(result["stats"]["hosts"], 1)
        self.assertEqual(len(result["issues"]), 3)
        self.assertEqual(result["groups"][0]["message"], "Broker service failed")



if __name__ == "__main__":
    unittest.main()
