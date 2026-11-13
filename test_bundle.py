import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from app import Analyser
from production import application_for
from bundle import BundleStore


def make_zip(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.store = BundleStore()
        self.temp = tempfile.TemporaryDirectory()
        self.collector = Analyser({'Database': 'test.sqlite3'}, self.temp.name)

    def test_entry_limit_and_expanded_size_have_distinct_diagnostics(self):
        from unittest.mock import patch
        raw = make_zip([('big.log', b'x' * 4096)])
        with patch('bundle.MAX_ENTRY_BYTES', 2048):
            with self.assertRaisesRegex(ValueError, r'big\.log.*4,096 bytes'):
                self.store.upload(io.BytesIO(raw), len(raw))
        with patch('bundle.MAX_INSPECTED_ENTRIES', 1):
            with self.assertRaisesRegex(ValueError, r'reached entry 2'):
                self.store.upload(io.BytesIO(raw), len(raw))
        self.assertFalse(self.store.sessions)

    def test_oversized_nested_perf_capture_is_counted_but_never_opened(self):
        from unittest.mock import patch
        inner = make_zip([('data/PERF.DAT', b'x' * 20000), ('controller.log', '[E] retained')])
        outer = make_zip([('RASAttachment.zip.log', inner)])
        original_open = zipfile.ZipFile.open
        def guarded_open(archive, member, *args, **kwargs):
            self.assertFalse(member.filename.lower().endswith('perf.dat'))
            return original_open(archive, member, *args, **kwargs)
        with patch.object(zipfile.ZipFile, 'open', guarded_open), patch('bundle.MAX_ENTRY_BYTES', 4096):
            result = self.store.upload(io.BytesIO(outer), len(outer))
            self.assertEqual(result['skipped'], 1)
            log, = result['servers'][0]['logs']
            data = self.store.analyze({'token': result['token'], 'log_id': log['id']}, self.collector)
            self.assertEqual(data['stats']['errors'], 1)
            with patch('bundle.MAX_INSPECTED_ENTRIES', 2):
                with self.assertRaisesRegex(ValueError, 'reached entry 3'):
                    self.store.upload(io.BytesIO(outer), len(outer))

    def test_farm_overview_and_ranked_drilldown(self):
        archive = make_zip([
            (name + "_DebugLog.zip", make_zip([("controller.log", "[E] failure\n" * count + "[I] ok")]))
            for name, count in (("C", 3), ("B", 3), ("A", 4), ("D", 2), ("E", 1), ("F", 1), ("G", 0))])
        opened = self.store.upload(io.BytesIO(archive), len(archive))
        import time
        deadline = time.monotonic() + 10
        while True:
            result = self.store.overview_status(opened["token"], self.collector)
            if result["done"]:break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)
        self.assertEqual(result["stats"]["errors"], 14)
        self.assertEqual(result["stats"]["total"], 21)
        self.assertEqual(result["included"], 7)
        self.assertEqual(result["omitted"], 0)
        self.assertEqual([(row["server"], row["errors"]) for row in result["top_logs"]],
                         [("A",4),("B",3),("C",3),("D",2),("E",1)])
        first = result["top_logs"][0]
        data = self.store.analyze({"token":opened["token"], "log_id":first["id"], "Severity":"error"}, self.collector)
        self.assertEqual(data["matched"], first["errors"])
        self.assertEqual(data["bundle_source"]["path"], first["path"])

    def test_open_log_while_overview_indexes_another(self):
        import threading
        import time
        from unittest.mock import patch
        login = "Login successful user 'alice'"
        controller = login + "\nLogon failed user 'alice'"
        data = make_zip([("Controller-1.log", controller), ("gateway.log", login + "\n[E] down")])
        opened = self.store.upload(io.BytesIO(data), len(data))
        token = opened["token"]
        entered, resume = threading.Event(), threading.Event()
        original = self.collector.build_index
        def build(payload, path):
            if payload["Files"][0]["Name"] == "Controller-1.log":
                entered.set()
                if not resume.wait(5): raise AssertionError("Concurrent log access stalled")
            return original(payload, path)
        from app import Parser, ROOT
        self.collector.parser = Parser(json.loads((ROOT/"appsettings.json").read_text()))
        with patch.object(self.collector, "build_index", side_effect=build):
            self.assertFalse(self.store.overview_status(token,self.collector)["done"])
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.store.overview_status(token,self.collector)["current"],"Controller-1.log")
                selected = self.store.analyze({"token":token,"log_id":"1"},self.collector)
                self.assertEqual(selected["stats"]["logins"],1)
            finally:
                resume.set()
            deadline=time.monotonic()+5
            while not (result:=self.store.overview_status(token,self.collector))["done"]:
                self.assertLess(time.monotonic(),deadline)
                time.sleep(.01)
        self.assertEqual(result["stats"]["logins"],1)
        self.assertEqual(result["stats"]["failed"],1)
        self.assertEqual(result["stats"]["total"],4)
        self.assertEqual(result["processed"],2)
        self.assertEqual(result["stats"]["errors"],2)

    def tearDown(self):
        for token in list(self.store.sessions):
            self.store.clear(token)
        self.temp.cleanup()

    def test_nested_disguised_zip_server_identity_and_text_analysis(self):
        nested = make_zip([('old.log', '[E] archived error')])
        server = make_zip([('controller.log', '[W] warning\n[I] ordinary'.encode('utf-16')),
                           ('older.zip', nested), ('data.evtx', b'binary'),
                           ('../../outside.log', '[E] path traversal stays a label')])
        outer = make_zip([('RED_BROKER_DebugLog.zip', server), ('Status.txt', 'ready')])
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            member = tarfile.TarInfo('RASAttachment.zip.log')
            member.size = len(outer)
            archive.addfile(member, io.BytesIO(outer))
        data = output.getvalue()
        result = self.store.upload(io.BytesIO(data), len(data))
        self.assertEqual([s['name'] for s in result['servers']], ['RED_BROKER', 'Farm-level files'])
        logs = result['servers'][0]['logs']
        self.assertEqual(len(logs), 3)
        self.assertEqual(result['skipped'], 1)
        self.assertTrue(any('older.zip' in log['path'] for log in logs))
        analysis = self.store.analyze({'token': result['token'], 'log_id': logs[0]['id']}, self.collector)
        self.assertEqual(analysis['stats']['warnings'], 1)
        self.assertEqual(analysis['stats']['information'], 1)
        self.assertEqual(analysis['bundle_source']['server'], 'RED_BROKER')
        session = self.store.sessions[result['token']]
        root = Path(session[1].name)
        for record in session[2]:
            self.assertEqual(record['disk'].parent, root)
        self.store.clear(result['token'])
        self.assertFalse(root.exists())
        with self.assertRaises(ValueError):
            self.store.analyze({'token': result['token'], 'log_id': '0'}, self.collector)

    def test_reject_bad_and_excessively_nested_archives(self):
        with self.assertRaises(ValueError):
            self.store.upload(io.BytesIO(b'not an archive'), 14)
        data = make_zip([('test.log', 'normal')])
        for _ in range(10):
            data = make_zip([('nested.zip', data)])
        with self.assertRaisesRegex(ValueError, 'nesting'):
            self.store.upload(io.BytesIO(data), len(data))
        self.assertEqual(self.store.sessions, {})

    def test_production_bundle_endpoints(self):
        self.collector.bundles = self.store
        application = application_for(self.collector)
        def request(path, body, mime, header='1'):
            response = {}
            environ = {'REQUEST_METHOD':'POST','PATH_INFO':path,'CONTENT_LENGTH':str(len(body)),
                       'CONTENT_TYPE':mime,'HTTP_X_LOGWATCH_ANALYZE':header,'wsgi.input':io.BytesIO(body)}
            def start(status, headers): response['status'] = status
            response['body'] = b''.join(application(environ, start))
            return response
        data = make_zip([('GW_GATEWAY_DebugLog.zip', make_zip([('gateway.log', '[E] failure')]))])
        result = request('/api/bundle', data, 'application/octet-stream')
        self.assertEqual(result['status'], '200 OK')
        token = json.loads(result['body'])['token']
        result = request('/api/bundle/analyze', json.dumps({'token':token,'log_id':'0'}).encode(), 'application/json')
        self.assertEqual(json.loads(result['body'])['stats']['errors'], 1)
        denied = request('/api/bundle', data, 'application/octet-stream', '')
        self.assertEqual(denied['status'], '403 Forbidden')
        self.assertEqual(request('/api/bundle/clear', json.dumps({'token':token}).encode(), 'application/json')['status'], '200 OK')

if __name__ == '__main__':
    unittest.main()
