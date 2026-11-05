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
