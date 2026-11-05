import io
import json
from pathlib import Path
import tempfile
import unittest
from wsgiref.validate import validator

from app import Analyser
from production import application_for


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        for name in ('broker1', 'broker2'):
            (base / name).mkdir()
            (base / name / 'controller.log').write_text('ERROR connection timed out\n', encoding='utf-8')
        config = {'Database': 'logs.sqlite3', 'Sources': [
            {'Folder': name, 'Files': ['controller.log'], 'Encoding': 'utf-8'} for name in ('broker1', 'broker2')]}
        self.config_path = base / 'appsettings.json'
        self.config_path.write_text(json.dumps(config), encoding='utf-8')
        self.collector = Analyser(config, base, self.config_path)
        self.application = validator(application_for(self.collector))

    def tearDown(self):
        self.temp.cleanup()

    def request(self, path='/', query='', method='GET', body=b'', **extra):
        environ = {'REQUEST_METHOD': method, 'PATH_INFO': path, 'SCRIPT_NAME': '',
                   'QUERY_STRING': query, 'SERVER_NAME': 'localhost', 'SERVER_PORT': '5001',
                   'SERVER_PROTOCOL': 'HTTP/1.1', 'wsgi.version': (1, 0), 'wsgi.url_scheme': 'http',
                   'wsgi.input': io.BytesIO(body), 'wsgi.errors': io.StringIO(), 'wsgi.multithread': True,
                   'wsgi.multiprocess': False, 'wsgi.run_once': False, **extra}
        response = {}

        def start(status, headers, exc_info=None):
            response.update(status=status, headers=dict(headers))

        body = self.application(environ, start)
        try:
            response['body'] = b''.join(body)
        finally:
            if hasattr(body, 'close'):
                body.close()
        return response

    def test_known_issue_library_persistence_and_validation(self):
        payload = {'title': 'Agent disabled', 'phrase': 'Agent was disabled', 'severity': 'warning',
                   'notes': 'Check agent status. KB123', 'links': 'https://example.com/kb/123', 'sample': '[W x] Agent was disabled'}
        def save(value, **headers):
            body = json.dumps(value).encode()
            return self.request('/api/known-issues', method='POST', body=body,
                                CONTENT_LENGTH=str(len(body)), CONTENT_TYPE='application/json', **headers)
        self.assertEqual(save(payload)['status'], '415 Unsupported Media Type')
        self.assertEqual(save(payload, HTTP_X_LOGWATCH_ADMIN='1', HTTP_SEC_FETCH_SITE='cross-site')['status'], '403 Forbidden')
        response = save(payload, HTTP_X_LOGWATCH_ADMIN='1')
        self.assertEqual(response['status'], '200 OK')
        saved = json.loads(response['body'])
        self.assertEqual(len(saved['issues']), 1)
        payload['id'] = saved['id']; payload['notes'] = 'Updated resolution'
        self.assertEqual(save(payload, HTTP_X_LOGWATCH_ADMIN='1')['status'], '200 OK')
        from app import Store
        restored = Store(self.collector.store.path).known_issues()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]['notes'], 'Updated resolution')
        payload['links'] = 'javascript:alert(1)'
        self.assertEqual(save(payload, HTTP_X_LOGWATCH_ADMIN='1')['status'], '400 Bad Request')
        payload['links'] = ''; payload['phrase'] = ' '
        self.assertEqual(save(payload, HTTP_X_LOGWATCH_ADMIN='1')['status'], '400 Bad Request')
        self.assertEqual(len(json.loads(self.request('/api/known-issues')['body'])), 1)





    def test_uploaded_log_analysis_endpoint(self):
        payload = json.dumps({'Files': [{'Name': 'controller.log',
                                         'Content': '[E123] failure\n[W123] warning\n[I123] normal'}]}).encode()
        response = self.request('/api/analyze', method='POST', body=payload,
                                CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(payload)),
                                HTTP_X_LOGWATCH_ANALYZE='1')
        self.assertEqual(response['status'], '200 OK')
        result = json.loads(response['body'])
        self.assertEqual((result['stats']['errors'], result['stats']['warnings'],
                          result['stats']['information']), (1, 1, 1))
        rejected = self.request('/api/analyze', method='POST', body=payload,
                                CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(payload)))
        self.assertEqual(rejected['status'], '415 Unsupported Media Type')


    def test_analysis_accepts_over_100_mib_and_250000_lines(self):
        line = '[I] ' + 'x' * 395 + '\n'
        count = 270000
        content = line * count + '[E] final error\n'
        self.assertGreater(len(content), 100 * 1024 * 1024)
        payload = json.dumps({'Files': [{'Name': 'large.log', 'Content': content}]}).encode()
        response = self.request('/api/analyze', method='POST', body=payload,
                                CONTENT_TYPE='application/json', CONTENT_LENGTH=str(len(payload)),
                                HTTP_X_LOGWATCH_ANALYZE='1')
        self.assertEqual(response['status'], '200 OK')
        data = json.loads(response['body'])
        self.assertEqual(data['stats']['total'], count + 1)
        self.assertEqual(data['stats']['information'], count)
        self.assertEqual(data['stats']['errors'], 1)
        self.assertEqual(data['issues'][0]['line'], count + 1)

    def test_latest_issue_across_files_and_beyond_display_limit(self):
        payload = {'Files': [
            {'Name': 'broker-a.log', 'Content': '[E 1] 17-09-26 12:00:00 - failure\n' * 5001 + '[E 1] 17-09-26 14:00:00 - failure'},
            {'Name': 'broker-b.log', 'Content': '[E 2] 17-09-26 13:00:00 - failure'},
            {'Name': 'empty.log', 'Content': '[I] normal'}]}
        result = self.collector.analyze_logs(payload)
        group = result['groups'][0]
        self.assertEqual(group['count'], 5003)
        self.assertEqual(group['latest']['file'], 'broker-a.log')
        self.assertEqual(group['latest']['line'], 5002)
        self.assertEqual(group['latest']['timestamp'], '17-09-26 14:00:00')
        self.assertNotIn(group['latest']['id'], [item['id'] for item in result['issues']])
        self.assertEqual(result['file_groups']['1'][0]['count'], 1)
        self.assertEqual(result['file_groups']['1'][0]['latest']['file'], 'broker-b.log')
        self.assertEqual(result['file_groups']['2'], [])
        self.assertEqual(len(group['files']), 2)
        self.assertEqual(len(result['file_options']), 3)

if __name__ == '__main__':
    unittest.main()
