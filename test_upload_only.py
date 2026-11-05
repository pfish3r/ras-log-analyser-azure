import io,json,sqlite3,tempfile,threading,unittest
from pathlib import Path
from contextlib import closing
from http.server import ThreadingHTTPServer
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from app import Analyser,Store,handler_for,ROOT
from production import application_for
from import_issues import import_library

class UploadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name)
        self.config={'Database':'issues.sqlite3','Sources':[{'Folder':str(self.base),'Files':['*.log']}]}
        self.path=self.base/'appsettings.json';self.path.write_text(json.dumps(self.config))
        self.app=Analyser(self.config,self.base,self.path)
    def tearDown(self): self.temp.cleanup()
    def request(self,path,method='GET',payload=None):
        raw=json.dumps(payload).encode() if payload is not None else b''
        env={'REQUEST_METHOD':method,'PATH_INFO':path,'wsgi.input':io.BytesIO(raw),
             'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','HTTP_X_LOGWATCH_ADMIN':'1','HTTP_X_LOGWATCH_ANALYZE':'1'}
        response={}
        def start(status,headers): response['status']=int(status.split()[0])
        response['body']=b''.join(application_for(self.app)(env,start))
        return response
    def test_removed_capabilities_and_routes(self):
        for name in ('scan','run','sources','read_file','manage_shares','snapshot','stop'):
            self.assertFalse(hasattr(self.app,name),name)
        for path in ('/api/snapshot','/api/shares'):
            for method in ('GET','POST'):
                self.assertEqual(self.request(path,method,{'action':'save','password':'dummy'})['status'],404)
        self.assertEqual(set(self.app.admin_settings()),{'ErrorSearchStrings','ActivityRules','CanSave'})
        for key in ('Sources','LogFolders','PollSeconds','RetentionDays','password','CanManageShares'):
            self.assertEqual(self.request('/api/settings','POST',{key:[]})['status'],400)
        with self.app.store.connect() as db:
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(tables,{'known_issues'})
    def test_standard_http_routes_and_upload(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(self.app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            for path in ('/api/snapshot','/api/shares'):
                for method in ('GET','POST'):
                    with self.assertRaises(HTTPError) as error:urlopen(Request(base+path,method=method),timeout=5)
                    self.assertEqual(error.exception.code,404)
            for path in ('/','/app.js','/style.css','/admin.css','/api/settings','/api/known-issues'):
                with urlopen(base+path,timeout=5) as response:self.assertEqual(response.status,200)
            body=json.dumps({'Files':[{'Name':'test.log','Content':'[E] failure'}]}).encode()
            request=Request(base+'/api/analyze',data=body,headers={'Content-Type':'application/json','X-Logwatch-Analyze':'1'})
            with urlopen(request,timeout=5) as response:self.assertEqual(json.load(response)['stats']['errors'],1)
        finally:server.shutdown();server.server_close();thread.join()
    def test_legacy_database_history_and_schema_untouched(self):
        path=self.base/'legacy.sqlite3'
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("CREATE TABLE events(id INTEGER,raw TEXT,matched TEXT); INSERT INTO events VALUES(1,'history','yes'); CREATE TABLE checkpoints(path TEXT); INSERT INTO checkpoints VALUES('original');")
        Store(path)
        with closing(sqlite3.connect(path)) as db, db:
            self.assertEqual(db.execute('SELECT * FROM events').fetchall(),[(1,'history','yes')])
            self.assertEqual(db.execute('SELECT * FROM checkpoints').fetchall(),[('original',)])
    def test_issue_import_readonly_merge_idempotent(self):
        source=self.base/'source.sqlite3';old=Store(source)
        issue={'title':'Saved','phrase':'failure','severity':'error','notes':'resolution','links':'https://example.com/kb','sample':'failure'}
        old.save_issue(issue)
        with old.connect() as db:db.executescript("CREATE TABLE events(raw TEXT); INSERT INTO events VALUES('keep');")
        before=source.read_bytes()
        self.app.store.save_issue(dict(issue,title='Existing'))
        added,backup=import_library(source,self.app.store.path)
        self.assertEqual(added,1);self.assertTrue(backup.exists())
        self.assertEqual(len(Store(backup).known_issues()),1)
        self.assertEqual(import_library(source,self.app.store.path)[0],0)
        self.assertEqual(len(self.app.store.known_issues()),2)
        self.assertEqual(source.read_bytes(),before)
    def test_settings_and_analysis_safety(self):
        saved=self.request('/api/settings','POST',{'ErrorSearchStrings':['custom fault'],'ActivityRules':[]})
        self.assertEqual(saved['status'],200)
        self.assertEqual(Analyser(json.loads(self.path.read_text()),self.base).parser.parse('CUSTOM FAULT','test')['kind'],'error')
        for payload in ({'Files':[]},{'Files':[{'Name':'big.log','Content':'x'*(1024*1024+1)}]}, {'Files':[{'Name':'x','Content':'x'}],'Severity':'invalid'}):
            self.assertEqual(self.request('/api/analyze','POST',payload)['status'],400)
    def test_ui_has_no_live_controls_or_broker_routes(self):
        html=(ROOT/'static/index.html').read_text(encoding='utf-8');js=(ROOT/'static/app.js').read_text(encoding='utf-8')
        for text in ('tab-live','view-live','share-password','live-server','/api/snapshot','/api/shares','setInterval'):
            self.assertNotIn(text,html+js)
        import re
        ids=set(re.findall(r'id="([^"]+)"',html))
        literals=set(re.findall(r"\$\('([^']+)'\)",js))
        self.assertFalse(literals-ids,literals-ids)

if __name__=='__main__':unittest.main()
