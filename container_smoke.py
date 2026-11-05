"""CI integration check against a disposable Compose deployment."""
import io
import json
import subprocess
import tarfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

BASE = 'http://127.0.0.1:8767'
def command(*args):
    return subprocess.check_output(['docker','compose',*args], text=True).strip()

def request(path, payload=None, header='X-Logwatch-Admin', raw=None):
    data = raw if raw is not None else json.dumps(payload).encode() if payload is not None else None
    headers = {header:'1','Content-Type':'application/octet-stream' if raw is not None else 'application/json'}
    with urlopen(Request(BASE + path, data=data, headers=headers),timeout=30) as response:
        return json.load(response)

issue = {'title':'Container persistence','phrase':'persistent fault','severity':'error','notes':'Saved resolution','links':'https://example.com/kb','sample':'persistent fault'}
saved = request('/api/known-issues', issue)
request('/api/settings', {'ErrorSearchStrings':['persistent fault'],'ActivityRules':[]})
result = request('/api/analyze', {'Files':[{'Name':'test.log','Content':'persistent fault\n[I] okay'}],'Severity':'all'}, 'X-Logwatch-Analyze')
assert result['stats']['errors'] == 1 and result['matched'] == 2
nested = io.BytesIO()
with zipfile.ZipFile(nested,'w') as archive:archive.writestr('controller.log','[E] nested fault')
outer = io.BytesIO()
with zipfile.ZipFile(outer,'w') as archive:archive.writestr('SERVER_DebugLog.zip',nested.getvalue())
bundle = request('/api/bundle',header='X-Logwatch-Analyze',raw=outer.getvalue())
log = bundle['servers'][0]['logs'][0]
assert request('/api/bundle/analyze',{'token':bundle['token'],'log_id':log['id']},'X-Logwatch-Analyze')['stats']['errors']==1
for path in ('/api/snapshot','/api/shares'):
    try:request(path, {})
    except HTTPError as error:assert error.code == 404
    else:raise AssertionError('Removed live route available')
assert command('exec','-T','analyser','id','-u') == '10001'
backup = command('exec','-T','analyser','python','container_backup.py')
command('cp','analyser:'+backup,'container-test-backup.tar.gz')
with tarfile.open('container-test-backup.tar.gz') as archive:assert set(archive.getnames())=={'appsettings.json','issues.sqlite3'}
# Remove the container and network, retain its named volume, then create a new container.
old = command('ps','-q','analyser')
command('down')
command('up','-d','--wait','--wait-timeout','120')
assert command('ps','-q','analyser') != old
assert request('/api/known-issues') == saved['issues']
assert request('/api/settings')['ErrorSearchStrings'] == ['persistent fault']
assert request('/api/analyze',{'Files':[{'Name':'test.log','Content':'persistent fault'}]},'X-Logwatch-Analyze')['stats']['errors']==1
print('PASS: non-root image, uploads, nested bundles, removed routes, backup, settings and issue library after container replacement')
