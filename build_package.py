"""Build an allowlisted upload-only source/deployment package; exclude runtime data."""
import argparse,hashlib,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
FILES=['version_stamp.py','install-azure.sh','Dockerfile','compose.yaml','.dockerignore','container_entrypoint.py','container_backup.py','test_container.py','container_smoke.py','CONTAINERS.md','app.py','production.py','bundle.py','import_issues.py','appsettings.json','requirements-server.txt',
       'start.cmd','README.md','build_package.py','test_app.py','test_production.py','test_bundle.py','test_upload_only.py',
       'static/index.html','static/app.js','static/style.css','static/admin.css',
       'linux/common.sh','linux/01-install.sh','linux/03-update.sh','linux/04-backup.sh','linux/ras-log-analyser.service']
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output');args=parser.parse_args()
    output=Path(args.output).resolve();output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(output,'w:gz') as archive:
        for name in FILES:
            source=ROOT/name
            info=archive.gettarinfo(str(source),arcname='ras-log-analyser/'+name)
            info.uid=info.gid=0;info.uname=info.gname='';info.mode=0o755 if name.endswith('.sh') else 0o644
            if name == 'static/index.html':
                from io import BytesIO
                from version_stamp import stamp
                data = stamp(source.read_bytes(), ROOT)
                info.size = len(data)
                archive.addfile(info, BytesIO(data))
            else:
                with source.open('rb') as stream:archive.addfile(info,stream)
    digest=hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name+'.sha256').write_text(f'{digest}  {output.name}\n',encoding='ascii')
    print(f'{output}\nSHA256 {digest}\n{len(FILES)} allowlisted files')
