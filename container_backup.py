"""Create a consistent SQLite snapshot and settings archive in the persistent volume."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile


def backup(state=Path('/data')):
    state = Path(state).resolve()
    config_path = state / 'appsettings.json'
    config_bytes = config_path.read_bytes()
    database = Path(json.loads(config_bytes)['Database'])
    if database != state / 'issues.sqlite3':
        raise ValueError('Expected the container database inside the persistent volume')
    folder = state / 'backups'
    folder.mkdir(mode=0o700, exist_ok=True)
    output = folder / ('ras-log-analyser-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.tar.gz')
    with tempfile.TemporaryDirectory(dir=state) as temporary:
        temporary = Path(temporary)
        (temporary / 'appsettings.json').write_bytes(config_bytes)
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as source, closing(sqlite3.connect(temporary / 'issues.sqlite3')) as destination:
            source.backup(destination)
        with tarfile.open(output, 'x:gz') as archive:
            for name in ('appsettings.json', 'issues.sqlite3'):
                archive.add(temporary / name, arcname=name)
    output.chmod(0o600)
    return output


if __name__ == '__main__':
    print(backup())
