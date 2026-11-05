"""Initialize persistent container settings once, then replace this process."""
import json
import os
from pathlib import Path
import sys
import tempfile


def initialize(state=Path('/data'), defaults=Path('/app/appsettings.json')):
    state = Path(state).resolve()
    state.mkdir(parents=True, exist_ok=True)
    config_path = state / 'appsettings.json'
    if not config_path.exists():
        config = json.loads(Path(defaults).read_text(encoding='utf-8-sig'))
        config.update(Database=str(state / 'issues.sqlite3'), LocalLog=str(state / 'logs' / 'analyser.log'))
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=state, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(config, stream, indent=2)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, config_path)  # Publish atomically; never replace existing settings.
            except FileExistsError:
                pass
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if Path(config['Database']) != state / 'issues.sqlite3':
        raise ValueError('Container Database must point to /data/issues.sqlite3 in the persistent volume')
    return config_path


if __name__ == '__main__':
    os.umask(0o077)
    initialize()
    if len(sys.argv) < 2:
        raise SystemExit('A server or maintenance command is required')
    os.execvp(sys.argv[1], sys.argv[1:])
