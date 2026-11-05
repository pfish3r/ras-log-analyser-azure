import json
from pathlib import Path
import sqlite3
from contextlib import closing
import tarfile
import tempfile
import unittest
from app import Store, ROOT
from container_entrypoint import initialize
from container_backup import backup


class ContainerStateTests(unittest.TestCase):
    def test_reinitialization_preserves_settings_and_issue_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            path = initialize(state, ROOT / 'appsettings.json')
            config = json.loads(path.read_text())
            config['ErrorSearchStrings'] = ['persistent custom phrase']
            path.write_text(json.dumps(config))
            store = Store(config['Database'])
            store.save_issue({'title':'Persistent issue','phrase':'fault','severity':'error','notes':'Resolution','links':'https://example.com/kb','sample':'fault'})
            previous = path.read_bytes()
            initialize(state, ROOT / 'appsettings.json')
            self.assertEqual(path.read_bytes(), previous)
            self.assertEqual(Store(config['Database']).known_issues()[0]['title'], 'Persistent issue')
            archive_path = backup(state)
            with tarfile.open(archive_path) as archive:
                self.assertEqual(set(archive.getnames()), {'appsettings.json','issues.sqlite3'})
                self.assertEqual(archive.extractfile('appsettings.json').read(), previous)
                restored = state / 'restored.sqlite3'
                restored.write_bytes(archive.extractfile('issues.sqlite3').read())
            self.assertEqual(Store(restored).known_issues(), store.known_issues())

    def test_bad_existing_config_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            path = state / 'appsettings.json'
            path.write_text('{bad')
            with self.assertRaises(ValueError):initialize(state, ROOT / 'appsettings.json')
            self.assertEqual(path.read_text(), '{bad')

    def test_database_outside_volume_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            path = state / 'appsettings.json'
            path.write_text(json.dumps({'Database':'/app/ephemeral.sqlite3'}))
            with self.assertRaises(ValueError):initialize(state, ROOT / 'appsettings.json')

if __name__ == '__main__':unittest.main()
