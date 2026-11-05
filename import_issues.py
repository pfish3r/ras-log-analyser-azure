"""Merge only known_issues from a read-only SQLite source; never copy live history."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from app import Store

FIELDS = 'title,phrase,severity,notes,links,sample,updated'

def import_library(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source == destination:
        raise ValueError('Source and destination must be different databases')
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as db:
        rows = db.execute(f'SELECT {FIELDS} FROM known_issues').fetchall()
    backup = None
    if destination.exists():
        backup = destination.with_name(destination.name + '.' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.bak')
        with closing(sqlite3.connect(destination.as_uri() + '?mode=ro', uri=True)) as src, closing(sqlite3.connect(backup)) as dst:
            src.backup(dst)
    store = Store(destination)
    added = 0
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        # Ignore original IDs; preserve all destination records and skip identical content.
        existing = {tuple(row)[:6] for row in db.execute(f'SELECT {FIELDS} FROM known_issues')}
        for row in rows:
            if row[:6] not in existing:
                db.execute(f'INSERT INTO known_issues({FIELDS}) VALUES(?,?,?,?,?,?,?)', row)
                existing.add(row[:6])
                added += 1
    return added, backup

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('destination')
    args = parser.parse_args()
    added, backup = import_library(args.source, args.destination)
    print(f'Imported {added} issues. Destination backup: {backup or "new database"}. Source was opened read-only.')
