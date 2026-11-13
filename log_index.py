"""Temporary parsed log index and bounded query-summary cache."""
from contextlib import closing
from datetime import datetime
import sqlite3


class LogIndex:
    columns = "file_id,line,timestamp,sort_time,severity,kind,file,user,host,ip,raw"

    def __init__(self, path, names, rows):
        self.path = path
        self.names = names
        self.cache_key = self.summary = None
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""CREATE TABLE entries(file_id TEXT,line INTEGER,timestamp TEXT,
                sort_time TEXT,severity TEXT,kind TEXT,file TEXT,user TEXT,host TEXT,ip TEXT,
                raw TEXT,signature TEXT,group_key TEXT,blank INTEGER,wall_time TEXT)""")
            db.executemany("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            db.execute("CREATE INDEX by_file ON entries(file_id,line)")
            db.execute("CREATE INDEX by_group ON entries(severity,group_key,sort_time)")
            db.execute("CREATE INDEX by_time ON entries(wall_time)")
            db.execute("CREATE INDEX by_severity ON entries(severity)")

    @staticmethod
    def item(row):
        data = dict(row)
        data["id"] = f"{data['file_id']}:{data['line']}"
        return data

    def add_overview(self, totals):
        with closing(sqlite3.connect(self.path)) as db:
            counts = db.execute("""SELECT count(*), count(CASE WHEN kind='login' THEN 1 END),
                count(CASE WHEN kind='login_failed' THEN 1 END),
                count(CASE WHEN severity='error' THEN 1 END) FROM entries WHERE blank=0""").fetchone()
            for key, count in zip(("total", "logins", "failed", "errors"), counts):
                totals[key] += count
            for column, key in (("user", "users"), ("host", "hosts")):
                totals[key].update(value for value, in db.execute(
                    f"SELECT DISTINCT {column} FROM entries WHERE blank=0 AND {column} != ''"))

    def groups(self, db, condition, params):
        groups = []
        # Only construct occurrence details for the 25 groups displayed.
        for row in db.execute(f"""SELECT severity,group_key,signature,count(*) AS n
                FROM entries WHERE {condition} AND group_key IS NOT NULL
                GROUP BY severity,group_key ORDER BY n DESC,signature LIMIT 25""", params):
            where = condition + " AND severity=? AND group_key=?"
            values = [*params, row["severity"], row["group_key"]]
            latest = db.execute(f"SELECT {self.columns} FROM entries WHERE {where} ORDER BY sort_time DESC,rowid DESC LIMIT 1", values).fetchone()
            files = dict(db.execute(f"SELECT DISTINCT file_id,file FROM entries WHERE {where}", values))
            groups.append(dict(severity=row["severity"], message=row["signature"], count=row["n"],
                               latest=self.item(latest), files=files))
        return groups

    def query(self, payload, max_page):
        severity = payload.get("Severity", "")
        if severity not in ("", "all", "error", "warning", "info"):
            raise ValueError("Invalid severity filter")
        where = "1" if severity == "all" else "blank=0"
        params = []
        since = payload.get("Since")
        if since is not None:
            try:
                bounds = [datetime.fromisoformat(value) for value in (since, payload["Until"])]
                if any(value.tzinfo for value in bounds) or bounds[0] > bounds[1]:
                    raise ValueError()
                params = [value.isoformat(timespec="microseconds") for value in bounds]
            except (TypeError, ValueError, KeyError):
                raise ValueError("Invalid analysis date range") from None
        try:
            offset = max(0, int(payload.get("Offset", 0)))
            limit = max(1, min(max_page, int(payload.get("PageSize", max_page))))
        except (TypeError, ValueError):
            raise ValueError("Invalid page") from None
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            db.create_function("fold", 1, str.casefold)
            base = where
            if params:
                where += " AND wall_time BETWEEN ? AND ?"
            key = (base, *params)
            if self.cache_key != key:
                unknown = 0
                if params:
                    unknown = db.execute(f"SELECT count(*) FROM entries WHERE {base} AND sort_time=''", ()).fetchone()[0]
                stats = dict(db.execute(f"""SELECT count(*) total,
                    count(CASE WHEN severity='error' THEN 1 END) errors,
                    count(CASE WHEN severity='warning' THEN 1 END) warnings,
                    count(CASE WHEN severity='info' THEN 1 END) information,
                    count(CASE WHEN kind='login' THEN 1 END) logins,
                    count(CASE WHEN kind='login_failed' THEN 1 END) failed,
                    count(CASE WHEN kind='connection' THEN 1 END) connections,
                    count(CASE WHEN kind='logout' THEN 1 END) logouts,
                    count(distinct nullif(user,'')) users, count(distinct nullif(host,'')) hosts
                    FROM entries WHERE {where}""", params).fetchone())
                groups = self.groups(db, where, params)
                per_file = {str(i): groups if len(self.names)==1 else self.groups(db, where+" AND file_id=?", [*params,str(i)])
                            for i in range(len(self.names))}
                self.summary = dict(stats=stats, groups=groups, file_groups=per_file, unknown_timestamps=unknown,
                                    files=len(self.names), file_options=[dict(id=str(i),name=n) for i,n in enumerate(self.names)])
                self.cache_key = key
            if severity == "":
                where += " AND severity IN ('error','warning')"
            elif severity != "all":
                where += " AND severity=?"
                params.append(severity)
            file_id = str(payload.get("FileId", ""))
            if file_id:
                where += " AND file_id=?"
                params.append(file_id)
            query = str(payload.get("Query","")).strip().casefold()
            if query:
                where += " AND instr(fold(raw || ' ' || user || ' ' || host || ' ' || file),?)>0"
                params.append(query)
            matched = db.execute(f"SELECT count(*) FROM entries WHERE {where}", params).fetchone()[0]
            issues = [self.item(row) for row in db.execute(
                f"SELECT {self.columns} FROM entries WHERE {where} ORDER BY rowid LIMIT ? OFFSET ?", [*params,limit,offset])]
            return dict(self.summary, matched=matched, offset=offset, page_size=limit, issues=issues,
                        omitted=max(0,matched-len(issues)))
