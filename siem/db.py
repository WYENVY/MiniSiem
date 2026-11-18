import sqlite3
from contextlib import contextmanager
from typing import Iterable, List

from siem.detector import Alert
from siem.parser import Event

DEFAULT_DB = "siem.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    UNIQUE (timestamp, event_type, user, ip, port)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE (timestamp, rule, ip)
);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
"""


@contextmanager
def connect(db_path: str = DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: str = DEFAULT_DB) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def insert_events(events: Iterable[Event], db_path: str = DEFAULT_DB) -> int:
    rows = [(e.timestamp.isoformat(), e.event_type, e.user, e.ip, e.port) for e in events]
    with connect(db_path) as conn:
        cur = conn.executemany(
            "INSERT OR IGNORE INTO events (timestamp, event_type, user, ip, port) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        return cur.rowcount


def insert_alerts(alerts: Iterable[Alert], db_path: str = DEFAULT_DB) -> int:
    rows = [(a.timestamp.isoformat(), a.rule, a.severity, a.ip, a.description) for a in alerts]
    with connect(db_path) as conn:
        cur = conn.executemany(
            "INSERT OR IGNORE INTO alerts (timestamp, rule, severity, ip, description) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        return cur.rowcount


def get_alerts(db_path: str = DEFAULT_DB, limit: int = 100) -> List[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def top_attackers(db_path: str = DEFAULT_DB, limit: int = 10) -> List[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT ip, COUNT(*) AS failed_attempts FROM events "
            "WHERE event_type = 'failed_login' "
            "GROUP BY ip ORDER BY failed_attempts DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def failures_per_hour(db_path: str = DEFAULT_DB) -> List[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS failures "
            "FROM events WHERE event_type = 'failed_login' "
            "GROUP BY hour ORDER BY hour"
        ).fetchall()
    return [dict(r) for r in rows]

def summary(db_path: str = DEFAULT_DB) -> dict:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM events) AS total_events, "
            "(SELECT COUNT(*) FROM events WHERE event_type = 'failed_login') AS failed_logins, "
            "(SELECT COUNT(DISTINCT ip) FROM events WHERE event_type = 'failed_login') AS unique_ips, "
            "(SELECT COUNT(*) FROM alerts) AS alerts"
        ).fetchone()
    return dict(row)