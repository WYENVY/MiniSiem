from datetime import datetime

from siem import db
from siem.detector import Alert
from siem.parser import Event

TS = datetime(2026, 11, 18, 10, 0, 0)


def make_db(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    return path


def test_insert_and_dedupe_events(tmp_path):
    path = make_db(tmp_path)
    events = [Event(TS, "failed_login", "root", "1.2.3.4", 22)]
    assert db.insert_events(events, path) == 1
    assert db.insert_events(events, path) == 0   # same event again is ignored


def test_alerts_roundtrip(tmp_path):
    path = make_db(tmp_path)
    alert = Alert(TS, "brute_force", "high", "1.2.3.4", "5 failed logins")
    db.insert_alerts([alert], path)
    stored = db.get_alerts(path)
    assert len(stored) == 1
    assert stored[0]["ip"] == "1.2.3.4"


def test_top_attackers_orders_by_count(tmp_path):
    path = make_db(tmp_path)
    events = [
        Event(TS.replace(second=s), "failed_login", "root", "9.9.9.9", 22)
        for s in range(3)
    ] + [Event(TS, "failed_login", "root", "8.8.8.8", 22)]
    db.insert_events(events, path)
    top = db.top_attackers(path)
    assert top[0] == {"ip": "9.9.9.9", "failed_attempts": 3}