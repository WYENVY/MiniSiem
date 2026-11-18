from datetime import datetime

from fastapi.testclient import TestClient

from siem import db
from siem.api import create_app
from siem.detector import Alert
from siem.parser import Event

TS = datetime(2026, 11, 18, 10, 0, 0)


def make_client(tmp_path):
    path = str(tmp_path / "api.db")
    app = create_app(path)
    db.insert_events([Event(TS, "failed_login", "root", "1.2.3.4", 22)], path)
    db.insert_alerts([Alert(TS, "brute_force", "high", "1.2.3.4", "test")], path)
    return TestClient(app)


def test_summary(tmp_path):
    data = make_client(tmp_path).get("/api/summary").json()
    assert data["failed_logins"] == 1
    assert data["alerts"] == 1


def test_alerts_and_top_attackers(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/alerts").json()[0]["ip"] == "1.2.3.4"
    assert client.get("/api/top-attackers").json()[0]["failed_attempts"] == 1


def test_limit_is_validated(tmp_path):
    assert make_client(tmp_path).get("/api/alerts?limit=999999").status_code == 422


def test_dashboard_served(tmp_path):
    r = make_client(tmp_path).get("/")
    assert r.status_code == 200
    assert "Mini SIEM" in r.text