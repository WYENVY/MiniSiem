from datetime import datetime, timedelta

from siem.detector import BruteForceDetector
from siem.parser import Event

START = datetime(2026, 11, 18, 10, 0, 0)


def fail(ip, seconds):
    return Event(START + timedelta(seconds=seconds), "failed_login", "root", ip, 22)


def test_alerts_on_rapid_failures():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    results = [d.process(fail("1.2.3.4", s)) for s in range(5)]
    assert results[-1] is not None
    assert results[-1].ip == "1.2.3.4"


def test_no_alert_when_attempts_are_spread_out():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    results = [d.process(fail("1.2.3.4", s * 120)) for s in range(5)]
    assert all(r is None for r in results)


def test_only_one_alert_during_cooldown():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = [a for a in (d.process(fail("1.2.3.4", s)) for s in range(20)) if a]
    assert len(alerts) == 1


def test_ips_are_tracked_separately():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    results = []
    for s in range(4):
        results.append(d.process(fail("1.1.1.1", s)))
        results.append(d.process(fail("2.2.2.2", s)))
    assert all(r is None for r in results)