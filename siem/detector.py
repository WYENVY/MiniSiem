from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

import yaml

from siem.parser import Event


@dataclass
class Alert:
    timestamp: datetime
    rule: str
    severity: str
    ip: str
    description: str


def load_rules(path: str = "rules.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


class BruteForceDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60, severity: str = "high"):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.severity = severity
        self.attempts = defaultdict(deque)   # ip -> timestamps of recent failures
        self.last_alert = {}                 # ip -> when we last alerted

    def process(self, event: Event) -> Optional[Alert]:
        if event.event_type != "failed_login":
            return None

        q = self.attempts[event.ip]
        q.append(event.timestamp)

        # Drop attempts that fell out of the window
        cutoff = event.timestamp - self.window
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self.threshold:
            last = self.last_alert.get(event.ip)
            if last is None or event.timestamp - last >= self.window:
                self.last_alert[event.ip] = event.timestamp
                return Alert(
                    timestamp=event.timestamp,
                    rule="brute_force",
                    severity=self.severity,
                    ip=event.ip,
                    description=f"{len(q)} failed logins from {event.ip} "
                                f"within {int(self.window.total_seconds())}s",
                )
        return None


def run_detection(events: Iterable[Event], rules: dict) -> List[Alert]:
    cfg = rules["brute_force"]
    detector = BruteForceDetector(
        cfg["threshold"], cfg["window_seconds"], cfg.get("severity", "high")
    )
    alerts = []
    for event in events:
        alert = detector.process(event)
        if alert:
            alerts.append(alert)
    return alerts