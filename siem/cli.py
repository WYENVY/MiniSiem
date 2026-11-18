import sys

from siem import db
from siem.detector import load_rules, run_detection
from siem.parser import parse_file


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/auth.log"
    events = list(parse_file(path))
    alerts = run_detection(events, load_rules())

    db.init_db()
    new_events = db.insert_events(events)
    new_alerts = db.insert_alerts(alerts)

    print(f"Parsed {len(events)} events ({new_events} new), {len(alerts)} alerts ({new_alerts} new).")
    for a in alerts:
        print(f"[{a.severity.upper()}] {a.timestamp} {a.rule}: {a.description}")


if __name__ == "__main__":
    main()