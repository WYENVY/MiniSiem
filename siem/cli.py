import sys

from siem.detector import load_rules, run_detection
from siem.parser import parse_file


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/auth.log"
    alerts = run_detection(parse_file(path), load_rules())
    if not alerts:
        print("No alerts.")
    for a in alerts:
        print(f"[{a.severity.upper()}] {a.timestamp} {a.rule}: {a.description}")


if __name__ == "__main__":
    main()