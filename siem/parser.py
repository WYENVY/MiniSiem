import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Matches: "Nov 18 10:02:11 host sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"
FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)

@dataclass
class Event:
    timestamp: datetime
    event_type: str   # "failed_login" or "successful_login"
    user: str
    ip: str
    port: int

def _parse_ts(raw: str, year: Optional[int] = None) -> datetime:
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")

def parse_line(line: str) -> Optional[Event]:
    for pattern, etype in ((FAILED, "failed_login"), (ACCEPTED, "successful_login")):
        m = pattern.match(line)
        if m:
            return Event(_parse_ts(m["ts"]), etype, m["user"], m["ip"], int(m["port"]))
    return None

def parse_file(path: str):
    with open(path, errors="replace") as f:
        for line in f:
            event = parse_line(line.strip())
            if event:
                yield event