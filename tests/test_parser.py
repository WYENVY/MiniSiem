from siem.parser import parse_line

def test_failed_login():
    line = "Nov 18 10:02:11 web sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"
    e = parse_line(line)
    assert e.event_type == "failed_login"
    assert e.user == "admin"
    assert e.ip == "203.0.113.5"

def test_ignores_noise():
    assert parse_line("Nov 18 10:02:11 web cron[1]: job ran") is None