import datetime
from src.parser import parse_log_line

def test_parse_valid_line():
    line = "2025-08-25 14:00:00, IP: 192.168.0.1, user: alice, action: login, result: success"
    parsed = parse_log_line(line)
    assert parsed is not None
    ts, ip, user, action, result = parsed
    assert isinstance(ts, datetime.datetime)
    assert ip == "192.168.0.1"
    assert user == "alice"
    assert action == "login"
    assert result == "success"

def test_parse_invalid_line():
    line = "INVALID LOG FORMAT"
    parsed = parse_log_line(line)
    assert parsed is None