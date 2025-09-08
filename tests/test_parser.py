import datetime
from src.parser import parse_log_line


def test_default_log():
    line = "2025-09-07 12:34:56, IP: 192.168.1.1, user: admin, action: login, result: success"
    parsed = parse_log_line(line)
    assert parsed is not None
    ts, ip, user, action, result = parsed
    assert isinstance(ts, datetime.datetime)
    assert ip == "192.168.1.1"
    assert user == "admin"
    assert action == "login"
    assert result == "success"


def test_apache_log():
    line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache.gif HTTP/1.0" 200 2326'
    parsed = parse_log_line(line)
    assert parsed is not None
    ts, ip, user, action, result = parsed
    assert isinstance(ts, datetime.datetime)
    assert ip == "127.0.0.1"
    assert user == "frank"
    assert action == "GET"
    assert result == "200"


def test_nginx_log():
    line = '192.168.0.1 - - [12/Mar/2021:19:14:36 +0000] "POST /login HTTP/1.1" 403 564 "-" "Mozilla/5.0"'
    parsed = parse_log_line(line)
    assert parsed is not None
    ts, ip, user, action, result = parsed
    assert isinstance(ts, datetime.datetime)
    assert ip == "192.168.0.1"
    assert user == "-"
    assert action == "POST"
    assert result == "403"


def test_ssh_log():
    line = "Jan 10 10:32:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
    parsed = parse_log_line(line)
    assert parsed is not None
    ts, ip, user, action, result = parsed
    assert isinstance(ts, datetime.datetime)
    assert ip == "192.168.1.100"
    assert user == "root"
    assert action == "ssh_login"
    assert result == "Failed"