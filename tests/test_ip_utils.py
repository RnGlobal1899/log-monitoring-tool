import pytest
from src.ip_utils import get_country_by_ip, normalize_country

class DummyLogger:
    def error(self, msg): print("[ERROR]", msg)
    def warning(self, msg): print("[WARN]", msg)
    def info(self, msg): print("[INFO]", msg)

def test_normalize_country():
    assert normalize_country("Brasil") == "BRASIL"
    assert normalize_country("México") == "MEXICO"
    assert normalize_country("United States") == "UNITED STATES"

def test_get_country_by_ip_mock(monkeypatch):
    # cria um mock de requests.get
    class DummyResponse:
        def json(self): return {"country": "US"}
        def raise_for_status(self): pass

    def fake_get(*args, **kwargs):
        return DummyResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    logger = DummyLogger()
    country = get_country_by_ip("1.1.1.1", logger)
    assert country == "UNITED STATES"