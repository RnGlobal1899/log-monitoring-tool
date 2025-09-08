from src.ip_utils import normalize_country

def test_normalize_country_basic():
    assert normalize_country("Brasil") == "BRASIL"
    assert normalize_country("España") == "ESPANA"
    assert normalize_country("Česká republika") == "CESKA REPUBLIKA"


def test_normalize_country_with_spaces():
    assert normalize_country("  France  ") == "FRANCE"
    assert normalize_country(" United States ") == "UNITED STATES"
