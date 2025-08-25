import requests
import pycountry
import unicodedata

ip_cache = {}

def normalize_country(name: str) -> str:
    nfkd_form = unicodedata.normalize('NFKD', name)
    only_ascii = ''.join([c for c in nfkd_form if not unicodedata.combining(c)])
    return only_ascii.upper().strip()

def get_country_by_ip(ip: str, logger) -> str:
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        response.raise_for_status()
        data = response.json()

        if "country" in data:
            country_code = data["country"]
            country = pycountry.countries.get(alpha_2=country_code)
            country_norm = normalize_country(country.name) if country else normalize_country(country_code)
        else:
            country_norm = "UNKNOWN"
    except Exception as e:
        logger.error(f"Error fetching country for IP {ip}: {e}")
        country_norm = "UNKNOWN"

    ip_cache[ip] = country_norm
    return country_norm