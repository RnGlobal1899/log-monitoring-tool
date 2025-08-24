import datetime
import collections
import re
import os
import requests
import pycountry
import logging
import unicodedata

# Directory where the log files are stored
LOG_DIR = r'C:\Users\bruno\Desktop\test project\test'

# Directory for monitoring logs
MONITOR_LOG_DIR = r'C:\Users\bruno\Desktop\test project\logs'

# making folder if not exists
os.makedirs(MONITOR_LOG_DIR, exist_ok=True)

# Main logger
logger = logging.getLogger('monitor')
logger.setLevel(logging.DEBUG)

#System logger
system_handler = logging.FileHandler(os.path.join(MONITOR_LOG_DIR, 'system.log'))
system_handler.setLevel(logging.DEBUG)
system_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
system_handler.setFormatter(system_formatter)

#alerts logger
alert_handler = logging.FileHandler(os.path.join(MONITOR_LOG_DIR, 'alerts.log'))
alert_handler.setLevel(logging.WARNING)
alert_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
alert_handler.setFormatter(alert_formatter)

#erros logger
error_handler = logging.FileHandler(os.path.join(MONITOR_LOG_DIR, 'errors.log'))
error_handler.setLevel(logging.ERROR)
error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
error_handler.setFormatter(error_formatter)

# Add handlers 
logger.addHandler(system_handler)
logger.addHandler(alert_handler)
logger.addHandler(error_handler)

# Normalize country names
def normalize_country(name):
    nfkd_form = unicodedata.normalize('NFKD', name)
    only_ascii = ''.join([c for c in nfkd_form if not unicodedata.combining(c)])
    return only_ascii.upper().strip()

# Global variables    
ALLOWED_COUNTRIES = {'BRAZIL', 'UNITED STATES', 'USA', 'EUA', 'RUSSIAN FEDERATION', 'CHINA', 'GERMANY', 'INDIA'}
LOGIN_FAIL_LIMIT = 5
LOGIN_FAIL_WINDOW = 60 #segundos
ip_cache = {}

# Lookup for the country by ip
def get_country_by_ip(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=3)
        data = response.json()
        if 'country' in data:
            country_code = data['country']
            country = pycountry.countries.get(alpha_2=country_code)
            country_norm = normalize_country(country.name) if country else normalize_country(country_code)
        else:
            country_norm = 'UNKNOWN'
    except Exception as e:
        logger.error(f"Error searching contry for IP {ip}: {e}")
        country_norm = 'UNKNOWN'
    ip_cache[ip] = country_norm
    return country_norm

# Get all the .log files in the directory
def get_log_files(log_dir):
    return (os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith('.log'))

# Read the log files and yield each line      
def read_logs(files):
    "ler os arquivos e retornar as linhas"
    for file in files:
        with open(file, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.strip()

# Parse a log line and return the components
def parse_log_line(line):
    regex = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), IP: ([\d\.]+), user: (\w+), action: (\w+), result: (\w+)'
    match = re.match(regex, line)
    if match:
        timestamp = datetime.datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
        ip = match.group(2)
        user = match.group(3)
        action = match.group(4)
        result = match.group(5)
        return timestamp, ip, user, action, result
    return None

# Load the blocked IPs 
def load_blocked_ips(filename="blocked_ips.txt"):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip().split(' - ')[0] for line in f if line.strip())

# Save the bloecked IPs 
def save_blocked_ips(ip, country, filename="blocked_ips.txt"):
    already_saved = set()
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            already_saved = set(line.strip().split(' - ')[0] for line in f if line.strip())
    if ip not in already_saved:      
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(filename, "a") as f:
                    f.write(f"{ip} - {country} - {timestamp}\n")

# Log analysis
def main():
    log_files = get_log_files(LOG_DIR)
    fail_logins = collections.defaultdict(list)
    blocked_ips = load_blocked_ips()
    alert_ips = set()

    for line in read_logs(log_files):
        data = parse_log_line(line)
        if not data:
            continue
        timestamp, ip, user, action, result = data
        if action != 'login':
            continue

        country_norm = get_country_by_ip(ip)
        
        # block IPs of not allowed countries
        if country_norm not in ALLOWED_COUNTRIES:
            if ip not in blocked_ips:
                logger.warning(f"IP {ip} from {country_norm} was blocked due to country restriction.")
                blocked_ips.add(ip)
                save_blocked_ips(ip, country_norm)
            else:
                logger.info(f"IP {ip} from ({country_norm}) is already blocked.")
            continue

        if ip in blocked_ips:
            continue

        # Count the number of failed logins
        if result == 'fail':
            fail_logins[ip].append(timestamp)
            window_start = timestamp - datetime.timedelta(seconds=LOGIN_FAIL_WINDOW)
            fail_logins[ip] = [t for t in fail_logins[ip] if t >= window_start]

            if len(fail_logins[ip]) >= LOGIN_FAIL_LIMIT:
                if ip not in alert_ips:
                    already_alerted = set()
                    if os.path.exists("alert_ips.txt"):
                        with open("alert_ips.txt", "r") as alert_file:
                            already_alerted = set(line.strip().split(' - ')[0] for line in alert_file if line.strip())

                    if ip not in already_alerted:
                        alert_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open("alert_ips.txt", "a") as alert_file:
                            alert_file.write(f"{ip} - {country_norm} - {alert_time}\n")
                        logger.warning(f"IP {ip} ({country_norm}) has failed login attempts exceeding limit. Adding to alert list.")
                        alert_ips.add(ip)
                    else:                        
                        logger.info(f"IP {ip} ({country_norm}) has failed login attempts exceeding limit. Already added to alert list.")

        # Fine behavior
        if not alert_ips and not blocked_ips:
            logger.info("Everthing is fine. No alerts or blocked IPs.")

if __name__ == "__main__":
    main()


