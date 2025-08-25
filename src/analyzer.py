import yaml
import datetime
import collections
import os
from log_utils import setup_logger
from ip_utils import get_country_by_ip
from parser import get_log_files, read_logs, parse_log_line

def load_blocked_ips(filename="blocked_ips.txt"):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as f:
        return set(line.strip().split(" - ")[0] for line in f if line.strip())

def save_blocked_ips(ip, country, filename="blocked_ips.txt"):
    already_saved = set()
    if os.path.exists(filename):
        with open(filename, "r") as f:
            already_saved = set(line.strip().split(" - ")[0] for line in f if line.strip())
    if ip not in already_saved:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(filename, "a") as f:
            f.write(f"{ip} - {country} - {timestamp}\n")

def main():
    # Load config
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    log_dir = config["log_dir"]
    monitor_log_dir = config["monitor_log_dir"]
    allowed_countries = set(config["allowed_countries"])
    login_fail_limit = config["login_fail_limit"]
    login_fail_window = config["login_fail_window"]

    logger = setup_logger(monitor_log_dir)

    log_files = get_log_files(log_dir)
    fail_logins = collections.defaultdict(list)
    blocked_ips = load_blocked_ips()
    alert_ips = set()
    processed_blocks = set()
    processed_alerts = set()

    for line in read_logs(log_files):
        data = parse_log_line(line)
        if not data:
            logger.error(f"Invalid log line: {line}")
            continue

        timestamp, ip, user, action, result = data
        if action != "login":
            continue

        country_norm = get_country_by_ip(ip, logger)

        # Block IPs from not allowed countries
        if country_norm not in allowed_countries:
            if ip not in blocked_ips:
                logger.warning(f"IP {ip} from {country_norm} blocked (country restriction).")
                blocked_ips.add(ip)
                save_blocked_ips(ip, country_norm)
            else:
                if ip not in processed_blocks:
                    logger.info(f"IP {ip} from {country_norm} already blocked.")
            processed_blocks.add(ip)
            continue

        if ip in blocked_ips:
            continue

        # Count failed logins
        if result == "fail":
            fail_logins[ip].append(timestamp)
            window_start = timestamp - datetime.timedelta(seconds=login_fail_window)
            fail_logins[ip] = [t for t in fail_logins[ip] if t >= window_start]

            if len(fail_logins[ip]) >= login_fail_limit:
                if ip not in alert_ips:
                    already_alerted = set()
                    if os.path.exists("alert_ips.txt"):
                        with open("alert_ips.txt", "r") as alert_file:
                            already_alerted = set(line.strip().split(" - ")[0] for line in alert_file if line.strip())

                    if ip not in already_alerted:
                        alert_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open("alert_ips.txt", "a") as alert_file:
                            alert_file.write(f"{ip} - {country_norm} - {alert_time}\n")
                        logger.warning(f"IP {ip} ({country_norm}) exceeded login attempts. Added to alert list.")
                        alert_ips.add(ip)
                    else:
                        if ip not in processed_alerts:
                            logger.info(f"IP {ip} ({country_norm}) exceeded login fail limit. Already in alert list.")
                        processed_alerts.add(ip)

    if not alert_ips and not blocked_ips:
        logger.info("Everything is fine. No alerts or blocked IPs.")

if __name__ == "__main__":
    main()