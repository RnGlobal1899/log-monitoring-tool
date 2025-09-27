import yaml
import datetime
import collections
import os
import re
from log_utils import setup_logger, mask_user
from ip_utils import get_country_by_ip
from parser import parse_log_line
from database import init_db, add_log_entry, add_blocked_ip, add_alert, get_all_blocked_ips, is_ip_alerted
    
def extract_user_from_error_line(line: str) -> str:
    match = re.search(r"user:\s*([^,]+)", line)
    if match:
        return mask_user(match.group(1).strip())
    return "unknown"

def normalize_result(result: str) -> str:
    if result in ["fail", "Failed", "403"]:
        return "fail"
    elif result in ["Accepted", "200"]:
        return "success"
    else:
        return "unkown"
    
def normalize_action(action: str) -> str:
    if action.lower() in ["login", "ssh_login", "post"]:
        return "login"
    return action

def process_line(line, logger, config, state):
    data = parse_log_line(line)
    if not data:
        masked_user = extract_user_from_error_line(line)
        masked_line = re.sub(r"user:\s*([^, ]+)", f"user: {masked_user}", line)
        logger.error(f"Invalid log line: {masked_line}")
        return
    
    timestamp, ip, user, action, result = data

    # Normalize
    action = normalize_action(action)
    result = normalize_result(result)

    country_norm = get_country_by_ip(ip, logger)

    add_log_entry(timestamp, ip, user, action, result, country_norm, line)

    if action != "login":
        return

    # Block IPs from not allowed countries
    if country_norm not in state["allowed_countries"]:
        if ip not in state["blocked_ips"]:
            logger.warning(f"IP {ip} from ({country_norm}), user: {mask_user(user)} blocked (country restriction).")
            state["blocked_ips"].add(ip)
            add_blocked_ip(ip, user, country_norm, timestamp)
        else:
            if ip not in state["processed_blocks"]:
                logger.info(f"IP {ip} from ({country_norm}), user: {mask_user(user)} already blocked.")
        state["processed_blocks"].add(ip)
        return

    if ip in state["blocked_ips"]:
        return

    # Count failed logins
    if result == "fail":
        state["fail_logins"][ip].append(timestamp)
        window_start = timestamp - datetime.timedelta(seconds=state["login_fail_window"])
        state["fail_logins"][ip] = [t for t in state["fail_logins"][ip] if t >= window_start]

        if len(state["fail_logins"][ip]) >= state["login_fail_limit"]:
            if ip not in state["alert_ips"]:
                if not is_ip_alerted(ip):
                    add_alert(user, ip, country_norm, datetime.datetime.now())
                    logger.warning(f"IP {ip} ({country_norm}), user: {mask_user(user)} exceeded login attempts. Added to alert list.")
                    state["alert_ips"].add(ip)
                else:
                    if ip not in state["processed_alerts"]:
                        logger.info(f"IP {ip} ({country_norm}), user: {mask_user(user)} exceeded login fail limit. Already in alert list.")
                    state["processed_alerts"].add(ip)

def init_state(config):
    return {
        "fail_logins": collections.defaultdict(list),
        "blocked_ips": get_all_blocked_ips(),
        "alert_ips": set(),
        "processed_blocks": set(),
        "processed_alerts": set(),
        "allowed_countries": set(config["allowed_countries"]),
        "login_fail_limit": config["login_fail_limit"],
        "login_fail_window": config["login_fail_window"],
    }

def main():
    # Load database
    init_db()

    # Load config
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    logger = setup_logger(config["monitor_log_dir"])
    state = init_state(config)

    # Choose between watchdog or journalctl
    from realtime import start_watchdog, stream_journal

    mode = config.get("mode", "watchdog")  # "watchdog" or "journalctl"

    if mode == "watchdog":
        start_watchdog(config["log_dir"], logger, lambda line: process_line(line, logger, config, state))
    elif mode == "journalctl":
        services = config.get("services", ["sshd", "apache2", "nginx"])
        stream_journal(services, lambda line: process_line(line, logger, config, state), logger)
    else:
        logger.error(f"Unknown mode: {mode}")     


if __name__ == "__main__":
    main()