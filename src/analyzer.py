import yaml
import datetime
import collections
import re
from log_utils import setup_logger, mask_user
from ip_utils import get_country_by_ip
from parser import parse_log_line
from database import init_db, add_login_attempt, add_blocked_ip, add_alert, get_all_blocked_ips, is_ip_alerted, get_or_create_user_profile, update_user_profile_country, update_user_login_counters
    
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

def process_line(line, logger, state):
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

    # Check if there is a user to create the profile
    if not user or user == "-":
        user = "unknown user"

    country_norm = get_country_by_ip(ip, logger)

    add_login_attempt(timestamp, ip, user, result, country_norm, line)

    if action != "login":
        return
    
    if result == "success":
        profile = get_or_create_user_profile(user)
        has_history = profile['successful_logins'] > 0 
        known_countries = profile['known_countries'].split(",") if profile['known_countries'] else []

        if has_history and country_norm not in known_countries:
            logger.warning(f"SUSPICIOUS LOGIN: User {mask_user(user)} logged in from a new country: {country_norm} (previous: {known_countries}) (IP: {ip})")

            update_user_profile_country(user, country_norm)
            update_user_login_counters(user, success=True)

    elif result == "fail":
        update_user_login_counters(user, success=False)

        # Spraying and distributed attack logic
        now = datetime.datetime.now()
        window = datetime.timedelta(seconds=state.get("attack_detection_window", 300))

        # Detection of password spraying
        state["ip_to_user"][ip].append((now, user))
        state["ip_to_user"][ip] = [t for t in state["ip_to_user"][ip] if now - t[0] < window]
        unique_users = len(set(t[1] for t in state["ip_to_user"][ip])) 

        ip_limit = state.get("ip_to_user_limit", 10)
        if unique_users > ip_limit:
            reason = f"Password spraying: IP tried to access {unique_users} accounts"
            logger.warning(f"PASSWORD SPRAYING DETECTED: IP {ip} ({country_norm}) tried to access {unique_users} accounts.")
            add_alert(ip, None, country_norm, now, reason)
            state["ip_to_user"][ip] = []  # Reset after alert

        # Detection of distributed attack
        state["user_to_ips"][user].append((now, ip))
        state["user_to_ips"][user] = [t for t in state["user_to_ips"][user] if now - t[0] < window]
        unique_ips = len(set(t[1] for t in state["user_to_ips"][user]))

        user_limit = state.get("user_to_ip_limit", 20)
        if unique_ips >= user_limit:
            reason = f"Distributed attack: User account targeted from {unique_ips} IPs"
            logger.warning(f"DISTRIBUTED ATTACK DETECTED: User {mask_user(user)} targeted from {unique_ips} IPs.")
            add_alert(None, user, None, now, reason)
            state["user_to_ips"][user] = []  # Reset after alert

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
    state["fail_logins"][ip].append(timestamp)
    window_start = timestamp - datetime.timedelta(seconds=state["login_fail_window"])
    state["fail_logins"][ip] = [t for t in state["fail_logins"][ip] if t >= window_start]

    if len(state["fail_logins"][ip]) >= state["login_fail_limit"]:
        if ip not in state["alert_ips"]:
            if not is_ip_alerted(ip):
                reason = f"Brute-force attack detected: {len(state['fail_logins'][ip])} failed attempts"
                add_alert(ip, user, country_norm, datetime.datetime.now(), reason)
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
        "ip_to_user": collections.defaultdict(set),
        "user_to_ips": collections.defaultdict(set),
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
        start_watchdog(config["log_dir"], logger, lambda line: process_line(line, logger, state))
    elif mode == "journalctl":
        services = config.get("services", ["sshd", "apache2", "nginx"])
        stream_journal(services, lambda line: process_line(line, logger, state), logger)
    else:
        logger.error(f"Unknown mode: {mode}")     


if __name__ == "__main__":
    main()