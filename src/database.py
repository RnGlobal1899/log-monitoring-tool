import sqlite3
import os

DATA_DIR = "data"
DB_FILE = os.path.join(DATA_DIR, "log_analyzer.db")

# Create and return a connection with the database
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database and create necessary tables if they don't exist
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(DB_FILE):
        return
    
    print("Making new database...")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Main table for all the login events
    cursor.execute("""
    CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip TEXT NOT NULL,
        user TEXT NOT NULL,
        result TEXT NOT NULL,
        country TEXT,
        raw_log TEXT 
    )
    """)

    # New table to create a profile of each user
    cursor.execute("""
    CREATE TABLE user_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL UNIQUE,
        known_countries TEXT NOT NULL, 
        successful_logins INTEGER DEFAULT 0,
        failed_logins INTEGER DEFAULT 0
    )
    """)

    # Table to store blocked IPs
    cursor.execute("""
    CREATE TABLE blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        user TEXT,
        country TEXT,
        block_time TEXT NOT NULL
    )
    """)

    # Table to store alerts
    cursor.execute("""
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        user TEXT,
        country TEXT,
        alert_time TEXT NOT NULL,
        reason TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()
    print("Database created successfully.")

# Add a new log attempt to the logs table
def add_login_attempt(timestamp, ip, user, result, country, raw_log):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO login_attempts (timestamp, ip, user, result, country, raw_log) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp.strftime("%Y-%m-%d %H:%M:%S"), ip, user, result, country, raw_log)
    )
    conn.commit()
    conn.close()

# Add a new blocked IP entry to the blocked_ips table
def add_blocked_ip(ip, user, country, timestamp):
    conn = get_db_connection()
    conn.execute(
        "INSERT OR IGNORE INTO blocked_ips (ip, user, country, block_time) VALUES (?, ?, ?, ?)",
        (ip, user, country, timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

# Add a new alert entry to the alerts table
def add_alert(ip, user, country, timestamp, reason):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO alerts (ip, user, country, alert_time, reason) VALUES (?, ?, ?, ?, ?)",
        (ip, user, country, timestamp.strftime("%Y-%m-%d %H:%M:%S"), reason)
    )
    conn.commit()
    conn.close()

# Return a set with all blocked IPs
def get_all_blocked_ips():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips")
    ips = {row["ip"] for row in cursor.fetchall()}
    conn.close()
    return ips

# Check if an IP is already in the alert list
def is_ip_alerted(ip:str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM alerts WHERE ip =?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Get or create user profile from logs table
def get_or_create_user_profile(user):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_profiles WHERE user = ?", (user,))
    profile = cursor.fetchone()
    if not profile:
        cursor.execute("INSERT INTO user_profiles (user, known_countries) VALUES (?, ?)", (user, ""))
        conn.commit()
        cursor.execute("SELECT * FROM user_profiles WHERE user = ?", (user,))
        profile = cursor.fetchone()
    conn.close()
    return dict(profile)

# Update user profile country in logs table
def update_user_profile_country(user, country):
    profile = get_or_create_user_profile(user)
    known_countries = set(profile["known_countries"].split(","))   
    if country not in known_countries:
        known_countries.add(country)
        known_countries.discard('')
        new_countries_str = ",".join(sorted(list(known_countries)))

        conn = get_db_connection()
        conn.execute("UPDATE user_profiles SET known_countries = ? WHERE user = ?", (new_countries_str, user))
        conn.commit()
        conn.close()

# Update user profile login counts in logs table
def update_user_login_counters(user, success= False):
    conn = get_db_connection()
    if success:
        conn.execute("UPDATE user_profiles SET successful_logins = successful_logins + 1 WHERE user = ?", (user,))
    else:
        conn.execute("UPDATE user_profiles SET failed_logins = failed_logins + 1 WHERE user = ?", (user,))
    conn.commit()
    conn.close()
    
