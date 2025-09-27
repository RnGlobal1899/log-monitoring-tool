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

    # Table to store processed logs
    cursor.execute("""
    CREATE TABLE logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip TEXT NOT NULL,
        user TEXT,
        action TEXT,
        result TEXT,
        country TEXT,
        raw_log TEXT 
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
        ip TEXT NOT NULL,
        user TEXT,
        country TEXT,
        alert_time TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()
    print("Database created successfully.")

# Add a new log entry to the logs table
def add_log_entry(timestamp, ip, user, action, result, country, raw_log):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO logs (timestamp, ip, user, action, result, country, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp.strftime("%Y-%m-%d %H:%M:%S"), ip, user, action, result, country, raw_log)
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
def add_alert(ip, user, country, timestamp):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO alerts (ip, user, country, alert_time) VALUES (?, ?, ?, ?)",
        (ip, user, country, timestamp.strftime("%Y-%m-%d %H:%M:%S"))
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
