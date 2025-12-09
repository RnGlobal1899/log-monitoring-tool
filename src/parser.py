import os
import re
import datetime
from typing import Optional, Tuple, Dict

# Define a type for the log entry
LOG_FORMATS: Dict[str, Dict] = {
    "default": {
        "regex": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), IP: ([\d\.]+), user: ([^,]+), action: (\w+), result: (\w+)",
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"),
            m.group(2),   #ip
            m.group(3),   #user
            m.group(4),   #action
            m.group(5)    #result
        ),
    },
    "apache": {
        "regex": r'((?:\d{1,3}\.){3}\d{1,3}) - (.*?) \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+\-]\d{4}\] "(\S+) (.*?) (\S+)" (\d{3}) (\d+)',
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(3), "%d/%b/%Y:%H:%M:%S"),
            m.group(1),  # ip
            m.group(2),  # user
            m.group(4),  # action
            m.group(7),  # status
        ),
    },
    "ssh": {
        "regex": r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) .*sshd.* (Failed|Accepted) password for (invalid user )?(.+?)(?=\s+from) from ((?:\d{1,3}\.){3}\d{1,3})',
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(1), "%b %d %H:%M:%S").replace(year=datetime.datetime.now().year),
            m.group(5),  # ip
            m.group(4),  # user 
            "ssh_login", # action
            m.group(2),  # result
        ),
    },
}

def get_log_files(log_dir):
    return (os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith(".log") or f.endswith(".csv"))

def read_logs(files):
    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            for line in f:
                yield line.strip()

def parse_windows_csv(line: str) -> Optional[Tuple]:
    try:
        parts = line.strip().split(',')
        if len(parts) < 5: return None
        if parts[0] == "Timestamp": return None # Skip header

        timestamp = datetime.datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
        ip = parts[1]
        user = parts[2]
        action = parts[3]
        result = parts[4].lower()
        if result == "4624": result = "success"
        if result == "4625": result = "failure"

        return (timestamp, ip, user, action, result)
    except Exception:
        return None

def parse_log_line(line: str) -> Optional[Tuple]:
    if not line or not line.strip():
        return None
    
    if "n" in line:
        csv_data = parse_windows_csv(line)
        if csv_data:
            return csv_data
        
    for fmt_name, fmt in LOG_FORMATS.items():
        match = re.search(fmt["regex"], line)
        if match:
            try:
                return fmt["parser"](match)
            except Exception as e:
                print(f"[Error parsing line as {fmt_name}] {line} => {e}") # DEBUG LINE
                return None
    print(f"[ignored] {line}")   # DEBUG LINE
    return None