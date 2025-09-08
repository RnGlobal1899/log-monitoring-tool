import os
import re
import datetime
from typing import Optional, Tuple, Dict, Callable

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
        "regex": r'([\d\.]+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d{3}) (\d+)',
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(3).split()[0], "%d/%b/%Y:%H:%M:%S"),
            m.group(1),  # ip
            m.group(2),  # user
            m.group(4),  # action 
            m.group(7),  # result 
        ),
    },
    "nginx": {
        "regex": r'([\d\.]+) - (\S+) \[(.*?)\] "(\S+) (.*?) (\S+)" (\d{3}) (\d+)',
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(3).split()[0], "%d/%b/%Y:%H:%M:%S"),
            m.group(1),  # ip
            m.group(2),  # user (- if anonymous)
            m.group(4),  # action
            m.group(7),  # status
        ),
    },
    "ssh": {
        "regex": r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) .*sshd.* (Failed|Accepted) password for (invalid user )?(\w+) from ([\d\.]+)',
        "parser": lambda m: (
            datetime.datetime.strptime(m.group(1), "%b %d %H:%M:%S"),
            m.group(5),  # ip
            m.group(4),  # user
            "ssh_login", # generic action
            m.group(2),  # result 
        ),
    },
}

def get_log_files(log_dir):
    return (os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith(".log"))

def read_logs(files):
    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            for line in f:
                yield line.strip()

def parse_log_line(line: str) -> Optional[Tuple]:
    for fmt in LOG_FORMATS.values():
        match = re.match(fmt["regex"], line)
        if match:
            try:
                return fmt["parser"](match)
            except Exception:
                return None
    return None