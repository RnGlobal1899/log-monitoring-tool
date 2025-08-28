import os
import re
import datetime

def get_log_files(log_dir):
    return (os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith(".log"))

def read_logs(files):
    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            for line in f:
                yield line.strip()

def parse_log_line(line):
    regex = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), IP: ([\d\.]+), user: ([^,]+), action: (\w+), result: (\w+)"
    match = re.match(regex, line)
    if match:
        try:
            timestamp = datetime.datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            ip = match.group(2)
            user = match.group(3)
            action = match.group(4)
            result = match.group(5)
            return timestamp, ip, user, action, result
        except Exception as e:
            return None
    return None