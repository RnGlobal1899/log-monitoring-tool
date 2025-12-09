import os
import csv
import subprocess
import datetime
import xml.etree.ElementTree as ET
import random

# --- CONFIGURAÇÃO ---

# Lab mode save the files locally and spoof IPs for testing
# Prod mode fetches from remote share and uses real IPs
LAB_MODE = False 

if LAB_MODE:
    LOG_DIR = r"C:\LogsExportados"
    print("🧪 LAB MODE ON: Local Path + IP Spoofing.")
else:
    # Replace with your actual remote share path
    LOG_DIR = r"YOUR_REMOTE_SHARE_PATH_HERE"
    print("🚀 PROD MODE ON: SMB Network Path + Real IPs.")

LOG_FILE = os.path.join(LOG_DIR, "windows_events.csv")
LAST_RUN_FILE = os.path.join(os.environ["USERPROFILE"], "agent_last_run.txt")

# IPs for testing (Australia, Russia, China, Google DNS, Spain)
SPOOFED_IPS = ["223.255.255.255", "109.252.255.255", "36.125.146.54", "8.8.8.8", "5.83.64.88"]

def ensure_setup():
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
        except OSError as e:
            print(f"⚠️  Warning: Could not create directory {LOG_DIR}. Check permissions or network path. Error: {e}")

    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "IP", "User", "Action", "Result"])
        except IOError as e:
            print(f"❌ Error initializing CSV file: {e}")

def get_last_run_time():
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE, "r") as f:
            return f.read().strip()
    return None

def update_last_run_time():
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LAST_RUN_FILE, "w") as f:
        f.write(now)


def fetch_windows_events():
    # Native Windows query (wevtutil) to retrieve raw XML.
    # Filter Security log, Event ID 4624 or 4625, last 20 events (/c:20), reverse order (/rd:true)
    # Note: In production, adjust the query to filter by TimeCreated.
    cmd = [
        "wevtutil", "qe", "Security",
        "/q:*[System[(EventID=4624 or EventID=4625)]]",
        "/f:xml",
        "/c:20",
        "/rd:true"
    ]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")
        return output
    except subprocess.CalledProcessError:
        return ""
    except FileNotFoundError:
        print("❌ Error: 'wevtutil' command not found. Ensure you are running this on a Windows system.")
        return ""
    
def parse_and_save(xml_content):
    if not xml_content.strip():
        print("ℹ️  No event found.")
        return

# wevtutil returns multiple <Event> elements without a root, so it needs to be wrapped.
    wrapped_xml = f"<Root>{xml_content}</Root>"

    try:
        root = ET.fromstring(wrapped_xml)
    except ET.ParseError:
        print("❌ Failed to parse XML content.")
        return
    
    new_logs_count = 0

    try:
        with open(LOG_FILE, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event in root.findall("ns:Event", ns):
                try:
                    # Extract timestamp
                    time_created = event.find('ns:System/ns:TimeCreated', ns)
                    timestamp_raw = time_created.get('SystemTime') if time_created is not None else ""
                    # Format date to YYYY-MM-DD HH:MM:SS
                    dt = datetime.datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

                    # Extract Event ID
                    event_id_tag = event.find('ns:System/ns:EventID', ns)
                    event_id = event_id_tag.text if event_id_tag is not None else ""

                    # Extract Data fields
                    ip_address = "-"
                    target_user = "-"
                
                    event_data = event.find('ns:EventData', ns)
                    if event_data is not None:
                        for data in event_data.findall('ns:Data', ns):
                            name = data.get('Name')
                            if name == 'IpAddress':
                                ip_address = data.text
                            elif name == 'TargetUserName':
                                target_user = data.text

                    # Filter empty IPs (Local System)
                    if not LAB_MODE and (not ip_address or ip_address == "-"):
                        continue

                    # LAB MODE LOGIC (Spoofing)
                    if LAB_MODE:
                        ip_address = random.choice(SPOOFED_IPS)
                        target_user = f"{target_user}-TEST"

                    # Normalize Action/Result
                    action = "login"
                    result = "success" if event_id == "4624" else "fail"

                    # Write in CSV
                    writer.writerow([timestamp, ip_address, target_user, action, result])
                    new_logs_count += 1
                
                except Exception as e:
                    print(f"⚠️ Error processing an event: {e}")
                    continue
    except IOError as e:
        print(f"❌ Error writing to CSV file: {e}")
        return
    
    if new_logs_count > 0:
        print(f"✅ {new_logs_count} new logs saved in {LOG_FILE}")
    else:
        print("ℹ️  Events processed, but none relevant saved.")

if __name__ == "__main__":
    ensure_setup()
    print("🔍 Searching for security events (via Python)...")
    if LAB_MODE:
        print("🧪 LAB MODE ACTIVE: IPs are being masked.")
        
    xml_data = fetch_windows_events()
    parse_and_save(xml_data)
    update_last_run_time()