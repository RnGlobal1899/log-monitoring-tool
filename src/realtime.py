import time
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class LogHandler(FileSystemEventHandler):
    def __init__(self, logger, process_line):
        super().__init__()
        self.logger = logger
        self.process_line = process_line
        self.file_positions = {}

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(".log"):
            return
        try:
            with open(event.src_path, "r", encoding="utf-8") as f:
                last_position = self.file_positions.get(event.src_path, 0)
                f.seek(last_position)

                for line in f:
                    self.process_line(line.strip())

                self.file_positions[event.src_path] = f.tell()
        except Exception as e:
            self.logger.error(f"Error reading log file {event.src_path}: {e}")

def start_watchdog(log_dir, logger, process_line):
    event_handler = LogHandler(logger, process_line)
    observer = Observer()
    observer.schedule(event_handler, path=log_dir, recursive=False)
    observer.start()
    logger.info(f"Started watchdog on {log_dir}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def stream_journal_worker(service, process_line, logger):
    # Worker to stream journalctl in separed tread/process.
    cmd = ["journalctl", "-fu", service, "-n", "0"]
    logger.info(f"Starting journalctl for service: {service}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for line in iter(process.stdout.readline, ''):
            if line.strip():
                process_line(line.strip())
    except Exception as e:
        logger.error(f"Error streaming journalctl for {service}: {e}")

def stream_journal(service, process_line, logger):
    # Initiate threads for each service to stream journalctl logs.
    threads = []
    for svc in service:
        t = threading.Thread(target=stream_journal_worker, args=(svc, process_line, logger), daemon=True)
        t.start()
        threads.append(t)

    # Keep the process alive while threads run in background.
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping journalctl streaming...")