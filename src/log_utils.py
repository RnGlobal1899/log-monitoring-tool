import os
import logging


import os
import logging

def setup_logger(monitor_log_dir):
    os.makedirs(monitor_log_dir, exist_ok=True)

    logger = logging.getLogger("monitor")
    logger.setLevel(logging.DEBUG)

    # system log
    system_handler = logging.FileHandler(os.path.join(monitor_log_dir, "system.log"))
    system_handler.setLevel(logging.DEBUG)
    system_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    system_handler.setFormatter(system_formatter)

    # alerts log
    alert_handler = logging.FileHandler(os.path.join(monitor_log_dir, "alerts.log"))
    alert_handler.setLevel(logging.WARNING)
    alert_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    alert_handler.setFormatter(alert_formatter)

    # errors log
    error_handler = logging.FileHandler(os.path.join(monitor_log_dir, "errors.log"))
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    error_handler.setFormatter(error_formatter)

    # console log (debugging)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)

    logger.addHandler(system_handler)
    logger.addHandler(alert_handler)
    logger.addHandler(error_handler)
    logger.addHandler(console_handler)

    return logger
