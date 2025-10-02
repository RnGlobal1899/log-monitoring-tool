import os
import datetime
from yaml import safe_load

def generate_test_logs(log_dir):
    os.makedirs(log_dir, exist_ok=True)

    test_file = os.path.join(log_dir, "access_test.log")
    with open(test_file, "w", encoding="utf-8") as f:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ✅ Login sucesso (Brasil)
        f.write(f"{now}, IP: 8.8.8.8, user: alice, action: login, result: success\n")

        # ❌ Login falho repetido (China)
        for i in range(6):
            ts = (datetime.datetime.now() + datetime.timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts}, IP: 1.2.2.124, user: ping-ong, action: login, result: fail\n")

        # 🚫 Login de país não permitido (Austria)
        ts2 = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{ts2}, IP: 103.203.183.145, user: evil, action: login, result: fail\n")

    print(f"✅ Test log file created at: {test_file}")


if __name__ == "__main__":
    # caminho relativo ao script
    script_dir = os.path.dirname(__file__)
    project_root = os.path.abspath(os.path.join(script_dir, "..", ".."))

    config_path = os.path.join(project_root, "config.yaml")
    with open(config_path, "r") as f:
        config = safe_load(f)

    log_dir = os.path.abspath(os.path.join(project_root, config["log_dir"]))
    generate_test_logs(log_dir)