import sqlite3
import os
from collections import Counter

# Database's file
DB_FILE = os.path.join("data", "log_analyzer.db")

# Generate report
def generate_report():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print("--- Relatório de Segurança---")

    # 1. The total of processed logs
    total_logs = cursor.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    print(f"\n[+] Total de logs analisados: {total_logs}")

    # 2. Top 5 países com mais tentativas de login
    cursor.execute("SELECT country FROM logs WHERE action = 'login'")
    countries = [row['country'] for row in cursor.fetchall() if row['country'] != 'UNKNOWN']
    top_countries = Counter(countries).most_common(5)
    print("\n[+] Top 5 países por tentativas de login:")
    for country, count in top_countries:
        print(f"  - {country}: {count} tentativas")

    # 3. Top 5 IPs que geraram alertas
    cursor.execute("SELECT ip FROM alerts")
    alert_ips = [row['ip'] for row in cursor.fetchall()]
    top_alert_ips = Counter(alert_ips).most_common(5)
    print("\n[+] Top 5 IPs que geraram mais alertas:")
    for ip, count in top_alert_ips:
        print(f"  - {ip}: {count} alertas")
        
    # 4. Últimos 5 IPs bloqueados
    cursor.execute("SELECT ip, country, block_time FROM blocked_ips ORDER BY id DESC LIMIT 5")
    last_blocked = cursor.fetchall()
    print("\n[+] Últimos 5 IPs bloqueados:")
    for row in last_blocked:
        print(f"  - IP: {row['ip']} ({row['country']}) em {row['block_time']}")


    conn.close()

if __name__ == "__main__":
    generate_report()