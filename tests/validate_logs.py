import sys
import os

# Lista de países permitidos
ALLOWED_COUNTRIES = ["Brazil", "United States", "Canada", "United Kingdom"]

# Caminho padrão (caso nenhum argumento seja passado)
DEFAULT_LOG_PATH = os.path.join("logs", "monitoring_logs", "system.log")

def validate_logs(log_file):
    errors = []
    with open(log_file, "r") as f:
        for line_num, line in enumerate(f, start=1):
            parts = line.strip().split()
            if len(parts) < 4:
                errors.append(f"Linha {line_num}: formato inválido -> {line.strip()}")
                continue

            date, time, country, status = parts[0], parts[1], parts[2], parts[3]

            # Verifica se país não permitido aparece como "success"
            if country not in ALLOWED_COUNTRIES and status == "success":
                errors.append(
                    f"Linha {line_num}: país proibido '{country}' com status success"
                )

            # Verifica se país permitido aparece como "fail"
            if country in ALLOWED_COUNTRIES and status == "fail":
                errors.append(
                    f"Linha {line_num}: país permitido '{country}' marcado como fail"
                )

    if errors:
        print("❌ Erros encontrados:")
        for err in errors:
            print("-", err)
    else:
        print("✅ Todos os logs estão corretos.")

if __name__ == "__main__":
    # Se o usuário não passar nada, usa o system.log por padrão
    log_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_PATH
    validate_logs(log_file)