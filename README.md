# Firewall Log Analyzer

Este projeto analisa arquivos de logs de acessos simulados, identifica tentativas de login suspeitas, bloqueia IPs de países não permitidos e gera alertas de segurança.
É uma ferramenta de monitoramento simples, pensada para simular o funcionamento de um firewall em um cenário real.

## Estrutura do projeto

```
firewall-log-analyzer/
│── src/
│   ├── monitor.py        # Script principal (entry point)
│   ├── log_utils.py      # Configuração do sistema de logs
│   ├── ip_utils.py       # Funções de IP e país
│   ├── parser.py         # Leitura e parsing de arquivos de log
│
│── tests/                # Testes automatizados com pytest
│   ├── generate_test_logs.py
│   ├── test_ip_utils.py
│   ├── test_parser.py
│   ├── validate_logs.py
│
│── config.yaml           # Arquivo de configuração
│── requirements.txt      # Dependências do projeto
│── blocked_ips.txt       # Lista persistente de IPs bloqueados
│── alert_ips.txt         # Lista persistente de IPs que geraram alertas
│── README.md             # Documentação principal
```

## Como usar

1. Instale as dependências
```bash
pip install -r requirements.txt
```

2. Gere logs artificiais de teste
```bash
python examples/generate_test_logs.py
```
Isso criará um arquivo de log de exemplo na pasta definida em config.yaml.

3. Execute o analisador
```bash
python src/monitor.py
```

4. Resultados e relatórios

Após a execução, os seguintes arquivos serão atualizados/gerados:

* **`log_analyzer.db`**: Banco de dados contendo todos os logs processados, IPs bloqueados e alertas gerados.
* **`logs/monitoring_logs/`**: Contém os logs da própria ferramenta (`system.log`, `alerts.log`, `errors.log`).

### Gerando um Relatório de Segurança

Para analisar os dados coletados, execute o script de relatório:

```bash
python report.py
```

## 🔍 Validação Automática dos Logs

Este repositório inclui um script de validação (`tests/validate_logs.py`) que verifica automaticamente se os logs estão corretos de acordo com as seguintes regras:

- Logins de **países permitidos** (`Brazil`, `United States`, `Canada`, `United Kingdom`) devem aparecer apenas como `success`.
- Logins de **países não permitidos** devem sempre aparecer como `fail`.

### ▶️ Como rodar o validador

No terminal, execute:

```bash
python tests/validate_logs.py "Caminho do arquivo .log"
```
Caso não especifique um caminho, o padrão será "/logs/monitoring_logs/system.log".


## Configuração

As opções principais ficam em config.yaml.
Exemplo de configuração:

log_dir: "C:/Users/seu_usuario/Desktop/test_project/test"
monitor_log_dir: "C:/Users/seu_usuario/Desktop/test_project/logs"
login_fail_limit: 5
login_fail_window: 60
allowed_countries:
  - BRAZIL
  - UNITED STATES
  - GERMANY
  - INDIA

## Requisitos

- Python 3.8+
- Dependências: `requests`, `pycountry`, `pyyaml`, `pytest` (esse último apenas para testar)

Instale com:
```bash
pip install -r requirements.txt
```
## testes
Testes Automatizados

Os testes ficam na pasta tests/ e usam pytest.

Rodar todos os testes:

```bash
python -m pytest -v
```
## Futuras melhorias

- Integração com firewall real (iptables/netsh)
- Notificações por e-mail ou webhook (Slack/Discord)
- Dashboard web para visualização em tempo real
