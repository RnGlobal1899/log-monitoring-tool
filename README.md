# Firewall Log Analyzer

Este projeto analisa arquivos de logs de acessos em tempo real, identifica tentativas de login suspeitas, bloqueia IPs de países não permitidos e gera alertas de segurança, persistindo todos os dados em um banco de dados SQLite para análise posterior.

## Estrutura do projeto

firewall-log-analyzer/
│── data/
│   └── log_analyzer.db   # Banco de dados SQLite (ignorado pelo Git)
│
│── scripts/              # Ferramentas e utilitários
│   ├── generate_test_logs.py
│   ├── report.py
│   └── run_tests.ps1
│
│── src/
│   ├── analyzer.py       # Script principal que executa a lógica
│   ├── database.py       # Módulo de gerenciamento do banco de dados
│   ├── ip_utils.py       # Funções de IP e geolocalização
│   ├── log_utils.py      # Configuração do sistema de logs
│   ├── parser.py         # Leitura e parsing de arquivos de log
│   └── realtime.py       # Monitoramento de logs em tempo real
│
│── tests/                # Testes automatizados com pytest
│   ├── test_ip_utils.py
│   ├── test_parser.py
│   └── validate_logs.py
│
│── .gitignore            # Arquivos e pastas a serem ignorados pelo Git
│── CHANGELOG.md          # Histórico de mudanças do projeto
│── LICENSE               # Licença de uso do software (MIT)
│── README.md             # Documentação principal
│── config.yaml           # Arquivo de configuração
│── pytest.ini            # Configuração do framework de testes
└── requirements.txt      # Dependências do projeto


## Como usar

1.  **Instale as dependências**
    ```bash
    pip install -r requirements.txt
    ```

2.  **(Opcional) Gere logs artificiais de teste**
    ```bash
    python scripts/generate_test_logs.py
    ```
    Isso criará arquivos de log de exemplo na pasta definida em `config.yaml`.

3.  **Execute o analisador**
    ```bash
    # CORREÇÃO AQUI
    python src/analyzer.py
    ```
    A ferramenta começará a monitorar o diretório de logs em tempo real.

## Resultados e Relatórios

Após a execução, os seguintes arquivos serão atualizados/gerados:

* **`data/log_analyzer.db`**: Banco de dados contendo todos os logs processados, IPs bloqueados e alertas gerados.
* **`logs/monitoring_logs/`**: Contém os logs da própria ferramenta (`system.log`, `alerts.log`, `errors.log`), conforme configurado no `config.yaml`.

### Gerando um Relatório de Segurança

Para analisar os dados coletados, execute o script de relatório:

```bash
python scripts/report.py
```

🔍 Validação Automática dos Logs
Este repositório inclui um script de validação (tests/validate_logs.py) para verificar a correção dos logs gerados.

▶️ Como rodar o validador
```bash
python tests/validate_logs.py "Caminho do arquivo .log"
```

Testes Automatizados
Os testes ficam na pasta tests/ e usam pytest. Para rodar todos os testes, execute o script auxiliar:

```bash
# No Windows (PowerShell)
./scripts/run_tests.ps1

# Ou execute diretamente com pytest
python -m pytest -v
```

Configuração
As opções principais ficam em config.yaml.
Exemplo de configuração:

YAML

log_dir: "logs/access_logs"
monitor_log_dir: "logs/monitoring_logs"
login_fail_limit: 5
login_fail_window: 60
allowed_countries:
  - BRAZIL
  - UNITED STATES
  - GERMANY
  - INDIA
Futuras melhorias
[x] ~~Armazenamento em banco de dados (SQLite)~~

Integração com firewall real (iptables/netsh)

Notificações por e-mail ou webhook (Slack/Discord)

Dashboard web para visualização em tempo real
