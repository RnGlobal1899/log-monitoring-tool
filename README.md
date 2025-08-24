# Firewall Log Analyzer

Este projeto analisa arquivos de logs simulados de conexões de rede, bloqueia IPs de países não permitidos e gera alertas de acessos suspeitos.

## Estrutura do projeto

```
firewall-log-analyzer/
│── src/
│   └── analyzer.py        # Script principal
│── tests/                 # Testes automatizados (futuros)
│── data/                  # Logs de entrada (.log)
│── docs/                  # Documentação
│── blocked_ips.txt        # Lista persistente de IPs bloqueados
│── alert_ips.txt          # Lista de IPs que geraram alertas
│── README.md              # Documentação principal
```

## Como usar

1. Coloque seus arquivos `.log` dentro da pasta escolhida
2. Execute o analisador:
   ```bash
   python src/analyzer.py
   ```
3. Os resultados serão salvos em:
   - `blocked_ips.txt`
   - `alert_ips.txt`

## Requisitos

- Python 3.8+
- Dependências: `requests`, `pycountry`

Instale com:
```bash
pip install -r requirements.txt
```

## Futuras melhorias

- Adicionar testes automatizados
- Melhorar detecção de padrões suspeitos
- Integrar com banco de dados
