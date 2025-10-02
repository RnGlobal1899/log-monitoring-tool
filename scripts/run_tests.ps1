# Seta o PYTHONPATH para a raiz do projeto
$env:PYTHONPATH = $PWD

Write-Host "PYTHONPATH definido para: $PWD"
Write-Host "Rodando pytest..."

# Executa pytest na pasta tests
pytest .\tests\ -v