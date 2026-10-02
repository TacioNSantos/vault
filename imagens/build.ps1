param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Compilando e Versionando Imagem Docker do Vault " -ForegroundColor Cyan
Write-Host " Versão: $Version" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan

Set-Location $RootDir

Write-Host "`n1. Executando build sem cache..." -ForegroundColor Green
docker build --no-cache -t "vault:$Version" -t "vault:latest" .

$OutputFile = Join-Path $ScriptDir "vault-$Version.tar"
$LatestFile = Join-Path $ScriptDir "vault-latest.tar"

Write-Host "`n2. Exportando imagem para: $OutputFile" -ForegroundColor Green
docker save -o $OutputFile "vault:$Version"

Write-Host "`n3. Atualizando atalho para a ultima versao: $LatestFile" -ForegroundColor Green
Copy-Item -Path $OutputFile -Destination $LatestFile -Force

Write-Host "`n[SUCESSO] Imagens versionadas salvas na pasta 'imagens/':" -ForegroundColor Cyan
Get-ChildItem -Path $ScriptDir -Filter "*.tar" | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
