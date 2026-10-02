#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo " Compilando e Versionando Imagem Docker do Vault "
echo " Versao: $VERSION"
echo "=================================================="

cd "$ROOT_DIR"

echo -e "\n1. Executando build sem cache..."
docker build --no-cache -t "vault:$VERSION" -t "vault:latest" .

OUTPUT_FILE="$SCRIPT_DIR/vault-$VERSION.tar"
LATEST_FILE="$SCRIPT_DIR/vault-latest.tar"

echo -e "\n2. Exportando imagem para: $OUTPUT_FILE"
docker save -o "$OUTPUT_FILE" "vault:$VERSION"

echo -e "\n3. Atualizando vault-latest.tar..."
cp -f "$OUTPUT_FILE" "$LATEST_FILE"

echo -e "\n[SUCESSO] Imagens versionadas salvas na pasta 'imagens/':"
ls -lh "$SCRIPT_DIR"/*.tar
