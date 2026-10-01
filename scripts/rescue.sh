#!/usr/bin/env bash
# ==============================================================================
# Vault Break-Glass Rescue Tool (Resgate de Emergencia Offline)
# Recupera segredos diretamente do volume de dados e da master.key
# sem necessidade da API web ativa e em isolamento de rede (--network none).
# ==============================================================================

set -euo pipefail

usage() {
    echo "Uso: $0 --key <caminho_master.key> --volume <nome_volume> [--output <arquivo_json>]"
    echo ""
    echo "Exemplo:"
    echo "  $0 --key ./master.key --volume vault-primary-data --output segredos.json"
    exit 1
}

KEY_PATH=""
VOLUME_NAME=""
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)
            KEY_PATH="$(realpath "$2")"
            shift 2
            ;;
        --volume)
            VOLUME_NAME="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$(realpath "$2")"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Opcao desconhecida: $1" >&2
            usage
            ;;
    esac
done

if [[ -z "$KEY_PATH" || -z "$VOLUME_NAME" ]]; then
    echo "Erro: --key e --volume sao obrigatorios." >&2
    usage
fi

if [[ ! -f "$KEY_PATH" ]]; then
    echo "Erro: Arquivo master.key nao encontrado em: $KEY_PATH" >&2
    exit 1
fi

echo "=================================================================="
echo "           INICIANDO RESGATE DE EMERGENCIA (BREAK-GLASS)          "
echo "=================================================================="
echo "• Volume:     $VOLUME_NAME"
echo "• Master Key: $KEY_PATH"
echo ""

# Verifica se existe container ativo usando o volume
RUNNING_CONTAINER=$(docker ps --filter "volume=$VOLUME_NAME" --format "{{.Names}}" | head -n 1 || true)

if [[ -n "$RUNNING_CONTAINER" ]]; then
    echo "Container ativo '$RUNNING_CONTAINER' detectado utilizando este volume."
    echo "Executando extracao diretamente no processo em execucao..."
    if [[ -n "$OUTPUT_FILE" ]]; then
        docker exec "$RUNNING_CONTAINER" vaultctl rescue --master-key /run/secrets/master.key --format json > "$OUTPUT_FILE"
        echo "[SUCESSO] Segredos extraidos e salvos em: $OUTPUT_FILE"
    else
        docker exec "$RUNNING_CONTAINER" vaultctl rescue --master-key /run/secrets/master.key --format text
    fi
else
    echo "Nenhum container ativo. Subindo container efemero isolado (--network none)..."
    RESCUE_CMD="
export PATH=\$(pg_config --bindir):\$PATH
chown -R postgres:postgres /var/lib/postgresql/data
chmod 700 /var/lib/postgresql/data
rm -f /var/lib/postgresql/data/postmaster.pid
export POSTGRES_PASSWORD=\$(cat /var/lib/postgresql/data/.db_password 2>/dev/null || echo vault)
export DATABASE_URL=postgresql+psycopg2://vault:\$POSTGRES_PASSWORD@localhost:5432/vault
if ! gosu postgres pg_ctl -D /var/lib/postgresql/data -o \"-c listen_addresses='localhost'\" -w start > /dev/null 2>&1; then
    gosu postgres pg_resetwal -f /var/lib/postgresql/data > /dev/null 2>&1
    gosu postgres pg_ctl -D /var/lib/postgresql/data -o \"-c listen_addresses='localhost'\" -w start > /dev/null 2>&1
fi
vaultctl rescue --master-key /run/secrets/master.key $([[ -n "$OUTPUT_FILE" ]] && echo "--format json" || echo "--format text")
gosu postgres pg_ctl -D /var/lib/postgresql/data -m fast -w stop > /dev/null 2>&1
"
    if [[ -n "$OUTPUT_FILE" ]]; then
        docker run --rm \
            -v "$VOLUME_NAME:/var/lib/postgresql/data" \
            --mount "type=bind,source=$KEY_PATH,target=/run/secrets/master.key,readonly" \
            --network none \
            --entrypoint bash \
            vault -c "$RESCUE_CMD" > "$OUTPUT_FILE"
        echo "[SUCESSO] Segredos extraidos e salvos em: $OUTPUT_FILE"
    else
        docker run --rm \
            -v "$VOLUME_NAME:/var/lib/postgresql/data" \
            --mount "type=bind,source=$KEY_PATH,target=/run/secrets/master.key,readonly" \
            --network none \
            --entrypoint bash \
            vault -c "$RESCUE_CMD"
    fi
fi
