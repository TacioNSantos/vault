#!/usr/bin/env bash
# ==============================================================================
# Smoke Test Docker: Cluster Vault de 2 Nós (Modelo Conjur / evoke)
# Valida:
# 1. Boot unconfigured no Node 1
# 2. configure primary com PKI autoassinada
# 3. Boot unconfigured no Node 2
# 4. seed standby por PIPE via stdin (docker exec node1 | docker exec -i node2)
# 5. configure standby no Node 2 com mTLS streaming
# 6. Verificacao de pg_stat_replication = streaming
# 7. Verificacao de /health nos dois nós
# 8. Desligamento do Node 1 e promocao do Node 2 (role promote)
# 9. Geracao de seed a partir do novo primario (nó promovido)
# ==============================================================================

set -euo pipefail

NET_NAME="vault-smoke-net"
VOL_NODE1="vault-smoke-n1-data"
VOL_NODE2="vault-smoke-n2-data"
CONTAINER_N1="vault-smoke-1"
CONTAINER_N2="vault-smoke-2"
TMP_DIR=$(mktemp -d)

cleanup() {
    echo -e "\n[Limpando ambiente de teste...]"
    docker rm -f "$CONTAINER_N1" "$CONTAINER_N2" 2>/dev/null || true
    docker volume rm "$VOL_NODE1" "$VOL_NODE2" 2>/dev/null || true
    docker network rm "$NET_NAME" 2>/dev/null || true
    rm -rf "$TMP_DIR"
    echo "Ambiente limpo."
}
trap cleanup EXIT INT TERM

echo "=================================================================="
echo "          INICIANDO SMOKE TEST DOCKER (MODELO CONJUR)             "
echo "=================================================================="

# 0. Prepara rede e chave mestra
docker network create "$NET_NAME"
docker volume create "$VOL_NODE1"
docker volume create "$VOL_NODE2"

KEY_FILE="$TMP_DIR/master.key"
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())" > "$KEY_FILE"
chmod 600 "$KEY_FILE"

# 1. Sobe Node 1 (inicia em unconfigured)
echo -e "\n[Passo 1] Subindo Node 1 (Líder em unconfigured)..."
docker run -d --name "$CONTAINER_N1" --network "$NET_NAME" \
    --mount "type=bind,source=$KEY_FILE,target=/run/secrets/master.key,readonly" \
    -v "$VOL_NODE1:/var/lib/postgresql/data" \
    vault

# 2. Configura Node 1 como Primário
echo -e "\n[Passo 2] Executando 'vaultctl configure primary' no Node 1..."
docker exec -i "$CONTAINER_N1" vaultctl configure primary \
    --hostname vault.cluster.local \
    --altname "$CONTAINER_N1" \
    --altname "$CONTAINER_N2" \
    --altname 127.0.0.1 \
    --admin-name admin \
    --admin-ip "0.0.0.0/0" \
    --admin-secret-stdin <<< "AdminSecret123!"

sleep 3

# 3. Sobe Node 2 (inicia em unconfigured)
echo -e "\n[Passo 3] Subindo Node 2 (Standby em unconfigured)..."
docker run -d --name "$CONTAINER_N2" --network "$NET_NAME" \
    --mount "type=bind,source=$KEY_FILE,target=/run/secrets/master.key,readonly" \
    -v "$VOL_NODE2:/var/lib/postgresql/data" \
    vault

# 4. Gera seed no Node 1 e envia DIRETAMENTE para o Node 2 via pipe stdin
echo -e "\n[Passo 4] Transferindo seed por pipe (Node 1 -> Node 2)..."
docker exec "$CONTAINER_N1" vaultctl seed standby "$CONTAINER_N2" --primary-host "$CONTAINER_N1" | \
    docker exec -i "$CONTAINER_N2" vaultctl unpack seed -

# 5. Configura Standby no Node 2
echo -e "\n[Passo 5] Executando 'vaultctl configure standby' no Node 2..."
docker exec "$CONTAINER_N2" vaultctl configure standby

sleep 4

# 6. Valida replicação WAL ativa no Node 1
echo -e "\n[Passo 6] Validando streaming de replicação no PostgreSQL..."
REPL_STATE=$(docker exec "$CONTAINER_N1" gosu postgres psql -tAc "SELECT state FROM pg_stat_replication;" | head -n 1)
echo "Estado da replicacao no lider: $REPL_STATE"
if [[ "$REPL_STATE" != "streaming" ]]; then
    echo "ERRO: Replicacao nao esta em streaming!" >&2
    exit 1
fi

# 7. Valida rota /health nos dois nós
echo -e "\n[Passo 7] Verificando endpoints /health com TLS..."
docker exec "$CONTAINER_N1" curl -ksf https://127.0.0.1:443/health | grep -q '"role":"primary"'
echo "Node 1 respondeu como primary!"

docker exec "$CONTAINER_N2" curl -ksf https://127.0.0.1:443/health | grep -q '"role":"standby"'
echo "Node 2 respondeu como standby (read-only)!"

# 8. Desliga Node 1 e promove Node 2 (Failover Anti-Split-Brain)
echo -e "\n[Passo 8] Desligando Node 1 e promovendo Node 2..."
docker stop "$CONTAINER_N1"
docker exec "$CONTAINER_N2" vaultctl role promote

sleep 2
docker exec "$CONTAINER_N2" curl -ksf https://127.0.0.1:443/health | grep -q '"role":"primary"'
echo "Node 2 assumiu como novo Líder de escrita!"

# 9. Promovido Node 2 gera seed para um terceiro nó
echo -e "\n[Passo 9] Testando geracao de seed pelo novo Primario..."
docker exec "$CONTAINER_N2" vaultctl seed standby vault-3 --output /tmp/node3.seed.tar
docker exec "$CONTAINER_N2" test -f /tmp/node3.seed.tar
echo "Novo primario gerou seed com sucesso para um terceiro no!"

echo -e "\n=================================================================="
echo "          TODOS OS TESTES DE SMOKE PASSARAM COM SUCESSO!          "
echo "=================================================================="
