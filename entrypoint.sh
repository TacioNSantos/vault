#!/bin/bash
set -e

MASTER_KEY_FILE="${MASTER_KEY_FILE:-/run/secrets/master.key}"
export PATH="$(pg_config --bindir):$PATH"

POSTGRES_USER="${POSTGRES_USER:-vault}"
POSTGRES_DB="${POSTGRES_DB:-vault}"
REPLICATION_USER="${REPLICATION_USER:-replicator}"

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
TMPFS_TLS="/dev/shm/vault_tls"

# Trap para limpar chaves em memoria volátil no shutdown do container
cleanup_tls() {
    python3 -c "from vault.pki import shred_tmpfs_keys; shred_tmpfs_keys('$TMPFS_TLS')" 2>/dev/null || true
}
trap cleanup_tls EXIT TERM INT

# =========================================================================
# 1. ESTADO: UNCONFIGURED vs CONFIGURED
# =========================================================================
mkdir -p "$PGDATA"
if [ "$(id -u)" = "0" ]; then
    chown -R postgres:postgres "$PGDATA" 2>/dev/null || true
    chmod 700 "$PGDATA" 2>/dev/null || true
fi

# Se o volume nao possui cluster.json, o container entra em modo de espera
# aguardando os comandos da CLI ('vaultctl configure ...').
if [ ! -f "$PGDATA/cluster.json" ]; then
    # Compatibilidade retroativa apenas se o volume legado ja possuia banco completo E tls
    if [ -s "$PGDATA/PG_VERSION" ] && [ -f "$PGDATA/tls/cluster.crt" ]; then
        echo "[VAULT] Volume pre-existente detectado. Gerando cluster.json..."
        cat <<EOF > "$PGDATA/cluster.json"
{
  "role": "${REPLICATION_ROLE:-primary}",
  "hostname": "localhost",
  "primary_host": "${PRIMARY_HOST:-vault-primary}",
  "primary_port": ${PRIMARY_PORT:-5432},
  "configured_at": "legacy"
}
EOF
    else
        echo "========================================================================"
        echo " [VAULT] Appliance iniciado em estado NAO CONFIGURADO."
        echo " Aguardando provisionamento via CLI..."
        echo ""
        echo " Para configurar como Líder (Primário):"
        echo "   docker exec -it <container> vaultctl configure primary --hostname <fqdn> --admin-ip <cidr>"
        echo ""
        echo " Para configurar como Réplica (Standby):"
        echo "   docker exec -i <container> vaultctl unpack seed - < seed.tar"
        echo "   docker exec <container> vaultctl configure standby"
        echo "========================================================================"

        # Mantem o processo vivo aguardando a CLI criar cluster.json
        while [ ! -f "$PGDATA/cluster.json" ]; do
            sleep 1
        done

        echo "[VAULT] Configuracao detectada. Prosseguindo com o boot..."
    fi
fi

# =========================================================================
# 2. CARREGA CONFIGURACAO DO CLUSTER (cluster.json)
# =========================================================================
if [ -f "$PGDATA/cluster.json" ]; then
    REPLICATION_ROLE="$(python3 -c "import json; print(json.load(open('$PGDATA/cluster.json')).get('role', 'primary'))" 2>/dev/null || echo primary)"
    PRIMARY_HOST="$(python3 -c "import json; print(json.load(open('$PGDATA/cluster.json')).get('primary_host', 'vault-primary'))" 2>/dev/null || echo vault-primary)"
    PRIMARY_PORT="$(python3 -c "import json; print(json.load(open('$PGDATA/cluster.json')).get('primary_port', 5432))" 2>/dev/null || echo 5432)"
    CLUSTER_HOSTNAME="$(python3 -c "import json; print(json.load(open('$PGDATA/cluster.json')).get('hostname', 'vault.cluster.local'))" 2>/dev/null || echo vault.cluster.local)"
elif [ -s "$PGDATA/PG_VERSION" ]; then
    # Compatibilidade com volumes existentes
    REPLICATION_ROLE="${REPLICATION_ROLE:-primary}"
    PRIMARY_HOST="${PRIMARY_HOST:-vault-primary}"
    PRIMARY_PORT="${PRIMARY_PORT:-5432}"
    CLUSTER_HOSTNAME="localhost"
    cat <<EOF > "$PGDATA/cluster.json"
{
  "role": "$REPLICATION_ROLE",
  "hostname": "$CLUSTER_HOSTNAME",
  "primary_host": "$PRIMARY_HOST",
  "primary_port": $PRIMARY_PORT
}
EOF
fi

if [ "$REPLICATION_ROLE" = "primary" ]; then
    POSTGRES_LISTEN_ADDRESSES="${POSTGRES_LISTEN_ADDRESSES:-*}"
else
    POSTGRES_LISTEN_ADDRESSES="${POSTGRES_LISTEN_ADDRESSES:-localhost}"
fi

# =========================================================================
# 3. RECUPERA OU GERA CREDENCIAIS INTERNAS DO POSTGRES
# =========================================================================
DB_PASS_FILE="$PGDATA/.db_password"
if [ -n "$POSTGRES_PASSWORD" ]; then
    PASS="$POSTGRES_PASSWORD"
elif [ -f "$DB_PASS_FILE" ]; then
    PASS="$(cat "$DB_PASS_FILE")"
elif [ -s "$PGDATA/PG_VERSION" ]; then
    PASS="vault"
else
    PASS="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
fi
export POSTGRES_PASSWORD="$PASS"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB}"

# Salva .database_url no volume para uso por comandos internos e docker exec
if [ -d "$PGDATA" ]; then
    echo "$DATABASE_URL" > "$PGDATA/.database_url" 2>/dev/null || true
    chmod 600 "$PGDATA/.database_url" 2>/dev/null || true
    chown postgres:postgres "$PGDATA/.database_url" 2>/dev/null || true
fi

# =========================================================================
# 4. INSTALA CHAVES TLS NA MEMORIA VOLATIL (tmpfs /dev/shm)
# =========================================================================
TLS_DIR=""
PG_SSL_OPTS=""

if [ -f "$PGDATA/tls/cluster.crt" ] && [ -f "$PGDATA/tls/cluster.key.enc" ]; then
    if [ -d "$MASTER_KEY_FILE" ] && [ -f "$MASTER_KEY_FILE/master.key" ]; then
        MASTER_KEY_FILE="$MASTER_KEY_FILE/master.key"
    fi
    if [ ! -f "$MASTER_KEY_FILE" ]; then
        echo "[VLT-1001] master.key nao encontrada em $MASTER_KEY_FILE ao carregar certificados do cluster." >&2
        exit 1
    fi

    # Decifra chaves privadas diretamente para o tmpfs
    python3 -c "
from vault.pki import install_keys_to_tmpfs
from vault.bootstrap import load_master_key_from_file
key = load_master_key_from_file()
install_keys_to_tmpfs('$PGDATA/tls', key, '$TMPFS_TLS')
"
    TLS_DIR="$TMPFS_TLS"
elif [ -f "/run/secrets/tls/server.crt" ] && [ -f "/run/secrets/tls/server.key" ]; then
    TLS_DIR="/run/secrets/tls"
fi

if [ -n "$TLS_DIR" ] && [ -f "$TLS_DIR/server.crt" ] && [ -f "$TLS_DIR/server.key" ]; then
    PG_SSL_OPTS="-c ssl=on -c ssl_cert_file=$TLS_DIR/server.crt -c ssl_key_file=$TLS_DIR/server.key"
    if [ -f "$TLS_DIR/ca.crt" ]; then
        PG_SSL_OPTS="$PG_SSL_OPTS -c ssl_ca_file=$TLS_DIR/ca.crt"
    fi
fi

# =========================================================================
# 5. ATIVA E CONFIGURA O POSTGRESQL
# =========================================================================
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Configura mapa de identidades mTLS (pg_ident.conf) e pg_hba.conf
cat <<EOF > "$PGDATA/pg_ident.conf"
# MAPNAME       SYSTEM-USERNAME (CERT CN)       PG-USERNAME
cluster_map     /^.*\$                          $REPLICATION_USER
EOF
chown postgres:postgres "$PGDATA/pg_ident.conf"
chmod 600 "$PGDATA/pg_ident.conf"

if [ "$REPLICATION_ROLE" = "primary" ]; then
    if ! grep -q "cluster_map" "$PGDATA/pg_hba.conf" 2>/dev/null; then
        echo "hostssl replication $REPLICATION_USER all cert map=cluster_map clientcert=verify-full" >> "$PGDATA/pg_hba.conf"
    fi
fi

# Sobe o Postgres se nao estiver rodando
if ! gosu postgres pg_isready -q; then
    if ! gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses='$POSTGRES_LISTEN_ADDRESSES' $PG_SSL_OPTS" -w start; then
        echo "Aviso: falha ao iniciar Postgres. Tentando auto-recuperacao de checkpoint..." >&2
        gosu postgres pg_resetwal -f "$PGDATA" 2>/dev/null || true
        gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses='$POSTGRES_LISTEN_ADDRESSES' $PG_SSL_OPTS" -w start
    fi
fi

until gosu postgres pg_isready -q; do
    sleep 1
done

# Garante criacao do usuario replicator no primario
if [ "$REPLICATION_ROLE" = "primary" ]; then
    gosu postgres psql -d postgres -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$REPLICATION_USER') THEN CREATE ROLE $REPLICATION_USER WITH REPLICATION LOGIN; END IF; END \$\$;" > /dev/null 2>&1 || true
fi

# Garante revogacao de SUPERUSER no usuario da aplicacao
if ! gosu postgres psql -d postgres -tAc "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q "t"; then
    gosu postgres psql -d postgres -c "ALTER ROLE \"$POSTGRES_USER\" WITH NOSUPERUSER NOCREATEDB NOCREATEROLE;" > /dev/null 2>&1 || true
fi

if [ "${VAULT_INIT_ONLY:-0}" = "1" ]; then
    echo "Postgres pronto para administracao / operacoes internas."
    touch /tmp/postgres-ready
    exec sleep infinity
fi

# =========================================================================
# 6. INICIA API REST EM HTTPS COM FASTAPI / UVICORN
# =========================================================================
UVICORN_SSL_ARGS=()
if [ -n "$TLS_DIR" ] && [ -f "$TLS_DIR/server.crt" ] && [ -f "$TLS_DIR/server.key" ]; then
    UVICORN_SSL_ARGS=(
        "--ssl-keyfile" "$TLS_DIR/server.key"
        "--ssl-certfile" "$TLS_DIR/server.crt"
    )
    if [ -f "$TLS_DIR/ca.crt" ]; then
        UVICORN_SSL_ARGS+=("--ssl-ca-certs" "$TLS_DIR/ca.crt")
    fi
fi

touch /tmp/postgres-ready
API_PORT="${API_PORT:-443}"
echo "[VAULT] Inicializacao concluida. Iniciando API Web em https://0.0.0.0:$API_PORT (role: $REPLICATION_ROLE)..."
exec python -m uvicorn vault.main:app --host 0.0.0.0 --port "$API_PORT" "${UVICORN_SSL_ARGS[@]}"
