#!/bin/bash
set -e

MASTER_KEY_FILE="${MASTER_KEY_FILE:-/run/secrets/master.key}"
export PATH="$(pg_config --bindir):$PATH"

POSTGRES_USER="${POSTGRES_USER:-vault}"
POSTGRES_DB="${POSTGRES_DB:-vault}"
REPLICATION_ROLE="${REPLICATION_ROLE:-standalone}"
REPLICATION_USER="${REPLICATION_USER:-replicator}"
REPLICATION_PASSWORD="${REPLICATION_PASSWORD:-vault_replicator_secret}"
PRIMARY_HOST="${PRIMARY_HOST:-vault-primary}"
PRIMARY_PORT="${PRIMARY_PORT:-5432}"
TLS_DIR="${TLS_DIR:-/run/secrets/tls}"

USE_TLS=0
PG_SSL_OPTS=""
if [ -f "$TLS_DIR/server.crt" ] && [ -f "$TLS_DIR/server.key" ]; then
    USE_TLS=1
    mkdir -p "$PGDATA/tls"
    [ -f "$TLS_DIR/ca.crt" ] && cp "$TLS_DIR/ca.crt" "$PGDATA/tls/ca.crt"
    cp "$TLS_DIR/server.crt" "$PGDATA/tls/server.crt"
    cp "$TLS_DIR/server.key" "$PGDATA/tls/server.key"
    [ -f "$TLS_DIR/client.crt" ] && cp "$TLS_DIR/client.crt" "$PGDATA/tls/client.crt"
    [ -f "$TLS_DIR/client.key" ] && cp "$TLS_DIR/client.key" "$PGDATA/tls/client.key"
    chown -R postgres:postgres "$PGDATA/tls" 2>/dev/null || true
    chmod 700 "$PGDATA/tls" 2>/dev/null || true
    chmod 600 "$PGDATA/tls/"* 2>/dev/null || true

    PG_SSL_OPTS="-c ssl=on -c ssl_cert_file=$PGDATA/tls/server.crt -c ssl_key_file=$PGDATA/tls/server.key"
    if [ -f "$PGDATA/tls/ca.crt" ]; then
        PG_SSL_OPTS="$PG_SSL_OPTS -c ssl_ca_file=$PGDATA/tls/ca.crt"
    fi
fi

if [ "$REPLICATION_ROLE" = "primary" ]; then
    POSTGRES_LISTEN_ADDRESSES="${POSTGRES_LISTEN_ADDRESSES:-*}"
else
    POSTGRES_LISTEN_ADDRESSES="${POSTGRES_LISTEN_ADDRESSES:-localhost}"
fi

# Recupera, carrega ou gera a credencial segura do Postgres
DB_PASS_FILE="$PGDATA/.db_password"
if [ -n "$POSTGRES_PASSWORD" ]; then
    PASS="$POSTGRES_PASSWORD"
elif [ -f "$DB_PASS_FILE" ]; then
    PASS="$(cat "$DB_PASS_FILE")"
elif [ -s "$PGDATA/PG_VERSION" ]; then
    # Compatibilidade com volume existente criado anteriormente
    PASS="vault"
else
    # Cluster novo: gera senha aleatoria forte
    PASS="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
fi
export POSTGRES_PASSWORD="$PASS"
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB}"

# Checagem rapida ANTES de gastar tempo subindo o Postgres: sem master
# key montada, nao ha motivo pra continuar o boot.
if [ "${VAULT_INIT_ONLY:-0}" != "1" ] && [ ! -f "$MASTER_KEY_FILE" ]; then
    echo "[VLT-1001] master key nao encontrada em $MASTER_KEY_FILE" >&2
    echo "Monte o arquivo gerado por 'vault-init init' nesse path e reinicie o container." >&2
    exit 1
fi

# --- sobe o Postgres embutido ---
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    if [ "$REPLICATION_ROLE" = "standby" ]; then
        echo "Modo STANDBY ativado. Aguardando primario em $PRIMARY_HOST:$PRIMARY_PORT..."
        if [ "$USE_TLS" = "1" ] && [ -f "$PGDATA/tls/client.crt" ]; then
            export PGSSLMODE="verify-full"
            export PGSSLROOTCERT="$PGDATA/tls/ca.crt"
            export PGSSLCERT="$PGDATA/tls/client.crt"
            export PGSSLKEY="$PGDATA/tls/client.key"
        fi
        until PGPASSWORD="$REPLICATION_PASSWORD" pg_isready -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$REPLICATION_USER" -q; do
            sleep 2
        done
        echo "Executando pg_basebackup inicial a partir do primario ($PRIMARY_HOST)..."
        mkdir -p "$PGDATA"
        chown -R postgres:postgres "$PGDATA"
        chmod 700 "$PGDATA"
        PGPASSWORD="$REPLICATION_PASSWORD" gosu postgres pg_basebackup \
            -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" -U "$REPLICATION_USER" \
            -D "$PGDATA" -Fp -Xs -R
        echo "pg_basebackup concluido com sucesso. Configurando standby..."
        if [ "$USE_TLS" = "1" ] && [ -f "$PGDATA/tls/client.crt" ]; then
            if [ -f "$PGDATA/postgresql.auto.conf" ]; then
                if ! grep -q "sslmode=verify-full" "$PGDATA/postgresql.auto.conf"; then
                    sed -i "s|primary_conninfo = '|primary_conninfo = 'sslmode=verify-full sslrootcert=$PGDATA/tls/ca.crt sslcert=$PGDATA/tls/client.crt sslkey=$PGDATA/tls/client.key |" "$PGDATA/postgresql.auto.conf"
                fi
            fi
        fi
        if [ -f "$DB_PASS_FILE" ]; then
            PASS="$(cat "$DB_PASS_FILE")"
            export POSTGRES_PASSWORD="$PASS"
            export DATABASE_URL="postgresql+psycopg2://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB"
            echo "$DATABASE_URL" > "$PGDATA/.database_url" 2>/dev/null || true
            chmod 600 "$PGDATA/.database_url" 2>/dev/null || true
            chown postgres:postgres "$PGDATA/.database_url" 2>/dev/null || true
        fi
    else
        echo "Inicializando cluster Postgres pela primeira vez..."
        mkdir -p "$PGDATA"
        chown -R postgres:postgres "$PGDATA"
        chmod 700 "$PGDATA"
        gosu postgres initdb -D "$PGDATA" > /dev/null

        echo "$POSTGRES_PASSWORD" > "$DB_PASS_FILE"
        chmod 600 "$DB_PASS_FILE"
        chown postgres:postgres "$DB_PASS_FILE"

        echo "$DATABASE_URL" > "$PGDATA/.database_url"
        chmod 600 "$PGDATA/.database_url"
        chown postgres:postgres "$PGDATA/.database_url"

        gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses='$POSTGRES_LISTEN_ADDRESSES' $PG_SSL_OPTS" -w start
        # Cria usuario da aplicacao sem privilégios de SUPERUSER (Principio do Menor Privilegio)
        gosu postgres psql --command "CREATE USER $POSTGRES_USER WITH NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$POSTGRES_PASSWORD';"
        gosu postgres psql --command "CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;"
        gosu postgres psql -d "$POSTGRES_DB" --command "GRANT ALL ON SCHEMA public TO $POSTGRES_USER;"
    fi
fi

# Assegura que .database_url existe no volume compartilhado
if [ -d "$PGDATA" ]; then
    echo "$DATABASE_URL" > "$PGDATA/.database_url" 2>/dev/null || true
    chmod 600 "$PGDATA/.database_url" 2>/dev/null || true
    chown postgres:postgres "$PGDATA/.database_url" 2>/dev/null || true
fi

chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
if ! gosu postgres pg_isready -q; then
    if ! gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses='$POSTGRES_LISTEN_ADDRESSES' $PG_SSL_OPTS" -w start; then
        echo "Aviso: falha ao iniciar Postgres. Tentando auto-recuperacao de checkpoint..." >&2
        gosu postgres pg_resetwal -f "$PGDATA"
        gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses='$POSTGRES_LISTEN_ADDRESSES' $PG_SSL_OPTS" -w start
    fi
fi

until gosu postgres pg_isready -q; do
    sleep 1
done

# Configura usuario de replicacao se este no for o primario
if [ "$REPLICATION_ROLE" = "primary" ]; then
    gosu postgres psql -d postgres -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$REPLICATION_USER') THEN CREATE ROLE $REPLICATION_USER WITH REPLICATION LOGIN PASSWORD '$REPLICATION_PASSWORD'; END IF; END \$\$;" > /dev/null 2>&1 || true
    if ! grep -q "replication $REPLICATION_USER" "$PGDATA/pg_hba.conf"; then
        if [ "$USE_TLS" = "1" ] && [ -f "$PGDATA/tls/ca.crt" ]; then
            echo "hostssl replication $REPLICATION_USER all cert clientcert=verify-full" >> "$PGDATA/pg_hba.conf"
        else
            echo "host replication $REPLICATION_USER all md5" >> "$PGDATA/pg_hba.conf"
        fi
        gosu postgres pg_ctl -D "$PGDATA" reload > /dev/null 2>&1 || true
    fi
fi

# Garante revogacao de SUPERUSER mesmo para bancos pre-existentes (se nao for replica em recovery)
if ! gosu postgres psql -d postgres -tAc "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q "t"; then
    gosu postgres psql -d postgres -c "ALTER ROLE \"$POSTGRES_USER\" WITH NOSUPERUSER NOCREATEDB NOCREATEROLE;" > /dev/null 2>&1 || true
fi

if [ "${VAULT_INIT_ONLY:-0}" = "1" ]; then
    echo "Postgres pronto para vault-init."
    touch /tmp/postgres-ready
    exec sleep infinity
fi

# --- checagem final de master key (formato + confere com o banco) roda
# dentro do proprio processo Python no import de vault.main / bootstrap.
# Se falhar aqui, o comando abaixo termina com exit != 0 e o container morre.
UVICORN_SSL_ARGS=()
if [ "$USE_TLS" = "1" ] && [ -f "$PGDATA/tls/server.crt" ] && [ -f "$PGDATA/tls/server.key" ]; then
    UVICORN_SSL_ARGS=(
        "--ssl-keyfile" "$PGDATA/tls/server.key"
        "--ssl-certfile" "$PGDATA/tls/server.crt"
    )
    if [ -f "$PGDATA/tls/ca.crt" ]; then
        UVICORN_SSL_ARGS+=("--ssl-ca-certs" "$PGDATA/tls/ca.crt")
    fi
fi
exec python -m uvicorn vault.main:app --host 0.0.0.0 --port 8000 "${UVICORN_SSL_ARGS[@]}"
