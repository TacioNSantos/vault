"""
Configuracao central do Vault. Tudo vem de env var, nada hardcoded.
"""
import os

# Onde o arquivo da master key deve estar montado dentro do container.
# Se nao existir nesse path no boot, o container NAO sobe (ver bootstrap.py).
MASTER_KEY_FILE = os.environ.get("MASTER_KEY_FILE", "/run/secrets/master.key")


def _get_database_url() -> str:
    # 1. Respeita env var explicita
    url = os.environ.get("DATABASE_URL")
    if url:
        return url

    # 2. Tenta ler URL gravada pelo entrypoint no volume compartilhado
    pgdata = os.environ.get("PGDATA", "/var/lib/postgresql/data")
    db_url_file = os.path.join(pgdata, ".database_url")
    if os.path.isfile(db_url_file):
        try:
            with open(db_url_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass

    # 3. Tenta ler a credencial segura salva no volume do Postgres
    pw_file = os.path.join(pgdata, ".db_password")
    user = os.environ.get("POSTGRES_USER", "vault")
    db = os.environ.get("POSTGRES_DB", "vault")
    password = "vault"
    if os.path.isfile(pw_file):
        try:
            with open(pw_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    password = content
        except Exception:
            pass

    return f"postgresql+psycopg2://{user}:{password}@localhost:5432/{db}"


# Postgres roda dentro do mesmo container (all-in-one appliance).
DATABASE_URL = _get_database_url()

# Duracao padrao do JWT emitido para App IDs.
JWT_TTL_MINUTES = int(os.environ.get("JWT_TTL_MINUTES", "15"))

# Limites compartilhados pelo Postgres para POST /auth/token.
AUTH_RATE_WINDOW_SECONDS = int(os.environ.get("AUTH_RATE_WINDOW_SECONDS", "60"))
AUTH_RATE_LIMIT_IP = int(os.environ.get("AUTH_RATE_LIMIT_IP", "30"))
AUTH_RATE_LIMIT_APP = int(os.environ.get("AUTH_RATE_LIMIT_APP", "10"))

# Rename exige coordenar a mudanca do nome de login em todos os clientes.
# A rota existe, mas nao altera dados enquanto esta flag estiver desativada.
ENABLE_APP_RENAME = os.environ.get("ENABLE_APP_RENAME", "false").lower() == "true"

# Algoritmo de assinatura do JWT.
JWT_ALGORITHM = "HS256"

# String de verificacao usada para confirmar que a master key fornecida
# no boot eh a mesma usada no vault-init (sem isso, uma master key errada
# subiria o vault "funcionando" mas incapaz de decriptar nada).
VERIFICATION_PLAINTEXT = b"VAULT_MASTER_KEY_OK"
VERIFICATION_CONFIG_KEY = "master_key_verification_blob"
JWT_SIGNING_KEY_CONFIG_KEY = "jwt_signing_key_encrypted"
