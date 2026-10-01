"""
Configuracao central do Vault. Tudo vem de env var, nada hardcoded.
"""
import os

# Onde o arquivo da master key deve estar montado dentro do container.
# Se nao existir nesse path no boot, o container NAO sobe (ver bootstrap.py).
MASTER_KEY_FILE = os.environ.get("MASTER_KEY_FILE", "/run/secrets/master.key")

# Postgres roda dentro do mesmo container (all-in-one appliance).
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg2://vault:vault@localhost:5432/vault",
)

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
