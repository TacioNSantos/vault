"""
Roda ANTES da API subir. Se qualquer checagem falhar, o processo termina
com exit code != 0 e uma mensagem [VLT-XXXX] no stderr. O container nunca
deve ficar de pe "meio funcional" com master key errada ou ausente.

Uso:
    python -m vault.bootstrap        # roda as checagens e sai 0 se tudo ok
Chamado tambem a partir de vault/main.py no startup do FastAPI, para
carregar a master key e a JWT signing key em memoria antes de aceitar
requests.
"""
import sys
import base64

from vault import config, crypto
from vault.security import MasterKeyHolder
from vault.database import SessionLocal, is_database_in_recovery
from vault.models import VaultConfig
from vault.vault_migration import ensure_vaults


class BootstrapError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


def load_master_key_from_file() -> bytes:
    try:
        with open(config.MASTER_KEY_FILE, "r") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        raise BootstrapError(
            "VLT-1001",
            f"master key nao encontrada em {config.MASTER_KEY_FILE}. "
            f"Monte o arquivo gerado pelo 'vault-init' nesse path antes de subir o container.",
        )

    try:
        key_bytes = base64.b64decode(raw)
    except Exception:
        raise BootstrapError("VLT-1002", "master key com formato invalido (esperado base64)")

    if len(key_bytes) != crypto.KEY_SIZE:
        raise BootstrapError(
            "VLT-1002",
            f"master key com tamanho invalido: {len(key_bytes)} bytes (esperado {crypto.KEY_SIZE})",
        )
    return key_bytes


def verify_master_key_and_load_jwt_key(master_key: bytes) -> bytes:
    try:
        db = SessionLocal()
    except Exception as e:
        raise BootstrapError("VLT-1003", f"falha ao conectar no Postgres: {e}")

    try:
        try:
            verification_row = db.query(VaultConfig).filter(
                VaultConfig.key == config.VERIFICATION_CONFIG_KEY
            ).first()
            jwt_key_row = db.query(VaultConfig).filter(
                VaultConfig.key == config.JWT_SIGNING_KEY_CONFIG_KEY
            ).first()
        except Exception as e:
            raise BootstrapError(
                "VLT-1005",
                f"vault nao inicializado ou tabelas ausentes: execute 'vaultctl configure primary' antes do start ({e})",
            )

        if not verification_row or not jwt_key_row:
            raise BootstrapError(
                "VLT-1005",
                "vault nao inicializado: execute 'vaultctl configure primary' antes do primeiro start.",
            )

        try:
            plaintext = crypto.decrypt(master_key, verification_row.value)
        except Exception:
            raise BootstrapError(
                "VLT-1004",
                "master key fornecida nao confere com a gravada no setup. "
                "Arquivo de master key errado montado neste container?",
            )

        if plaintext != config.VERIFICATION_PLAINTEXT:
            raise BootstrapError("VLT-1004", "master key falhou na verificacao de integridade")

        jwt_signing_key = crypto.decrypt(master_key, jwt_key_row.value)
        return jwt_signing_key
    finally:
        db.close()


def run() -> bytes:
    """Executa toda a checagem. Retorna a master key carregada, ou
    termina o processo (sys.exit) em caso de falha."""
    try:
        master_key = load_master_key_from_file()
        jwt_signing_key = verify_master_key_and_load_jwt_key(master_key)
        if not is_database_in_recovery():
            ensure_vaults()
    except BootstrapError as e:
        sys.stderr.write(f"[{e.code}] {e.message}\n")
        sys.exit(1)

    MasterKeyHolder.set_master_key(master_key)
    MasterKeyHolder.set_jwt_signing_key(jwt_signing_key)
    sys.stderr.write("[VLT-0000] master key carregada e verificada com sucesso.\n")
    return master_key


if __name__ == "__main__":
    run()
