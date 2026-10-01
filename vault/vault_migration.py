"""Adiciona cofres a bancos existentes sem recriar secrets nem a master key."""

from sqlalchemy import inspect, text

from vault.database import Base, SessionLocal, engine
from vault.models import AuthRateLimit, Secret, Vault, VaultPermission
from vault.vault_paths import legacy_vault_name


def ensure_vaults():
    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection, tables=[
            Vault.__table__, VaultPermission.__table__, AuthRateLimit.__table__,
        ])
        # create_all nao adiciona indices a tabelas existentes.
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_audit_log_timestamp_id ON audit_log (timestamp, id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_audit_log_app_timestamp ON audit_log (app_id, timestamp)"
        ))
        if "vault_id" not in {column["name"] for column in inspect(connection).get_columns("secrets")}:
            connection.execute(text("ALTER TABLE secrets ADD COLUMN vault_id UUID"))
            connection.execute(text(
                "ALTER TABLE secrets ADD CONSTRAINT fk_secrets_vault_id "
                "FOREIGN KEY (vault_id) REFERENCES vaults(id)"
            ))

    db = SessionLocal()
    try:
        vaults = {vault.name: vault for vault in db.query(Vault).all()}
        for secret in db.query(Secret).filter(Secret.vault_id.is_(None)):
            name = legacy_vault_name(secret.name)
            if name not in vaults:
                vaults[name] = Vault(name=name)
                db.add(vaults[name])
                db.flush()
            secret.vault_id = vaults[name].id
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    with engine.begin() as connection:
        vault_id_column = next(
            column for column in inspect(connection).get_columns("secrets")
            if column["name"] == "vault_id"
        )
        if vault_id_column["nullable"]:
            connection.execute(text("ALTER TABLE secrets ALTER COLUMN vault_id SET NOT NULL"))
