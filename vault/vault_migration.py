"""Adiciona cofres a bancos existentes sem recriar secrets nem a master key."""

from sqlalchemy import inspect, text

from vault.database import Base, SessionLocal, engine
from vault.models import AuthRateLimit, Secret, SecretVersion, Vault, VaultPermission
from vault.vault_paths import legacy_vault_name


def ensure_vaults():
    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection, tables=[
            Vault.__table__, VaultPermission.__table__, AuthRateLimit.__table__, SecretVersion.__table__,
        ])
        # create_all nao adiciona indices a tabelas existentes.
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_audit_log_timestamp_id ON audit_log (timestamp, id)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_audit_log_app_timestamp ON audit_log (app_id, timestamp)"
        ))
        connection.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_secret_versions_secret_id_version ON secret_versions (secret_id, version)"
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

        # Backfill de versoes existentes na tabela secret_versions
        for secret in db.query(Secret).all():
            has_ver = db.query(SecretVersion).filter(
                SecretVersion.secret_id == secret.id,
                SecretVersion.version == secret.version,
            ).first()
            if not has_ver and secret.encrypted_dek and secret.ciphertext:
                db.add(SecretVersion(
                    secret_id=secret.id,
                    version=secret.version,
                    encrypted_dek=secret.encrypted_dek,
                    ciphertext=secret.ciphertext,
                    created_by=secret.created_by,
                    created_at=secret.updated_at or secret.created_at,
                ))

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
