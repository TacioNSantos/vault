import uuid
import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, Integer,
    Index, LargeBinary, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from vault.database import Base
from vault.permissions import Permission, SECRET_PERMISSIONS


def gen_uuid():
    return str(uuid.uuid4())


class VaultConfig(Base):
    """Key/value simples pra guardar blobs de config criptografados
    (verification blob da master key, JWT signing key encriptada, etc)."""
    __tablename__ = "vault_config"

    key = Column(String, primary_key=True)
    value = Column(LargeBinary, nullable=False)


class AppIdentity(Base):
    """Um App ID = uma integracao (app externo, admin, futura UI etc)."""
    __tablename__ = "app_identities"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False, unique=True)
    secret_hash = Column(String, nullable=False)  # bcrypt hash do app secret

    # Controle de origem. allowed_ip aceita IP unico ou CIDR (ex: 10.0.0.0/24).
    allowed_ip = Column(String, nullable=False)
    trust_proxy = Column(Boolean, nullable=False, default=False)  # honra X-Forwarded-For

    is_admin = Column(Boolean, nullable=False, default=False)
    # Coluna legada preservada para volumes ja inicializados. A API usa Permission.
    _create_enabled = Column("can_create_secrets", Boolean, nullable=False, default=False)
    active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    secret_grants = relationship("SecretPermission", back_populates="app", cascade="all, delete-orphan")
    vault_grants = relationship("VaultPermission", back_populates="app", cascade="all, delete-orphan")

    @property
    def permissions(self) -> set[Permission]:
        return {Permission.Create} if self._create_enabled else set()

    @permissions.setter
    def permissions(self, values: set[Permission]):
        if set(values) - {Permission.Create}:
            raise ValueError("Somente Permission.Create e uma permissao global")
        self._create_enabled = Permission.Create in values


class Vault(Base):
    """Cofre real: cada secret pertence a um cofre pelo UUID, nao pelo prefixo."""
    __tablename__ = "vaults"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False, unique=True)
    secrets = relationship("Secret", back_populates="vault")
    permissions = relationship("VaultPermission", back_populates="vault", cascade="all, delete-orphan")


class VaultPermission(Base):
    __tablename__ = "vault_permissions"
    __table_args__ = (UniqueConstraint("vault_id", "app_id", name="uq_vault_app"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    vault_id = Column(UUID(as_uuid=False), ForeignKey("vaults.id"), nullable=False)
    app_id = Column(UUID(as_uuid=False), ForeignKey("app_identities.id"), nullable=False)
    _values = Column("permissions", ARRAY(String), nullable=False, default=list)

    vault = relationship("Vault", back_populates="permissions")
    app = relationship("AppIdentity", back_populates="vault_grants")

    @property
    def permissions(self) -> set[Permission]:
        return {Permission(value) for value in (self._values or [])}

    @permissions.setter
    def permissions(self, values: set[Permission]):
        self._values = [permission.value for permission in Permission if permission in values]


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False, unique=True)  # path logico, ex: app-x/db-password
    vault_id = Column(UUID(as_uuid=False), ForeignKey("vaults.id"), nullable=False)

    encrypted_dek = Column(LargeBinary, nullable=False)   # DEK criptografada pela master key
    ciphertext = Column(LargeBinary, nullable=False)      # valor do secret criptografado pela DEK

    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String, nullable=False)  # app_id de quem criou
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    updated_at = Column(DateTime, default=datetime.datetime.now(datetime.UTC), onupdate=datetime.datetime.now(datetime.UTC))

    permissions = relationship("SecretPermission", back_populates="secret", cascade="all, delete-orphan")
    vault = relationship("Vault", back_populates="secrets")
    versions = relationship("SecretVersion", back_populates="secret", cascade="all, delete-orphan", order_by="SecretVersion.version.desc()")


class SecretVersion(Base):
    """Historico de versoes de secrets."""
    __tablename__ = "secret_versions"
    __table_args__ = (UniqueConstraint("secret_id", "version", name="uq_secret_version"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    secret_id = Column(UUID(as_uuid=False), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)

    encrypted_dek = Column(LargeBinary, nullable=False)   # DEK criptografada pela master key
    ciphertext = Column(LargeBinary, nullable=False)      # valor do secret criptografado pela DEK

    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now(datetime.UTC))

    secret = relationship("Secret", back_populates="versions")


class SecretPermission(Base):
    """ACL: qual App ID pode fazer o que em qual secret."""
    __tablename__ = "secret_permissions"
    __table_args__ = (UniqueConstraint("secret_id", "app_id", name="uq_secret_app"),)

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    secret_id = Column(UUID(as_uuid=False), ForeignKey("secrets.id"), nullable=False)
    app_id = Column(UUID(as_uuid=False), ForeignKey("app_identities.id"), nullable=False)

    # Mantem o esquema existente; permissões sao usadas como conjunto na aplicacao.
    _read_enabled = Column("can_read", Boolean, nullable=False, default=False)
    _update_enabled = Column("can_update", Boolean, nullable=False, default=False)
    _delete_enabled = Column("can_delete", Boolean, nullable=False, default=False)

    secret = relationship("Secret", back_populates="permissions")
    app = relationship("AppIdentity", back_populates="secret_grants")

    @property
    def permissions(self) -> set[Permission]:
        return {
            permission for permission, enabled in (
                (Permission.Read, self._read_enabled),
                (Permission.Update, self._update_enabled),
                (Permission.Delete, self._delete_enabled),
            ) if enabled
        }

    @permissions.setter
    def permissions(self, values: set[Permission]):
        if set(values) - SECRET_PERMISSIONS:
            raise ValueError("Permission.Create nao e uma permissao por secret")
        self._read_enabled = Permission.Read in values
        self._update_enabled = Permission.Update in values
        self._delete_enabled = Permission.Delete in values


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_timestamp_id", "timestamp", "id"),
        Index("ix_audit_log_app_timestamp", "app_id", "timestamp"),
    )

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    timestamp = Column(DateTime, default=datetime.datetime.now(datetime.UTC))
    app_id = Column(String, nullable=True)
    action = Column(String, nullable=False)     # ex: secret.read, secret.create, auth.login
    resource = Column(String, nullable=True)    # nome do secret ou app afetado
    result = Column(String, nullable=False)     # success | denied | error
    source_ip = Column(String, nullable=True)
    detail = Column(String, nullable=True)


class AuthRateLimit(Base):
    """Janela compartilhada entre processos para tentativas de login."""
    __tablename__ = "auth_rate_limits"
    __table_args__ = (Index("ix_auth_rate_limits_window_started_at", "window_started_at"),)

    key = Column(String, primary_key=True)
    window_started_at = Column(DateTime, nullable=False)
    attempts = Column(Integer, nullable=False)
