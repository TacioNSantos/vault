from datetime import datetime
from typing import Literal, Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from vault.permissions import Permission, SECRET_PERMISSIONS


APP_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_name: str
    app_secret: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class AppCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_name: str = Field(min_length=1, pattern=APP_NAME_PATTERN)
    allowed_ip: str          # IP unico ou CIDR, ex "10.0.0.5" ou "10.0.0.0/24"
    trust_proxy: bool = False
    permissions: set[Permission] = Field(default_factory=set)
    is_admin: bool = False

    @field_validator("permissions")
    @classmethod
    def only_global_permissions(cls, value: set[Permission]) -> set[Permission]:
        if value - {Permission.Create}:
            raise ValueError("App ID aceita apenas a permissao global 'create'")
        return value


class AppCreateResponse(BaseModel):
    app_name: str
    app_secret: str          # devolvido em texto puro SOMENTE nesta resposta, uma vez


class AppOut(BaseModel):
    app_name: str
    allowed_ip: str
    trust_proxy: bool
    permissions: list[Permission]
    is_admin: bool
    active: bool


class PermissionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_name: str = Field(description="Nome de outra integracao que recebera acesso; opcional ao criar o secret.")
    permissions: set[Permission] = Field(
        default_factory=set,
        description="Neste secret: apenas read, update e delete. Create e uma permissao do cofre ou do app.",
    )

    @field_validator("permissions")
    @classmethod
    def only_secret_permissions(cls, value: set[Permission]) -> set[Permission]:
        if value - SECRET_PERMISSIONS:
            raise ValueError("Permissoes por secret aceitam apenas read, update e delete")
        return value


class AppRenameRequest(BaseModel):
    new_app_name: str = Field(min_length=1, pattern=APP_NAME_PATTERN)


class VaultCreateRequest(BaseModel):
    name: str = Field(min_length=1, pattern=APP_NAME_PATTERN)


class VaultOut(BaseModel):
    name: str


class VaultPermissionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_name: str
    permissions: set[Permission] = Field(default_factory=set)


class VaultGrantOut(BaseModel):
    app_name: str
    permissions: list[Permission]


class SecretCreateRequest(BaseModel):
    name: str = Field(description="Caminho cofre/secret; o cofre precisa existir.")
    value: str
    permissions: Optional[List[PermissionGrant]] = Field(
        default=None,
        description="Opcional: compartilhar o novo secret. O criador e identificado pelo token e ja recebe acesso completo.",
    )


class SecretUpdateRequest(BaseModel):
    value: str


class SecretOut(BaseModel):
    id: str
    name: str
    version: int


class SecretValueOut(BaseModel):
    id: str
    name: str
    version: int
    value: str


class AuditEventOut(BaseModel):
    id: str
    timestamp: datetime
    app_name: str | None
    action: str
    resource: str | None
    result: Literal["success", "denied", "error"]
    source_ip: str | None
    detail: str | None


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int
