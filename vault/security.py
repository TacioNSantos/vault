"""
Tudo que toca segredo em memoria ou identidade fica aqui.

MasterKeyHolder: guarda a master key SOMENTE em memoria de processo.
Nunca eh escrita em log, em disco, ou serializada em qualquer resposta.
"""
import ipaddress
import datetime
import bcrypt
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from vault import config
from vault.database import get_db
from vault.models import AppIdentity, AuditLog


class MasterKeyHolder:
    """Singleton simples em memoria de processo. Setado uma vez no
    startup (vault/bootstrap.py) e nunca mais escrito."""
    _key: bytes = None
    _jwt_signing_key: bytes = None

    @classmethod
    def set_master_key(cls, key: bytes):
        cls._key = key

    @classmethod
    def get_master_key(cls) -> bytes:
        if cls._key is None:
            # Isso nao deveria ser alcancavel: bootstrap.py aborta o boot
            # antes de subir a API se a master key nao estiver carregada.
            raise RuntimeError("master key nao carregada em memoria")
        return cls._key

    @classmethod
    def set_jwt_signing_key(cls, key: bytes):
        cls._jwt_signing_key = key

    @classmethod
    def get_jwt_signing_key(cls) -> bytes:
        if cls._jwt_signing_key is None:
            raise RuntimeError("jwt signing key nao carregada em memoria")
        return cls._jwt_signing_key


# ---------- App secret hashing ----------

def hash_app_secret(plain_secret: str) -> str:
    return bcrypt.hashpw(plain_secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_app_secret(plain_secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_secret.encode("utf-8"), hashed.encode("utf-8"))


# ---------- IP / proxy validation ----------

def extract_client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # primeiro IP da cadeia = cliente original
            return forwarded.split(",")[0].strip()
    return request.client.host


def ip_allowed(client_ip: str, allowed_ip_or_cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(allowed_ip_or_cidr, strict=False)
        return ipaddress.ip_address(client_ip) in network
    except ValueError:
        return client_ip == allowed_ip_or_cidr


def audit_event(request: Request, app: AppIdentity, action: str, resource: str | None = None,
                result: str = "success", detail: str | None = None) -> AuditLog:
    """Registra a identidade da integração e o IP efetivo em ações autenticadas."""
    return AuditLog(
        app_id=app.id, action=action, resource=resource, result=result,
        source_ip=extract_client_ip(request, app.trust_proxy), detail=detail,
    )


# ---------- JWT ----------

def create_access_token(app: AppIdentity) -> tuple[str, int]:
    ttl_seconds = config.JWT_TTL_MINUTES * 60
    now = datetime.datetime.utcnow()
    payload = {
        "sub": app.id,
        "name": app.name,
        "is_admin": app.is_admin,
        "permissions": sorted(permission.value for permission in app.permissions),
        "iat": now,
        "exp": now + datetime.timedelta(seconds=ttl_seconds),
    }
    token = jwt.encode(payload, MasterKeyHolder.get_jwt_signing_key().hex(), algorithm=config.JWT_ALGORITHM)
    return token, ttl_seconds


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, MasterKeyHolder.get_jwt_signing_key().hex(), algorithms=[config.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "VLT-2003", "message": "token invalido ou expirado"},
        )


# ---------- FastAPI dependencies ----------

bearer_auth = HTTPBearer(auto_error=False)


def get_current_app(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_auth),
    db: Session = Depends(get_db),
) -> AppIdentity:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "VLT-2003", "message": "header Authorization Bearer ausente"},
        )
    claims = decode_access_token(credentials.credentials)

    app_identity = db.query(AppIdentity).filter(AppIdentity.id == claims["sub"]).first()
    if not app_identity or not app_identity.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "VLT-2003", "message": "App ID inexistente ou desativado"},
        )

    # revalida IP a cada chamada, nao so no login
    client_ip = extract_client_ip(request, app_identity.trust_proxy)
    if not ip_allowed(client_ip, app_identity.allowed_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "VLT-2002", "message": f"IP {client_ip} nao autorizado para este App ID"},
        )
    return app_identity


def require_admin(app_identity: AppIdentity = Depends(get_current_app)) -> AppIdentity:
    if not app_identity.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "VLT-3002", "message": "acao requer App ID admin"},
        )
    return app_identity
