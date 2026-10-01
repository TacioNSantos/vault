from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from vault.database import get_db, is_database_in_recovery
from vault.models import AppIdentity, AuditLog
from vault.schemas import TokenRequest, TokenResponse
from vault import security
from vault.rate_limit import check_login_limit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def login(payload: TokenRequest, request: Request, db: Session = Depends(get_db)):
    app_identity = db.query(AppIdentity).filter(AppIdentity.name == payload.app_name).first()
    in_recovery = is_database_in_recovery()

    if not in_recovery:
        try:
            check_login_limit(db, request.client.host, app_identity.id if app_identity else None)
        except HTTPException as exc:
            db.add(AuditLog(app_id=app_identity.id if app_identity else payload.app_name,
                            action="auth.login", result="denied", source_ip=request.client.host,
                            detail="rate limit excedido"))
            db.commit()
            raise exc

    if not app_identity or not app_identity.active or not security.verify_app_secret(
        payload.app_secret, app_identity.secret_hash
    ):
        if not in_recovery:
            db.add(AuditLog(app_id=payload.app_name, action="auth.login", result="denied",
                             source_ip=request.client.host, detail="credenciais invalidas"))
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "VLT-2001", "message": "App ID ou secret invalidos"},
        )

    client_ip = security.extract_client_ip(request, app_identity.trust_proxy)
    if not security.ip_allowed(client_ip, app_identity.allowed_ip):
        if not in_recovery:
            db.add(AuditLog(app_id=app_identity.id, action="auth.login", result="denied",
                             source_ip=client_ip, detail="IP fora da allowlist"))
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error_code": "VLT-2002", "message": f"IP {client_ip} nao autorizado para este App ID"},
        )

    token, ttl = security.create_access_token(app_identity)
    if not in_recovery:
        db.add(AuditLog(app_id=app_identity.id, action="auth.login", result="success", source_ip=client_ip))
        db.commit()

    return TokenResponse(access_token=token, expires_in_seconds=ttl)
