from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from vault.database import get_db
from vault.models import AppIdentity
from vault.schemas import AppCreateRequest, AppCreateResponse, AppOut, AppRenameRequest
from vault import security
from vault import config
from vault.permissions import Permission
import secrets as pysecrets

router = APIRouter(prefix="/admin/apps", tags=["admin - app ids"])


@router.post("", response_model=AppCreateResponse, status_code=status.HTTP_201_CREATED)
def create_app(
    payload: AppCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(security.require_admin),
):
    if db.query(AppIdentity).filter(AppIdentity.name == payload.app_name).first():
        raise HTTPException(status_code=409, detail={"error_code": "VLT-2004", "message": "App ID com esse nome ja existe"})

    plain_secret = pysecrets.token_urlsafe(32)
    app_identity = AppIdentity(
        name=payload.app_name,
        secret_hash=security.hash_app_secret(plain_secret),
        allowed_ip=payload.allowed_ip,
        trust_proxy=payload.trust_proxy,
        is_admin=payload.is_admin,
    )
    app_identity.permissions = payload.permissions
    db.add(app_identity)
    db.add(security.audit_event(request, admin, "app.create", payload.app_name))
    db.commit()
    db.refresh(app_identity)

    # app_secret so aparece aqui, uma vez. Nao fica recuperavel depois.
    return AppCreateResponse(app_name=app_identity.name, app_secret=plain_secret)


@router.get("", response_model=list[AppOut])
def list_apps(db: Session = Depends(get_db), admin: AppIdentity = Depends(security.require_admin)):
    apps = db.query(AppIdentity).all()
    return [
        AppOut(
            app_name=a.name, allowed_ip=a.allowed_ip, trust_proxy=a.trust_proxy,
            permissions=[permission for permission in Permission if permission in a.permissions],
            is_admin=a.is_admin, active=a.active,
        )
        for a in apps
    ]


@router.delete("/{app_name}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_app(app_name: str, request: Request, db: Session = Depends(get_db), admin: AppIdentity = Depends(security.require_admin)):
    app_identity = db.query(AppIdentity).filter(AppIdentity.name == app_name).first()
    if not app_identity:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-2005", "message": "App ID nao encontrado"})
    app_identity.active = False
    db.add(security.audit_event(request, admin, "app.revoke", app_name))
    db.commit()
    return None


@router.patch("/{app_name}", response_model=AppOut)
def rename_app(
    app_name: str,
    payload: AppRenameRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(security.require_admin),
):
    # Desativado por padrao: grants e JWT usam UUID e sobrevivem ao rename, mas
    # clientes precisam atualizar o nome usado no login e nas chamadas da API.
    # Habilite somente apos coordenar a troca de nome com essas integracoes.
    if not config.ENABLE_APP_RENAME:
        raise HTTPException(status_code=403, detail={"error_code": "VLT-2006", "message": "renomeacao de apps desativada"})

    app_identity = db.query(AppIdentity).filter(AppIdentity.name == app_name).first()
    if not app_identity:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-2005", "message": "App ID nao encontrado"})
    if payload.new_app_name != app_name and db.query(AppIdentity).filter(AppIdentity.name == payload.new_app_name).first():
        raise HTTPException(status_code=409, detail={"error_code": "VLT-2004", "message": "App ID com esse nome ja existe"})
    app_identity.name = payload.new_app_name
    db.add(security.audit_event(request, admin, "app.rename", app_name,
                                detail=f"novo nome: {payload.new_app_name}"))
    db.commit()
    db.refresh(app_identity)
    return AppOut(
        app_name=app_identity.name, allowed_ip=app_identity.allowed_ip,
        trust_proxy=app_identity.trust_proxy,
        permissions=[permission for permission in Permission if permission in app_identity.permissions],
        is_admin=app_identity.is_admin, active=app_identity.active,
    )
