from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from vault.database import get_db
from vault.models import AppIdentity, Secret, SecretPermission, Vault, VaultPermission
from vault.permissions import Permission
from vault.schemas import SecretOut, VaultCreateRequest, VaultOut, VaultPermissionGrant, VaultGrantOut
from vault.security import audit_event, get_current_app, require_admin
from vault.vault_access import vault_permissions


router = APIRouter(prefix="/vaults", tags=["vaults"])


@router.post("", response_model=VaultOut, status_code=status.HTTP_201_CREATED)
def create_vault(
    payload: VaultCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(require_admin),
):
    if db.query(Vault).filter(Vault.name == payload.name).first():
        raise HTTPException(status_code=409, detail={"error_code": "VLT-4002", "message": "cofre ja existe"})
    vault = Vault(name=payload.name)
    db.add(vault)
    db.add(audit_event(request, admin, "vault.create", payload.name))
    db.commit()
    return VaultOut(name=vault.name)


@router.get("", response_model=list[VaultOut])
def list_vaults(db: Session = Depends(get_db), app: AppIdentity = Depends(get_current_app)):
    query = db.query(Vault)
    if not app.is_admin and Permission.Create not in app.permissions:
        vault_ids = {
            grant.vault_id for grant in db.query(VaultPermission).filter(VaultPermission.app_id == app.id)
            if grant.permissions
        }
        vault_ids.update(
            vault_id for (vault_id,) in db.query(Secret.vault_id).join(SecretPermission).filter(
                SecretPermission.app_id == app.id, SecretPermission._read_enabled.is_(True)
            ).distinct()
        )
        query = query.filter(Vault.id.in_(vault_ids))
    return [VaultOut(name=vault.name) for vault in query.order_by(Vault.name)]


@router.post("/{vault_name}/permissions", status_code=status.HTTP_204_NO_CONTENT)
def grant_vault_permission(
    vault_name: str,
    grant: VaultPermissionGrant,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(require_admin),
):
    vault = db.query(Vault).filter(Vault.name == vault_name).first()
    if not vault:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-4001", "message": "cofre nao encontrado"})
    app = db.query(AppIdentity).filter(AppIdentity.name == grant.app_name).first()
    if not app:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-2005", "message": "app nao encontrado"})
    permission = db.query(VaultPermission).filter(
        VaultPermission.vault_id == vault.id, VaultPermission.app_id == app.id
    ).first()
    if not permission:
        permission = VaultPermission(vault_id=vault.id, app_id=app.id)
        db.add(permission)
    permission.permissions = grant.permissions
    db.add(audit_event(request, admin, "vault.permission_grant", vault_name))
    db.commit()
    return None


@router.get("/{vault_name}/permissions", response_model=list[VaultGrantOut])
def list_vault_permissions(
    vault_name: str,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(require_admin),
):
    vault = db.query(Vault).filter(Vault.name == vault_name).first()
    if not vault:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-4001", "message": "cofre nao encontrado"})
    grants = db.query(VaultPermission).join(AppIdentity).filter(
        VaultPermission.vault_id == vault.id
    ).order_by(AppIdentity.name).all()
    return [VaultGrantOut(
        app_name=grant.app.name,
        permissions=[permission for permission in Permission if permission in grant.permissions],
    ) for grant in grants]


@router.get("/{vault_name}/secrets", response_model=list[SecretOut])
def list_vault_secrets(
    vault_name: str,
    db: Session = Depends(get_db),
    app: AppIdentity = Depends(get_current_app),
):
    vault = db.query(Vault).filter(Vault.name == vault_name).first()
    if not vault:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-4001", "message": "cofre nao encontrado"})
    if app.is_admin or Permission.Read in vault_permissions(db, vault.id, app.id):
        secrets = db.query(Secret).filter(Secret.vault_id == vault.id).order_by(Secret.name).all()
    else:
        secrets = db.query(Secret).join(SecretPermission).filter(
            Secret.vault_id == vault.id,
            SecretPermission.app_id == app.id,
            SecretPermission._read_enabled.is_(True),
        ).order_by(Secret.name).all()
    return [SecretOut(id=secret.id, name=secret.name, version=secret.version) for secret in secrets]
