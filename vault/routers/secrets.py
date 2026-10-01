from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from vault.database import get_db, is_database_in_recovery
from vault.models import Secret, SecretPermission, AppIdentity, Vault
from vault.schemas import SecretCreateRequest, SecretUpdateRequest, SecretOut, SecretValueOut, PermissionGrant
from vault import security, crypto
from vault.security import MasterKeyHolder
from vault.permissions import Permission, SECRET_PERMISSIONS
from vault.vault_access import vault_permissions
from vault.vault_paths import vault_name_from_secret

router = APIRouter(prefix="/secrets", tags=["secrets"])


def _get_permission(db: Session, secret_id: str, app_id: str) -> SecretPermission | None:
    return db.query(SecretPermission).filter(
        SecretPermission.secret_id == secret_id, SecretPermission.app_id == app_id
    ).first()


def _has_permission(db: Session, secret: Secret, app: AppIdentity, permission: Permission) -> bool:
    if app.is_admin or permission in vault_permissions(db, secret.vault_id, app.id):
        return True
    grant = _get_permission(db, secret.id, app.id)
    return grant is not None and permission in grant.permissions


@router.post("", response_model=SecretOut, status_code=status.HTTP_201_CREATED)
def create_secret(
    request: Request,
    payload: SecretCreateRequest = Body(openapi_examples={
        "simples": {
            "summary": "Criar sem compartilhar",
            "value": {"name": "financeiro/minha-chave", "value": "<valor-do-secret>"},
        },
        "compartilhado": {
            "summary": "Criar e compartilhar com outra integracao",
            "value": {
                "name": "financeiro/minha-chave",
                "value": "<valor-do-secret>",
                "permissions": [{"app_name": "app-leitora", "permissions": ["read"]}],
            },
        },
    }),
    db: Session = Depends(get_db),
    app_identity: AppIdentity = Depends(security.get_current_app),
):
    try:
        vault_name = vault_name_from_secret(payload.name)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    vault = db.query(Vault).filter(Vault.name == vault_name).first()
    if not vault:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-4001", "message": "cofre nao encontrado"})
    if not (app_identity.is_admin or Permission.Create in app_identity.permissions
            or Permission.Create in vault_permissions(db, vault.id, app_identity.id)):
        raise HTTPException(status_code=403, detail={"error_code": "VLT-3002", "message": "App ID sem permissao de criar secrets"})

    if db.query(Secret).filter(Secret.name == payload.name).first():
        raise HTTPException(status_code=409, detail={"error_code": "VLT-3003", "message": "secret com esse nome ja existe"})

    dek = crypto.generate_key()
    encrypted_dek = crypto.encrypt_dek(MasterKeyHolder.get_master_key(), dek)
    ciphertext = crypto.encrypt(dek, payload.value.encode("utf-8"))

    secret = Secret(
        name=payload.name,
        vault_id=vault.id,
        encrypted_dek=encrypted_dek,
        ciphertext=ciphertext,
        created_by=app_identity.id,
    )
    db.add(secret)
    db.flush()  # pega o id gerado antes do commit

    # quem cria sempre recebe full access ao proprio secret
    owner_grant = SecretPermission(secret_id=secret.id, app_id=app_identity.id)
    owner_grant.permissions = SECRET_PERMISSIONS
    db.add(owner_grant)

    for grant in (payload.permissions or []):
        target_app = db.query(AppIdentity).filter(AppIdentity.name == grant.app_name).first()
        if not target_app:
            raise HTTPException(status_code=404, detail={"error_code": "VLT-2005", "message": f"App {grant.app_name} nao encontrado"})
        permission = SecretPermission(secret_id=secret.id, app_id=target_app.id)
        permission.permissions = grant.permissions
        db.add(permission)

    db.add(security.audit_event(request, app_identity, "secret.create", payload.name))
    db.commit()
    db.refresh(secret)
    return SecretOut(id=secret.id, name=secret.name, version=secret.version)


@router.get("/{name:path}", response_model=SecretValueOut)
def read_secret(name: str, request: Request, db: Session = Depends(get_db), app_identity: AppIdentity = Depends(security.get_current_app)):
    secret = db.query(Secret).filter(Secret.name == name).first()
    if not secret:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-3001", "message": "secret nao encontrado"})

    if not _has_permission(db, secret, app_identity, Permission.Read):
        if not is_database_in_recovery():
            db.add(security.audit_event(request, app_identity, "secret.read", name, result="denied"))
            db.commit()
        raise HTTPException(status_code=403, detail={"error_code": "VLT-3002", "message": "App ID sem permissao de leitura neste secret"})

    dek = crypto.decrypt_dek(MasterKeyHolder.get_master_key(), secret.encrypted_dek)
    value = crypto.decrypt(dek, secret.ciphertext).decode("utf-8")

    if not is_database_in_recovery():
        db.add(security.audit_event(request, app_identity, "secret.read", name))
        db.commit()
    return SecretValueOut(id=secret.id, name=secret.name, version=secret.version, value=value)


@router.put("/{name:path}", response_model=SecretOut)
def update_secret(
    name: str,
    payload: SecretUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    app_identity: AppIdentity = Depends(security.get_current_app),
):
    secret = db.query(Secret).filter(Secret.name == name).first()
    if not secret:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-3001", "message": "secret nao encontrado"})

    if not _has_permission(db, secret, app_identity, Permission.Update):
        db.add(security.audit_event(request, app_identity, "secret.update", name, result="denied"))
        db.commit()
        raise HTTPException(status_code=403, detail={"error_code": "VLT-3002", "message": "App ID sem permissao de update neste secret"})

    # rotaciona a DEK a cada update, nao so o ciphertext
    dek = crypto.generate_key()
    secret.encrypted_dek = crypto.encrypt_dek(MasterKeyHolder.get_master_key(), dek)
    secret.ciphertext = crypto.encrypt(dek, payload.value.encode("utf-8"))
    secret.version += 1

    db.add(security.audit_event(request, app_identity, "secret.update", name))
    db.commit()
    db.refresh(secret)
    return SecretOut(id=secret.id, name=secret.name, version=secret.version)


@router.delete("/{name:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(name: str, request: Request, db: Session = Depends(get_db), app_identity: AppIdentity = Depends(security.get_current_app)):
    secret = db.query(Secret).filter(Secret.name == name).first()
    if not secret:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-3001", "message": "secret nao encontrado"})

    if not _has_permission(db, secret, app_identity, Permission.Delete):
        db.add(security.audit_event(request, app_identity, "secret.delete", name, result="denied"))
        db.commit()
        raise HTTPException(status_code=403, detail={"error_code": "VLT-3002", "message": "App ID sem permissao de delete neste secret"})

    db.add(security.audit_event(request, app_identity, "secret.delete", name))
    db.delete(secret)
    db.commit()
    return None


@router.post("/{name:path}/permissions", status_code=status.HTTP_204_NO_CONTENT)
def grant_permission(
    name: str,
    grant: PermissionGrant,
    request: Request,
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(security.require_admin),
):
    secret = db.query(Secret).filter(Secret.name == name).first()
    if not secret:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-3001", "message": "secret nao encontrado"})

    target_app = db.query(AppIdentity).filter(AppIdentity.name == grant.app_name).first()
    if not target_app:
        raise HTTPException(status_code=404, detail={"error_code": "VLT-2005", "message": f"App {grant.app_name} nao encontrado"})

    perm = _get_permission(db, secret.id, target_app.id)
    if perm:
        perm.permissions = grant.permissions
    else:
        perm = SecretPermission(secret_id=secret.id, app_id=target_app.id)
        perm.permissions = grant.permissions
        db.add(perm)
    db.add(security.audit_event(request, admin, "secret.permission_grant", name))
    db.commit()
    return None
