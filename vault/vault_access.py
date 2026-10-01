from sqlalchemy.orm import Session

from vault.models import VaultPermission
from vault.permissions import Permission


def vault_permissions(db: Session, vault_id: str, app_id: str) -> set[Permission]:
    grant = db.query(VaultPermission).filter(
        VaultPermission.vault_id == vault_id, VaultPermission.app_id == app_id
    ).first()
    return grant.permissions if grant else set()
