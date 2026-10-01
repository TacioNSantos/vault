"""Consulta paginada de eventos, restrita a administradores."""

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from vault.database import get_db
from vault.models import AppIdentity, AuditLog
from vault.schemas import AuditEventOut, AuditPage
from vault.security import require_admin


router = APIRouter(prefix="/admin/audit", tags=["admin - audit"])


def utc_naive(value: datetime) -> datetime:
    """Colunas antigas são timestamp sem timezone, sempre em UTC."""
    if value.tzinfo:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


@router.get("", response_model=AuditPage)
def list_audit(
    app_name: str | None = None,
    action: str | None = None,
    result: Literal["success", "denied", "error"] | None = None,
    resource: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: AppIdentity = Depends(require_admin),
):
    if since and until and utc_naive(since) > utc_naive(until):
        raise HTTPException(status_code=422, detail="since deve ser anterior a until")

    query = db.query(AuditLog)
    if app_name is not None:
        app = db.query(AppIdentity).filter(AppIdentity.name == app_name).first()
        # Tentativas de login inválidas guardam o nome digitado; eventos de
        # apps existentes guardam o UUID. Buscar os dois inclui ambos.
        query = query.filter(AuditLog.app_id.in_([app_name, app.id] if app else [app_name]))
    if action is not None:
        query = query.filter(AuditLog.action == action)
    if result is not None:
        query = query.filter(AuditLog.result == result)
    if resource is not None:
        query = query.filter(AuditLog.resource == resource)
    if since is not None:
        query = query.filter(AuditLog.timestamp >= utc_naive(since))
    if until is not None:
        query = query.filter(AuditLog.timestamp <= utc_naive(until))

    total = query.count()
    events = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).offset(offset).limit(limit).all()

    ids = set()
    for event in events:
        if event.app_id:
            try:
                ids.add(str(UUID(event.app_id)))
            except ValueError:
                pass  # app_id de login negado é o nome digitado
    names = dict(db.query(AppIdentity.id, AppIdentity.name).filter(AppIdentity.id.in_(ids)).all()) if ids else {}

    return AuditPage(
        items=[AuditEventOut(
            id=event.id,
            timestamp=event.timestamp.replace(tzinfo=timezone.utc),
            app_name=names.get(event.app_id, event.app_id),
            action=event.action,
            resource=event.resource,
            result=event.result,
            source_ip=event.source_ip,
            detail=event.detail,
        ) for event in events],
        total=total,
        limit=limit,
        offset=offset,
    )
