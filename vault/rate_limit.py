"""Rate limit atômico do login, compartilhado pelo PostgreSQL."""

import hashlib
import math
import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from vault import config
from vault.models import AuthRateLimit


def check_login_limit(db: Session, peer_ip: str, app_id: str | None):
    now = datetime.utcnow()
    window = config.AUTH_RATE_WINDOW_SECONDS
    if window <= 0 or config.AUTH_RATE_LIMIT_IP <= 0 or config.AUTH_RATE_LIMIT_APP <= 0:
        raise RuntimeError("limites de autenticacao devem ser inteiros positivos")
    cutoff = now - timedelta(seconds=window)
    # IP vem da conexao (nao de X-Forwarded-For, que pode ser falsificado).
    # A segunda chave e o UUID do app, evitando uma linha por nome inventado.
    keys = [("ip:" + hashlib.sha256(peer_ip.encode()).hexdigest(), config.AUTH_RATE_LIMIT_IP)]
    if app_id is not None:
        keys.append(("app:" + app_id, config.AUTH_RATE_LIMIT_APP))

    exceeded = []
    for key, maximum in keys:
        expired = AuthRateLimit.window_started_at <= cutoff
        statement = insert(AuthRateLimit).values(key=key, window_started_at=now, attempts=1)
        statement = statement.on_conflict_do_update(
            index_elements=[AuthRateLimit.key],
            set_={
                "attempts": case((expired, 1), else_=AuthRateLimit.attempts + 1),
                "window_started_at": case((expired, now), else_=AuthRateLimit.window_started_at),
            },
        ).returning(AuthRateLimit.attempts, AuthRateLimit.window_started_at)
        attempts, started_at = db.execute(statement).one()
        if attempts > maximum:
            exceeded.append(math.ceil((started_at + timedelta(seconds=window) - now).total_seconds()))

    # Limpa janelas antigas ocasionalmente para nao acumular IPs indefinidamente.
    if secrets.randbelow(128) == 0:
        db.query(AuthRateLimit).filter(
            AuthRateLimit.window_started_at < now - timedelta(seconds=max(window * 2, 3600))
        ).delete(synchronize_session=False)
    db.commit()  # persiste inclusive as tentativas que ultrapassaram o limite

    if exceeded:
        retry_after = max(1, max(exceeded))
        raise HTTPException(
            status_code=429,
            detail={"error_code": "VLT-2007", "message": "muitas tentativas de login; tente novamente depois"},
            headers={"Retry-After": str(retry_after)},
        )
