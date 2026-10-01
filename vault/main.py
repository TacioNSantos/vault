import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from vault import bootstrap, security
from vault.database import is_database_in_recovery, SessionLocal
from vault.models import AppIdentity
from vault.routers import auth, apps, audit, secrets, vaults

# Checagem de master key roda ANTES do app aceitar qualquer request.
# Se falhar, run() chama sys.exit(1) e o processo morre aqui mesmo.
bootstrap.run()

app = FastAPI(
    title="Vault",
    version="1.0.0",
    description="Cofre de secrets com envelope encryption, App IDs e JWT de curta duracao.",
)

DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}


@app.middleware("http")
async def restrict_docs_to_admin(request: Request, call_next):
    # Protege a documentacao interativa e o schema OpenAPI contra acessos nao-admin
    if request.url.path in DOCS_PATHS:
        # Se DOCS_ALLOWED_IP estiver definido no env, checa ele prioritariamente
        env_allowed_ip = os.environ.get("DOCS_ALLOWED_IP")
        if env_allowed_ip:
            client_ip = request.client.host if request.client else "127.0.0.1"
            if not security.ip_allowed(client_ip, env_allowed_ip):
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            return await call_next(request)

        # Senao, restringe exclusivamente aos IPs/CIDRs cadastrados para os admins ativos
        db = SessionLocal()
        try:
            admins = db.query(AppIdentity).filter(
                AppIdentity.is_admin == True,
                AppIdentity.active == True,
            ).all()
            allowed = False
            for admin in admins:
                client_ip = security.extract_client_ip(request, admin.trust_proxy)
                if security.ip_allowed(client_ip, admin.allowed_ip):
                    allowed = True
                    break
            if not allowed:
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
        except Exception:
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        finally:
            db.close()

    return await call_next(request)


@app.middleware("http")
async def block_writes_on_standby(request: Request, call_next):
    # Bloqueia escritas se o no for replica/standby em recuperacao (read-only)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.url.path not in ("/auth/token",) and is_database_in_recovery():
            return JSONResponse(
                status_code=421,
                content={
                    "detail": {
                        "error_code": "VLT-5001",
                        "message": "este no esta em modo standby (somente leitura); direcione escritas para o primario",
                    }
                },
            )
    return await call_next(request)


app.include_router(auth.router)
app.include_router(apps.router)
app.include_router(audit.router)
app.include_router(vaults.router)
app.include_router(secrets.router)


@app.get("/health")
def health():
    in_recovery = is_database_in_recovery()
    return {
        "status": "ok",
        "role": "standby" if in_recovery else "primary",
        "read_only": in_recovery,
    }
