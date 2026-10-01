from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from vault import bootstrap
from vault.database import is_database_in_recovery
from vault.routers import auth, apps, audit, secrets, vaults

# Checagem de master key roda ANTES do app aceitar qualquer request.
# Se falhar, run() chama sys.exit(1) e o processo morre aqui mesmo.
bootstrap.run()

app = FastAPI(
    title="Vault",
    version="1.0.0",
    description="Cofre de secrets com envelope encryption, App IDs e JWT de curta duracao.",
)


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
