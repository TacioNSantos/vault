"""CLI interna para promover um no PostgreSQL de standby (replica) para primario."""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

import click


def find_pg_ctl() -> str:
    found = shutil.which("pg_ctl")
    if found:
        return found
    candidates = glob.glob("/usr/lib/postgresql/*/bin/pg_ctl")
    if candidates:
        return candidates[0]
    return "pg_ctl"


def get_primary_host(data_dir: str) -> str | None:
    host = os.environ.get("PRIMARY_HOST")
    if host:
        return host
    auto_conf = os.path.join(data_dir, "postgresql.auto.conf")
    if os.path.isfile(auto_conf):
        try:
            with open(auto_conf, "r", encoding="utf-8") as f:
                content = f.read()
            match = re.search(r"host=([^\s\'\"]+)", content)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None


def check_primary_is_active_master(primary_host: str, primary_port: int = 5432, primary_api_port: int = 443) -> bool:
    # 1. Checa a API /health do primario via HTTPS / HTTP
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for proto in ("https", "http"):
        try:
            url = f"{proto}://{primary_host}:{primary_api_port}/health"
            with urllib.request.urlopen(url, timeout=2, context=ctx if proto == "https" else None) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    if data.get("role") == "primary":
                        return True
        except Exception:
            pass

    # 2. Checa diretamente o status do PostgreSQL do primario
    try:
        check = subprocess.run(
            ["pg_isready", "-h", primary_host, "-p", str(primary_port), "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        if check.returncode == 0:
            query = subprocess.run(
                ["psql", "-h", primary_host, "-p", str(primary_port), "-U", "postgres", "-d", "postgres", "-tAc", "SELECT pg_is_in_recovery();"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2
            )
            if query.returncode == 0 and query.stdout.strip() == "f":
                return True
    except Exception:
        pass

    return False


@click.command()
@click.option("--pgdata", default=None, help="Caminho do diretorio de dados do Postgres.")
@click.option("--force", is_flag=True, default=False, help="Forca a promocao ignorando a checagem anti-split-brain.")
def cli(pgdata, force):
    """Promove o no PostgreSQL standby a primario de escrita (failover manual com anti-split-brain)."""
    data_dir = pgdata or os.environ.get("PGDATA", "/var/lib/postgresql/data")
    primary_host = get_primary_host(data_dir)

    if primary_host and not force:
        click.echo(f"Executando checagem anti-split-brain contra o no primario ({primary_host})...")
        if check_primary_is_active_master(primary_host):
            click.echo(
                f"\n[VLT-5003] [SPLIT-BRAIN BLOCKED] O no primario '{primary_host}' ainda esta ATIVO e operando como MASTER!\n"
                "Promover a replica com o primario ativo geraria duas bases divergentes (Split-Brain).\n"
                "Para realizar o failover, o primario deve ser desligado primeiro (ou use --force se o primario foi isolado).\n",
                err=True,
            )
            sys.exit(1)

    pg_ctl_bin = find_pg_ctl()
    click.echo(f"Promovendo o no PostgreSQL em {data_dir} para primario...")

    cmd = ["gosu", "postgres", pg_ctl_bin, "-D", data_dir, "promote"]
    result = subprocess.run(cmd, text=True)
    if result.returncode == 0:
        click.echo("[VLT-0000] Promocao concluida com sucesso. O no agora e o primario de escrita.")
    else:
        click.echo(f"[VLT-5002] Falha ao promover no PostgreSQL (exit {result.returncode}).", err=True)
        sys.exit(result.returncode)


if __name__ == "__main__":
    cli()
