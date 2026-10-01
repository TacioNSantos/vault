"""
CLI de setup do Vault. Roda UMA VEZ (ou de novo, com --force, para
reinicializar do zero) contra o Postgres do container antes do primeiro
boot da API.

Uso tipico:
    vault-init init --output-dir ./vault-init-output --admin-ip 10.0.0.5

Gera:
    <output-dir>/master.key             -> entregar ao admin, montar no container
"""
import os
import sys
import base64

import click
from sqlalchemy.exc import OperationalError

from vault import config, crypto
from vault.database import Base, engine, SessionLocal
from vault.models import VaultConfig, AppIdentity
from vault.security import hash_app_secret
from vault.permissions import Permission


@click.group()
def cli():
    """vault-init - setup e administracao offline do cofre."""
    pass


@cli.command()
@click.option("--output-dir", default="./vault-init-output", help="Onde salvar master.key.")
@click.option("--admin-name", default="admin", help="Nome do App ID admin criado no setup.")
@click.option("--admin-ip", required=True, help="IP ou CIDR de onde o admin pode se autenticar.")
@click.option("--admin-secret-stdin", is_flag=True, help="Le o app_secret do admin da entrada padrao (sem expor em argumentos).")
@click.option("--trust-proxy", is_flag=True, default=False, help="Aceita X-Forwarded-For para o admin.")
@click.option("--force", is_flag=True, default=False, help="Reinicializa mesmo se o vault ja tiver config.")
def init(output_dir, admin_name, admin_ip, admin_secret_stdin, trust_proxy, force):
    """Inicializa o schema do banco, gera a master key e o admin inicial."""

    if admin_secret_stdin:
        admin_secret_plain = sys.stdin.readline().rstrip("\r\n")
    else:
        admin_secret_plain = click.prompt("Senha do admin", hide_input=True, confirmation_prompt=True)
    if not admin_secret_plain:
        raise click.ClickException("A senha do admin nao pode ser vazia")
    if len(admin_secret_plain.encode("utf-8")) > 72:
        raise click.ClickException("A senha do admin deve ter no maximo 72 bytes (limite do bcrypt)")

    try:
        Base.metadata.create_all(bind=engine)
    except OperationalError as e:
        click.echo(f"[VLT-1003] falha ao conectar/criar schema no Postgres: {e}", err=True)
        sys.exit(1)

    db = SessionLocal()
    try:
        existing = db.query(VaultConfig).filter(VaultConfig.key == config.VERIFICATION_CONFIG_KEY).first()
        if existing and not force:
            click.echo("[VLT-1006] vault ja inicializado. Use --force para reinicializar (isso invalida a master key atual).", err=True)
            sys.exit(1)

        if existing and force:
            db.query(VaultConfig).delete()
            db.query(AppIdentity).delete()
            db.commit()

        os.makedirs(output_dir, exist_ok=True)

        # 1. master key
        master_key = crypto.generate_key()

        # 2. verification blob, pra bootstrap.py conferir a master key certa no boot futuro
        verification_blob = crypto.encrypt(master_key, config.VERIFICATION_PLAINTEXT)
        db.add(VaultConfig(key=config.VERIFICATION_CONFIG_KEY, value=verification_blob))

        # 3. jwt signing key, gerada agora, guardada encriptada pela master key
        jwt_signing_key = crypto.generate_key()
        encrypted_jwt_key = crypto.encrypt(master_key, jwt_signing_key)
        db.add(VaultConfig(key=config.JWT_SIGNING_KEY_CONFIG_KEY, value=encrypted_jwt_key))

        # 4. admin App ID inicial
        admin_app = AppIdentity(
            name=admin_name,
            secret_hash=hash_app_secret(admin_secret_plain),
            allowed_ip=admin_ip,
            trust_proxy=trust_proxy,
            is_admin=True,
        )
        admin_app.permissions = {Permission.Create}
        db.add(admin_app)
        db.commit()

        # 5. grava a master key; a senha do admin fica apenas como hash no banco
        master_key_path = os.path.join(output_dir, "master.key")
        with open(master_key_path, "w") as f:
            f.write(base64.b64encode(master_key).decode("ascii"))
        os.chmod(master_key_path, 0o600)

        click.echo("Vault inicializado com sucesso.")
        click.echo(f"  master key salva em: {master_key_path}")
        click.echo("")
        click.echo("PROXIMOS PASSOS:")
        click.echo(f"  1. Monte {master_key_path} no container em MASTER_KEY_FILE (default /run/secrets/master.key)")
        click.echo("  2. Guarde a master.key em local seguro; o container precisa dela ao iniciar")
        click.echo(f"  3. Use o usuario '{admin_name}' e a senha escolhida para autenticar")

    finally:
        db.close()


if __name__ == "__main__":
    cli()
