"""
vaultctl: CLI unificada de administracao do Vault.
Suporta init, geracao de seeds para Standby/DR (estilo CyberArk Conjur),
join de replicas, promocao com anti-split-brain, inspecao de certificados e resgate offline.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from typing import List, Optional

import click
from sqlalchemy.exc import OperationalError

from vault import config, crypto, pki
from vault.database import Base, engine, SessionLocal
from vault.models import VaultConfig, AppIdentity
from vault.security import hash_app_secret
from vault.permissions import Permission
from cli.vault_promote import cli as promote_cmd
from cli.rescue import cli as rescue_cmd


@click.group()
def cli():
    """vaultctl - Painel de controle e administracao do Vault."""
    pass


# =========================================================================
# 1. INIT: Inicializa cofre, admin, master.key e PKI / TLS
# =========================================================================
@cli.command("init")
@click.option("--output-dir", default="./vault-init-output", help="Diretorio onde salvar master.key e certificados.")
@click.option("--admin-name", default="admin", help="Nome do App ID admin criado no setup.")
@click.option("--admin-ip", required=True, help="IP ou CIDR de onde o admin pode se autenticar.")
@click.option("--admin-secret-stdin", is_flag=True, help="Le o secret do admin da entrada padrao.")
@click.option("--trust-proxy", is_flag=True, default=False, help="Aceita X-Forwarded-For para o admin.")
@click.option("--enable-tls/--no-tls", default=True, help="Gera Root CA e certificados TLS para o no primario.")
@click.option("--node-san", multiple=True, help="SANs adicionais (IPs ou hostnames) para o certificado TLS do nó.")
@click.option("--force", is_flag=True, default=False, help="Reinicializa mesmo se o vault ja tiver config.")
def init(output_dir, admin_name, admin_ip, admin_secret_stdin, trust_proxy, enable_tls, node_san, force):
    """Inicializa schema do banco, gera master key, admin inicial e certificados TLS."""
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
            click.echo("[VLT-1006] vault ja inicializado. Use --force para reinicializar.", err=True)
            sys.exit(1)

        if existing and force:
            db.query(VaultConfig).delete()
            db.query(AppIdentity).delete()
            db.commit()

        out_path = Path(output_dir).expanduser().resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        # 1. Master key
        master_key = crypto.generate_key()

        # 2. Verification blob
        verification_blob = crypto.encrypt(master_key, config.VERIFICATION_PLAINTEXT)
        db.add(VaultConfig(key=config.VERIFICATION_CONFIG_KEY, value=verification_blob))

        # 3. JWT signing key
        jwt_signing_key = crypto.generate_key()
        encrypted_jwt_key = crypto.encrypt(master_key, jwt_signing_key)
        db.add(VaultConfig(key=config.JWT_SIGNING_KEY_CONFIG_KEY, value=encrypted_jwt_key))

        # 4. Admin App ID
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

        # Salva master.key
        key_file = out_path / "master.key"
        key_file.write_text(base64.b64encode(master_key).decode("ascii") + "\n", encoding="utf-8")
        if os.name != "nt":
            key_file.chmod(0o600)

        # 5. Gera PKI / TLS se habilitado
        if enable_tls:
            tls_dir = out_path / "tls"
            sans = ["127.0.0.1", "localhost", "vault-primary"]
            if node_san:
                sans.extend(node_san)

            ca_cert, ca_key = pki.create_root_ca(
                common_name="Vault Root CA",
                organization="Vault Cluster PKI",
            )
            node_cert, node_key = pki.issue_node_certificate(
                ca_cert=ca_cert,
                ca_key=ca_key,
                common_name="vault-primary",
                sans=sans,
            )
            client_cert, client_key = pki.issue_client_certificate(
                ca_cert=ca_cert,
                ca_key=ca_key,
                common_name="replicator",
            )
            pki.save_pki_bundle(
                output_dir=tls_dir,
                ca_cert=ca_cert,
                ca_key=ca_key,
                node_cert=node_cert,
                node_key=node_key,
                client_cert=client_cert,
                client_key=client_key,
            )
            click.echo(f"  Certificados TLS salvos em: {tls_dir}")

        click.echo(f"\n[SUCESSO] Vault inicializado.")
        click.echo(f"  master.key salva em: {key_file}")
        click.echo(f"  Admin '{admin_name}' configurado para IP: {admin_ip}")
    finally:
        db.close()


# =========================================================================
# 2. SEED: Cria pacote de inicializacao para nó Standby / DR (Estilo Conjur)
# =========================================================================
@cli.group("seed")
def seed_group():
    """Gera pacotes seed para inicializar novos nós no cluster."""
    pass


@seed_group.command("standby")
@click.argument("target_host")
@click.option("--name", default=None, help="Nome do nó standby (default: vault-standby-<host>).")
@click.option("--key", default="./vault-init-output/master.key", help="Caminho da master.key original.")
@click.option("--tls-dir", default="./vault-init-output/tls", help="Caminho dos certificados TLS da CA.")
@click.option("--primary-host", default="vault-primary", help="Hostname/IP do primario para replicacao.")
@click.option("--primary-port", default=5432, type=int, help="Porta do PostgreSQL do primario.")
@click.option("--output", default=None, help="Arquivo .seed.tar de saida (default: <nome>.seed.tar).")
def seed_standby(target_host, name, key, tls_dir, primary_host, primary_port, output):
    """Gera um pacote .seed.tar seguro contendo certs mTLS e master.key para uma nova réplica."""
    key_path = Path(key).expanduser().resolve()
    tls_path = Path(tls_dir).expanduser().resolve()

    if not key_path.is_file():
        raise click.ClickException(f"master.key nao encontrada em: {key_path}")

    node_name = name or f"vault-standby-{target_host.replace('.', '-').replace(':', '-')}"
    out_file = output or f"{node_name}.seed.tar"

    ca_crt_path = tls_path / "ca.crt"
    ca_key_path = tls_path / "ca.key"

    if not ca_crt_path.is_file() or not ca_key_path.is_file():
        raise click.ClickException(f"CA TLS nao encontrada em {tls_path} (necessario ca.crt e ca.key)")

    ca_cert = pki.load_certificate(ca_crt_path.read_bytes())
    ca_key = pki.load_private_key(ca_key_path.read_bytes())

    # Emite certificado exclusivo para o novo nó Standby
    sans = [target_host, "localhost", "127.0.0.1", node_name]
    node_cert, node_key = pki.issue_node_certificate(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name=node_name,
        sans=sans,
    )

    # Emite certificado de cliente replicator para mTLS com o primario
    client_cert, client_key = pki.issue_client_certificate(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name="replicator",
    )

    # Prepara metadados do seed
    seed_meta = {
        "role": "standby",
        "node_name": node_name,
        "target_host": target_host,
        "primary_host": primary_host,
        "primary_port": primary_port,
        "created_at": str(os.environ.get("SOURCE_DATE_EPOCH", "")),
    }

    # Empacota tudo em um arquivo tar em memoria/disco
    with tarfile.open(out_file, "w") as tar:
        # 1. master.key
        key_data = key_path.read_bytes()
        ti = tarfile.TarInfo(name="master.key")
        ti.size = len(key_data)
        ti.mode = 0o600
        tar.addfile(ti, io.BytesIO(key_data))

        # 2. tls/ca.crt
        ca_data = pki.serialize_certificate(ca_cert)
        ti = tarfile.TarInfo(name="tls/ca.crt")
        ti.size = len(ca_data)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(ca_data))

        # 3. tls/server.crt e tls/server.key
        srv_crt = pki.serialize_certificate(node_cert)
        ti = tarfile.TarInfo(name="tls/server.crt")
        ti.size = len(srv_crt)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(srv_crt))

        srv_key = pki.serialize_private_key(node_key)
        ti = tarfile.TarInfo(name="tls/server.key")
        ti.size = len(srv_key)
        ti.mode = 0o600
        tar.addfile(ti, io.BytesIO(srv_key))

        # 4. tls/client.crt e tls/client.key
        cli_crt = pki.serialize_certificate(client_cert)
        ti = tarfile.TarInfo(name="tls/client.crt")
        ti.size = len(cli_crt)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(cli_crt))

        cli_key = pki.serialize_private_key(client_key)
        ti = tarfile.TarInfo(name="tls/client.key")
        ti.size = len(cli_key)
        ti.mode = 0o600
        tar.addfile(ti, io.BytesIO(cli_key))

        # 5. seed.json
        meta_data = json.dumps(seed_meta, indent=2).encode("utf-8")
        ti = tarfile.TarInfo(name="seed.json")
        ti.size = len(meta_data)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(meta_data))

    click.echo(f"\n[SUCESSO] Pacote seed gerado com sucesso em: {out_file}")
    click.echo(f"• Nó Alvo:       {node_name} ({target_host})")
    click.echo(f"• Primário:      {primary_host}:{primary_port}")
    click.echo(f"\nPróximo passo na máquina réplica:")
    click.echo(f"  1. Copie o arquivo: scp {out_file} user@{target_host}:/caminho/")
    click.echo(f"  2. Na réplica execute: vaultctl join --seed {out_file}\n")


# =========================================================================
# 3. JOIN: Configura nó local usando pacote seed
# =========================================================================
@cli.command("join")
@click.option("--seed", required=True, help="Caminho do arquivo .seed.tar recebido do primário.")
@click.option("--output-dir", default="./vault-config", help="Diretório onde desempacotar as configurações.")
def join(seed, output_dir):
    """Desempacota o arquivo seed e prepara a réplica para conexão mTLS com o primário."""
    seed_path = Path(seed).expanduser().resolve()
    if not seed_path.is_file():
        raise click.ClickException(f"Arquivo seed nao encontrado em: {seed_path}")

    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    with tarfile.open(seed_path, "r") as tar:
        tar.extractall(path=out_path)

    seed_json_path = out_path / "seed.json"
    if not seed_json_path.is_file():
        raise click.ClickException("Arquivo seed.json ausente no pacote seed.")

    meta = json.loads(seed_json_path.read_text(encoding="utf-8"))

    click.echo("\n=======================================================")
    click.echo("           NÓ RECEPTOR STANDBY CONFIGURADO             ")
    click.echo("=======================================================")
    click.echo(f"• Nome do Nó:    {meta.get('node_name')}")
    click.echo(f"• Primário Host: {meta.get('primary_host')}:{meta.get('primary_port')}")
    click.echo(f"• Arquivos em:   {out_path}")
    click.echo("\nComando Docker para subir o container Standby mTLS:")
    click.echo(
        f"docker run -d --name {meta.get('node_name')} \\\n"
        f"  -p 8000:8000 \\\n"
        f"  -e REPLICATION_ROLE=standby \\\n"
        f"  -e PRIMARY_HOST={meta.get('primary_host')} \\\n"
        f"  -e PRIMARY_PORT={meta.get('primary_port')} \\\n"
        f"  --mount type=bind,source={out_path}/master.key,target=/run/secrets/master.key,readonly \\\n"
        f"  --mount type=bind,source={out_path}/tls,target=/run/secrets/tls,readonly \\\n"
        f"  -v {meta.get('node_name')}-data:/var/lib/postgresql/data vault\n"
    )


# =========================================================================
# 4. CERTS: Inspecao e Renovacao de Certificados
# =========================================================================
@cli.group("certs")
def certs_group():
    """Inspecao e gerenciamento do ciclo de vida de certificados X.509."""
    pass


@certs_group.command("inspect")
@click.argument("cert_file")
def inspect_cert(cert_file):
    """Exibe informacoes detalhadas e validade de um arquivo de certificado."""
    path = Path(cert_file).expanduser().resolve()
    if not path.is_file():
        raise click.ClickException(f"Arquivo nao encontrado: {path}")

    cert = pki.load_certificate(path.read_bytes())
    days = pki.cert_days_remaining(cert)

    click.echo(f"Certificado: {path.name}")
    click.echo(f"• Subject:     {cert.subject.rfc4514_string()}")
    click.echo(f"• Issuer:      {cert.issuer.rfc4514_string()}")
    click.echo(f"• Serial:      {cert.serial_number}")
    click.echo(f"• Válido de:   {cert.not_valid_before_utc}")
    click.echo(f"• Válido até:  {cert.not_valid_after_utc}")
    click.echo(f"• Dias rest.:  {days} dias ({'VÁLIDO' if days > 0 else 'EXPIRADO'})")

    try:
        from cryptography.x509.oid import ExtensionOID
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_list = [f"{type(n).__name__}:{n.value}" for n in san]
        click.echo(f"• SANs:        {', '.join(san_list)}")
    except Exception as e:
        click.echo(f"• SANs:        (erro: {e})")


# Conecta subcomandos promote e rescue existentes na CLI unificada
cli.add_command(promote_cmd, name="promote")
cli.add_command(rescue_cmd, name="rescue")


if __name__ == "__main__":
    cli()
