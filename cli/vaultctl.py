"""
vaultctl: CLI unificada de administracao do Vault no modelo CyberArk Conjur (evoke).
Suporta:
- configure primary: Bootstrap do nó líder, schema, admin e PKI (autoassinada ou BYO).
- configure standby: Configuração da réplica a partir do seed com streaming mTLS.
- seed standby: Geração de pacote .seed.tar seguro contendo certs mTLS e chaves cifradas (master.key NUNCA inclusa).
- unpack seed: Desempacotamento e validação de seed via arquivo ou pipe stdin (-).
- ca issue: Reemissão do certificado de cluster com novos SANs para expansão de nós.
- role promote: Promoção com checagem anti-split-brain via HTTPS + mTLS.
- status: Exibição detalhada de papel, cluster, validade de certificados e replicação.
- rescue: Resgate de emergência offline (Break-Glass).
"""

from __future__ import annotations

import base64
import datetime
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

import click
from sqlalchemy.exc import OperationalError

from vault import config, crypto, pki
from vault.database import Base, engine, SessionLocal
from vault.models import VaultConfig, AppIdentity
from vault.security import hash_app_secret
from vault.permissions import Permission
from cli.rescue import cli as rescue_cmd


def get_pgdata() -> Path:
    return Path(os.environ.get("PGDATA", "/var/lib/postgresql/data")).expanduser().resolve()


def get_master_key_file() -> Path:
    return Path(os.environ.get("MASTER_KEY_FILE", config.MASTER_KEY_FILE)).expanduser().resolve()


def get_seed_stage_dir() -> Path:
    return Path(os.environ.get("SEED_STAGE_DIR", "/tmp/vault_seed_stage")).expanduser().resolve()


def load_master_key() -> bytes:
    key_path = get_master_key_file()
    if not key_path.is_file():
        raise click.ClickException(
            f"[VLT-1001] master.key nao encontrada em {key_path}. "
            "Monte o arquivo de chave mestra no container antes de executar a operacao."
        )
    raw = key_path.read_text(encoding="utf-8").strip()
    try:
        key_bytes = base64.b64decode(raw)
    except Exception:
        raise click.ClickException("[VLT-1002] master.key com formato invalido (esperado base64).")
    if len(key_bytes) != crypto.KEY_SIZE:
        raise click.ClickException(f"[VLT-1002] master.key com tamanho invalido: {len(key_bytes)} bytes.")
    return key_bytes


# =========================================================================
# ROOT CLI GROUP
# =========================================================================
@click.group()
def cli():
    """vaultctl - Painel de administracao e gerenciamento do Vault."""
    pass


# =========================================================================
# 1. CONFIGURE GROUP (primary / standby)
# =========================================================================
@cli.group("configure")
def configure_group():
    """Configura o papel e os servicos do no (estilo evoke configure)."""
    pass


@configure_group.command("primary")
@click.option("--hostname", required=True, help="Nome FQDN ou hostname principal do cluster.")
@click.option("--altname", "altnames", multiple=True, help="Hostnames ou IPs adicionais (SANs) de todos os nos.")
@click.option("--admin-name", default="admin", help="Nome do App ID admin inicial.")
@click.option("--admin-ip", required=True, help="IP ou CIDR de onde o admin pode se autenticar.")
@click.option("--admin-secret-stdin", is_flag=True, help="Le a senha do admin a partir da entrada padrao.")
@click.option("--cert", "cert_file", default=None, help="Caminho do certificado do cluster (BYO-Cert).")
@click.option("--key", "key_file", default=None, help="Caminho da chave privada do cluster (BYO-Cert).")
@click.option("--ca", "ca_file", default=None, help="Caminho da Root CA / cadeia (BYO-Cert).")
def configure_primary(hostname, altnames, admin_name, admin_ip, admin_secret_stdin, cert_file, key_file, ca_file):
    """Configura o no como Lider (Primario) com banco, admin e PKI (autoassinada ou BYO)."""
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"

    if cluster_file.is_file():
        raise click.ClickException("[VLT-1006] O cofre ja esta configurado neste no.")

    master_key = load_master_key()

    if admin_secret_stdin:
        admin_secret_plain = sys.stdin.readline().rstrip("\r\n")
    else:
        admin_secret_plain = click.prompt("Senha do admin", hide_input=True, confirmation_prompt=True)
    if not admin_secret_plain:
        raise click.ClickException("A senha do admin nao pode ser vazia.")
    if len(admin_secret_plain.encode("utf-8")) > 72:
        raise click.ClickException("A senha do admin deve ter no maximo 72 bytes (limite do bcrypt).")

    # 1. Processamento da PKI (BYO ou Autoassinada)
    all_altnames = list(altnames)
    ca_key = None
    if cert_file or key_file or ca_file:
        if not (cert_file and key_file and ca_file):
            raise click.ClickException("[VLT-1009] Para BYO-Cert, informe --cert, --key e --ca.")
        c_bytes = Path(cert_file).read_bytes()
        k_bytes = Path(key_file).read_bytes()
        ca_bytes = Path(ca_file).read_bytes()
        try:
            cluster_cert, cluster_key, ca_cert, warning = pki.validate_byo_certificates(
                c_bytes, k_bytes, ca_bytes, hostname, all_altnames
            )
            if warning:
                click.echo(warning, err=True)
        except pki.BYOValidationError as e:
            raise click.ClickException(f"[{e.code}] Falha na validacao BYO: {e.message}")
        ca_type = "byo"
    else:
        # Gera Root CA e Certificado Unico de Cluster
        ca_cert, ca_key = pki.create_root_ca(
            common_name=f"Vault CA ({hostname})",
            organization="Vault Cluster PKI",
        )
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key, hostname, all_altnames
        )
        ca_type = "internal"

    # 2. Inicializa PostgreSQL PRIMEIRO (se o banco for novo)
    pgdata.mkdir(parents=True, exist_ok=True)
    if not (pgdata / "PG_VERSION").is_file():
        # Limpa residuos de tentativas anteriores para o initdb nao falhar com "directory exists but is not empty"
        for item in pgdata.iterdir():
            if item.is_dir():
                shutil.rmtree(str(item), ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

        subprocess.run(
            ["gosu", "postgres", "initdb", "-D", str(pgdata), "-A", "trust", "--auth-local=trust"],
            check=True, stdout=subprocess.DEVNULL
        )
        db_pass = crypto.b64encode(crypto.generate_key())
        (pgdata / ".db_password").write_text(db_pass, encoding="utf-8")
        if os.name != "nt":
            (pgdata / ".db_password").chmod(0o600)
            import pwd
            try:
                pg_uid = pwd.getpwnam("postgres").pw_uid
                pg_gid = pwd.getpwnam("postgres").pw_gid
                os.chown(str(pgdata / ".db_password"), pg_uid, pg_gid)
            except Exception:
                pass

    # 3. Salva PKI no volume com chaves privadas cifradas (agora seguro apos o initdb)
    tls_dir = pgdata / "tls"
    pki.save_cluster_pki_to_disk(
        tls_dir, master_key, ca_cert, cluster_cert, cluster_key, ca_key
    )

    # 4. Decifra chaves para tmpfs temporario para subir o Postgres
    tmpfs_dir = pki.install_keys_to_tmpfs(tls_dir, master_key)

    # 5. Inicia Postgres local temporariamente para criar o schema
    pg_opts = f"-c listen_addresses='localhost' -c ssl=on -c ssl_cert_file={tmpfs_dir}/server.crt -c ssl_key_file={tmpfs_dir}/server.key -c ssl_ca_file={tmpfs_dir}/ca.crt"
    subprocess.run(["gosu", "postgres", "pg_ctl", "-D", str(pgdata), "-o", pg_opts, "-w", "start"], check=True)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    try:
        # Cria usuario e banco se nao existirem
        pass_val = (pgdata / ".db_password").read_text(encoding="utf-8").strip()
        subprocess.run(
            ["gosu", "postgres", "psql", "-c", f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault') THEN CREATE USER vault WITH NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '{pass_val}'; END IF; END $$;"],
            check=True, stdout=subprocess.DEVNULL
        )
        check_db = subprocess.run(
            ["gosu", "postgres", "psql", "-tAc", "SELECT 1 FROM pg_database WHERE datname = 'vault';"],
            capture_output=True, text=True
        )
        if "1" not in (check_db.stdout or ""):
            subprocess.run(
                ["gosu", "postgres", "psql", "-c", "CREATE DATABASE vault OWNER vault;"],
                check=True, stdout=subprocess.DEVNULL
            )
        subprocess.run(
            ["gosu", "postgres", "psql", "-d", "vault", "-c", "GRANT ALL ON SCHEMA public TO vault;"],
            check=True, stdout=subprocess.DEVNULL
        )

        # Atualiza DATABASE_URL
        db_url = f"postgresql+psycopg2://vault:{pass_val}@localhost:5432/vault"
        os.environ["DATABASE_URL"] = db_url
        (pgdata / ".database_url").write_text(db_url, encoding="utf-8")

        temp_engine = create_engine(db_url, pool_pre_ping=True)
        Base.metadata.create_all(bind=temp_engine)
        TempSession = sessionmaker(bind=temp_engine)
        db = TempSession()
        try:
            # Master key verification blob
            v_blob = crypto.encrypt(master_key, config.VERIFICATION_PLAINTEXT)
            db.add(VaultConfig(key=config.VERIFICATION_CONFIG_KEY, value=v_blob))

            # JWT signing key
            jwt_key = crypto.generate_key()
            jwt_enc = crypto.encrypt(master_key, jwt_key)
            db.add(VaultConfig(key=config.JWT_SIGNING_KEY_CONFIG_KEY, value=jwt_enc))

            # Admin App ID
            admin_app = AppIdentity(
                name=admin_name,
                secret_hash=hash_app_secret(admin_secret_plain),
                allowed_ip=admin_ip,
                trust_proxy=False,
                is_admin=True,
            )
            admin_app.permissions = {Permission.Create}
            db.add(admin_app)
            db.commit()
        finally:
            db.close()
            temp_engine.dispose()
    finally:
        subprocess.run(["gosu", "postgres", "pg_ctl", "-D", str(pgdata), "-m", "fast", "-w", "stop"], check=True)
        pki.shred_tmpfs_keys(str(tmpfs_dir))

    # 6. Grava cluster.json definitivo
    cluster_meta = {
        "role": "primary",
        "hostname": hostname,
        "altnames": all_altnames,
        "ca_type": ca_type,
        "primary_port": 5432,
        "configured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    cluster_file.write_text(json.dumps(cluster_meta, indent=2), encoding="utf-8")

    click.echo(f"\n[SUCESSO] No Lider configurado com sucesso!")
    click.echo(f"• Cluster Hostname: {hostname}")
    click.echo(f"• SANs Registrados: {', '.join(pki.get_certificate_sans(cluster_cert))}")
    click.echo(f"• Admin Provisionado: {admin_name} ({admin_ip})")
    click.echo("O container principal agora iniciara os servicos automaticamente.")


@configure_group.command("standby")
def configure_standby():
    """Configura o no como Standby (Replica) utilizando os dados do seed desempacotado."""
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"
    if cluster_file.is_file():
        raise click.ClickException("[VLT-1006] O cofre ja esta configurado neste no.")

    stage_dir = get_seed_stage_dir()
    seed_json = stage_dir / "seed.json"
    if not seed_json.is_file():
        raise click.ClickException(
            "[VLT-1007] Nenhum seed desempacotado localizado em /tmp/vault_seed_stage. "
            "Execute 'vaultctl unpack seed <arquivo|->' primeiro."
        )

    meta = json.loads(seed_json.read_text(encoding="utf-8"))
    primary_host = meta["primary_host"]
    primary_port = meta.get("primary_port", 5432)
    master_key = load_master_key()

    # Move os certificados e chaves cifradas do seed_stage para $PGDATA/tls
    tls_dir = pgdata / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    for fname in ("ca.crt", "cluster.crt", "cluster.key.enc", "ca.key.enc"):
        src = stage_dir / fname
        if src.is_file():
            shutil.copyfile(str(src), str(tls_dir / fname))

    # Decifra chaves para tmpfs para o pg_basebackup usar mTLS
    tmpfs_dir = pki.install_keys_to_tmpfs(tls_dir, master_key)

    # Aguarda o nó primário responder
    click.echo(f"Aguardando conectividade com o primario em {primary_host}:{primary_port}...")
    env = os.environ.copy()
    env["PGSSLMODE"] = "verify-full"
    env["PGSSLROOTCERT"] = str(tmpfs_dir / "ca.crt")
    env["PGSSLCERT"] = str(tmpfs_dir / "server.crt")
    env["PGSSLKEY"] = str(tmpfs_dir / "server.key")

    ready = False
    for _ in range(30):
        res = subprocess.run(
            ["pg_isready", "-h", primary_host, "-p", str(primary_port), "-U", "replicator", "-d", "postgres", "-q"],
            env=env
        )
        if res.returncode == 0:
            ready = True
            break
        import time
        time.sleep(2)

    if not ready:
        pki.shred_tmpfs_keys(str(tmpfs_dir))
        raise click.ClickException(f"[VLT-1003] Falha ao alcancar o primario em {primary_host}:{primary_port} via mTLS.")

    # Limpa arquivos residuais do pgdata antes do basebackup para evitar erro "directory exists but is not empty"
    for item in pgdata.iterdir():
        if item.name == "tls":
            continue
        if item.is_dir():
            shutil.rmtree(str(item), ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

    # Executa pg_basebackup via mTLS
    click.echo(f"Sincronizando banco inicial a partir de {primary_host}...")
    backup_cmd = [
        "gosu", "postgres", "pg_basebackup",
        "-h", primary_host, "-p", str(primary_port),
        "-U", "replicator", "-D", str(pgdata),
        "-Fp", "-Xs", "-R",
    ]
    res_backup = subprocess.run(backup_cmd, env=env)
    if res_backup.returncode != 0:
        pki.shred_tmpfs_keys(str(tmpfs_dir))
        raise click.ClickException("[VLT-1003] Falha no pg_basebackup a partir do lider.")

    # Restaura certificados tls no volume (se basebackup tiver limpado)
    tls_dir.mkdir(parents=True, exist_ok=True)
    for fname in ("ca.crt", "cluster.crt", "cluster.key.enc", "ca.key.enc"):
        src = stage_dir / fname
        if src.is_file():
            shutil.copyfile(str(src), str(tls_dir / fname))

    # Ajusta primary_conninfo no postgresql.auto.conf para mTLS definitivo
    auto_conf = pgdata / "postgresql.auto.conf"
    if auto_conf.is_file():
        conninfo_line = (
            f"primary_conninfo = 'host={primary_host} port={primary_port} user=replicator "
            f"sslmode=verify-full sslrootcert=/dev/shm/vault_tls/ca.crt "
            f"sslcert=/dev/shm/vault_tls/server.crt sslkey=/dev/shm/vault_tls/server.key'\n"
        )
        # Substitui linha primary_conninfo
        lines = auto_conf.read_text(encoding="utf-8").splitlines()
        new_lines = [l for l in lines if not l.startswith("primary_conninfo")]
        new_lines.append(conninfo_line)
        auto_conf.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # Limpa stage e tmpfs
    shutil.rmtree(str(stage_dir), ignore_errors=True)
    pki.shred_tmpfs_keys(str(tmpfs_dir))

    # Grava cluster.json definitivo
    meta["configured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cluster_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    click.echo(f"\n[SUCESSO] No Standby configurado com sucesso!")
    click.echo(f"• Conectado ao Lider: {primary_host}:{primary_port}")
    click.echo("O container principal agora iniciara o streaming de replicacao e a API.")


# =========================================================================
# 2. SEED STANDBY: Gera o pacote .seed.tar para nova réplica
# =========================================================================
@cli.group("seed")
def seed_group():
    """Gera pacotes seed cifrados para expansao do cluster (estilo evoke seed)."""
    pass


@seed_group.command("standby")
@click.argument("target_host")
@click.option("--primary-host", default=None, help="Hostname/IP do lider pelo qual a replica ira se conectar.")
@click.option("--primary-port", default=5432, type=int, help="Porta do PostgreSQL do lider.")
@click.option("--output", "-o", default=None, help="Arquivo .seed.tar de saida (padrao: stdout).")
def seed_standby(target_host, primary_host, primary_port, output):
    """Gera pacote seed cifrado para o nó standby alvo. Master key NUNCA inclusa."""
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"

    if not cluster_file.is_file():
        raise click.ClickException("[VLT-1005] O cofre nao esta configurado neste no.")

    cluster_meta = json.loads(cluster_file.read_text(encoding="utf-8"))
    if cluster_meta.get("role") != "primary":
        raise click.ClickException("[VLT-5001] Somente o no lider (primario) pode gerar seeds.")

    p_host = primary_host or cluster_meta.get("hostname", "vault-primary")
    tls_dir = pgdata / "tls"

    cluster_crt_path = tls_dir / "cluster.crt"
    cluster_key_enc_path = tls_dir / "cluster.key.enc"
    ca_crt_path = tls_dir / "ca.crt"
    ca_key_enc_path = tls_dir / "ca.key.enc"

    if not (cluster_crt_path.is_file() and cluster_key_enc_path.is_file() and ca_crt_path.is_file()):
        raise click.ClickException("[VLT-1008] Componentes de PKI ausentes no volume.")

    # Verifica se o target_host esta coberto nos SANs do certificado do cluster
    cluster_cert = pki.load_certificate(cluster_crt_path.read_bytes())
    if not pki.is_certificate_valid_for_host(cluster_cert, target_host):
        click.echo(
            f"Aviso: O target_host '{target_host}' nao consta nos SANs do certificado de cluster! "
            f"Se necessario, execute 'vaultctl ca issue --force {target_host}' antes de gerar os seeds.",
            err=True
        )

    # Se BYO (sem ca.key.enc), avisa no stderr
    has_ca_key = ca_key_enc_path.is_file()
    if not has_ca_key:
        click.echo("Info: CA corporativa externa em uso (ca.key ausente). Standby nao podera reemitir certs.", err=True)

    seed_meta = {
        "role": "standby",
        "target_host": target_host,
        "primary_host": p_host,
        "primary_port": primary_port,
        "cluster_hostname": cluster_meta.get("hostname"),
        "altnames": cluster_meta.get("altnames", []),
        "ca_type": cluster_meta.get("ca_type", "internal"),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        # 1. seed.json
        meta_bytes = json.dumps(seed_meta, indent=2).encode("utf-8")
        ti = tarfile.TarInfo(name="seed.json")
        ti.size = len(meta_bytes)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(meta_bytes))

        # 2. ca.crt
        ca_data = ca_crt_path.read_bytes()
        ti = tarfile.TarInfo(name="ca.crt")
        ti.size = len(ca_data)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(ca_data))

        # 3. ca.key.enc (se existir)
        if has_ca_key:
            ca_k_data = ca_key_enc_path.read_bytes()
            ti = tarfile.TarInfo(name="ca.key.enc")
            ti.size = len(ca_k_data)
            ti.mode = 0o600
            tar.addfile(ti, io.BytesIO(ca_k_data))

        # 4. cluster.crt
        c_data = cluster_crt_path.read_bytes()
        ti = tarfile.TarInfo(name="cluster.crt")
        ti.size = len(c_data)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(c_data))

        # 5. cluster.key.enc (chaves sempre cifradas com a master.key)
        k_enc_data = cluster_key_enc_path.read_bytes()
        ti = tarfile.TarInfo(name="cluster.key.enc")
        ti.size = len(k_enc_data)
        ti.mode = 0o600
        tar.addfile(ti, io.BytesIO(k_enc_data))

    seed_bytes = tar_stream.getvalue()

    click.echo("Aviso: o pacote seed contem material criptografico do cluster cifrado com a master key.", err=True)

    if output and output != "-":
        out_p = Path(output).expanduser().resolve()
        out_p.write_bytes(seed_bytes)
        click.echo(f"Seed gravado em: {out_p}", err=True)
    else:
        # Escreve tar binario no stdout limpo (para suporte a pipe ssh)
        sys.stdout.buffer.write(seed_bytes)
        sys.stdout.buffer.flush()


# =========================================================================
# 3. UNPACK GROUP: Desempacota e valida o seed
# =========================================================================
@cli.group("unpack")
def unpack_group():
    """Desempacota pacotes de configuracao (estilo evoke unpack)."""
    pass


@unpack_group.command("seed")
@click.argument("seed_source")
def unpack_seed(seed_source):
    """Desempacota e valida o arquivo seed a partir de um arquivo ou stdin (-)."""
    pgdata = get_pgdata()
    master_key = load_master_key()

    if seed_source == "-":
        seed_data = sys.stdin.buffer.read()
    else:
        seed_file = Path(seed_source).expanduser().resolve()
        if not seed_file.is_file():
            raise click.ClickException(f"Arquivo seed nao encontrado em: {seed_file}")
        seed_data = seed_file.read_bytes()

    if len(seed_data) == 0:
        raise click.ClickException("[VLT-1007] O pacote seed fornecido esta vazio.")

    stage_dir = get_seed_stage_dir()
    shutil.rmtree(str(stage_dir), ignore_errors=True)
    stage_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(fileobj=io.BytesIO(seed_data), mode="r") as tar:
            tar.extractall(path=stage_dir)
    except Exception as e:
        shutil.rmtree(str(stage_dir), ignore_errors=True)
        raise click.ClickException(f"[VLT-1007] Pacote seed corrompido ou formato tar invalido: {e}")

    # Valida componentes obrigatorios
    for req in ("seed.json", "ca.crt", "cluster.crt", "cluster.key.enc"):
        if not (stage_dir / req).is_file():
            shutil.rmtree(str(stage_dir), ignore_errors=True)
            raise click.ClickException(f"[VLT-1008] Componente obrigatorio ausente no seed: {req}")

    # Garante que a master.key NAO foi enviada no seed
    if (stage_dir / "master.key").is_file():
        shutil.rmtree(str(stage_dir), ignore_errors=True)
        raise click.ClickException("[VLT-1007] Violacao de seguranca: o seed contem master.key. O pacote foi rejeitado.")

    # Valida criptografia: tenta decifrar a chave do cluster com a master.key deste nó
    try:
        cluster_enc = (stage_dir / "cluster.key.enc").read_bytes()
        pki.decrypt_private_key(cluster_enc, master_key)
    except pki.PKIError as e:
        shutil.rmtree(str(stage_dir), ignore_errors=True)
        raise click.ClickException(
            f"[{e.code}] A master.key montada neste no NAO foi capaz de decifrar o seed! "
            "Certifique-se de que a mesma master.key do lider foi entregue e montada."
        )

    click.echo(
        "[SUCESSO] Seed desempacotado e validado com sucesso. "
        "Execute 'vaultctl configure standby' para sincronizar o no."
    )


# =========================================================================
# 4. CA GROUP: Reemissao de Certificado de Cluster
# =========================================================================
@cli.group("ca")
def ca_group():
    """Gerenciamento da autoridade certificadora (estilo evoke ca)."""
    pass


@ca_group.command("issue")
@click.argument("hostnames", nargs=-1, required=True)
@click.option("--replace", is_flag=True, default=False, help="Substitui a lista de SANs em vez de mesclar.")
@click.option("--force", is_flag=True, default=False, help="Forca a reemissao do certificado de cluster.")
def ca_issue(hostnames, replace, force):
    """Reemite o certificado do cluster incluindo novos SANs (hostnames/IPs)."""
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"

    if not cluster_file.is_file():
        raise click.ClickException("[VLT-1005] O cofre nao esta configurado neste no.")

    cluster_meta = json.loads(cluster_file.read_text(encoding="utf-8"))
    if cluster_meta.get("role") != "primary":
        raise click.ClickException("[VLT-5001] Somente o lider pode reemitir certificados de cluster.")

    tls_dir = pgdata / "tls"
    ca_key_enc_path = tls_dir / "ca.key.enc"
    ca_crt_path = tls_dir / "ca.crt"

    if not (ca_key_enc_path.is_file() and ca_crt_path.is_file()):
        raise click.ClickException(
            "[VLT-1010] ca.key.enc ausente. Com CA corporativa externa, a reemissao deve ser feita na PKI externa."
        )

    master_key = load_master_key()
    ca_cert = pki.load_certificate(ca_crt_path.read_bytes())
    ca_key = pki.decrypt_private_key(ca_key_enc_path.read_bytes(), master_key)

    # Define novos SANs (substitui ou mescla)
    if replace:
        new_altnames = sorted(list(set(hostnames)))
    else:
        current_altnames = set(cluster_meta.get("altnames", []))
        current_altnames.update(hostnames)
        new_altnames = sorted(list(current_altnames))

    hostname = cluster_meta.get("hostname", "vault-cluster")
    cluster_cert, cluster_key = pki.create_cluster_certificate(
        ca_cert, ca_key, hostname, new_altnames
    )

    # Salva no disco cifrado
    pki.save_cluster_pki_to_disk(tls_dir, master_key, ca_cert, cluster_cert, cluster_key, ca_key)

    # Atualiza chaves decifradas no tmpfs em memoria para o Postgres e Uvicorn
    try:
        pki.install_keys_to_tmpfs(tls_dir, master_key)
        subprocess.run(["gosu", "postgres", "pg_ctl", "-D", str(pgdata), "reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Atualiza cluster.json
    cluster_meta["altnames"] = new_altnames
    cluster_file.write_text(json.dumps(cluster_meta, indent=2), encoding="utf-8")

    click.echo(f"[SUCESSO] Certificado de cluster reemitido com sucesso!")
    click.echo(f"• Novos SANs: {', '.join(pki.get_certificate_sans(cluster_cert))}")
    click.echo(
        "\nATENCAO: E necessario regenerar os pacotes seed ('vaultctl seed standby ...') "
        "e redistribuir o novo certificado para as replicas existentes do cluster."
    )


# =========================================================================
# 5. ROLE GROUP: Promocao com Anti-Split-Brain (role promote / promote)
# =========================================================================
@cli.group("role")
def role_group():
    """Gerenciamento de papeis operacionais dos nos."""
    pass


def execute_promotion(force: bool = False):
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"

    if not cluster_file.is_file():
        raise click.ClickException("[VLT-1005] O cofre nao esta configurado neste no.")

    cluster_meta = json.loads(cluster_file.read_text(encoding="utf-8"))
    if cluster_meta.get("role") != "standby":
        click.echo(f"O no ja opera como {cluster_meta.get('role')}.")
        return

    primary_host = cluster_meta.get("primary_host")
    ca_crt_path = pgdata / "tls" / "ca.crt"

    primary_api_port = cluster_meta.get("primary_api_port", int(os.environ.get("API_PORT", 443)))

    # Checagem ativa anti-split-brain via HTTPS seguro
    if primary_host and not force:
        click.echo(f"Verificando status do lider anterior em https://{primary_host}:{primary_api_port}/health...")
        ctx = ssl.create_default_context(cafile=str(ca_crt_path) if ca_crt_path.is_file() else None)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE if not ca_crt_path.is_file() else ssl.CERT_REQUIRED

        leader_active = False
        check_error = None
        try:
            req = urllib.request.Request(f"https://{primary_host}:{primary_api_port}/health")
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    if data.get("role") == "primary":
                        leader_active = True
        except Exception as e:
            check_error = str(e)

        if leader_active:
            raise click.ClickException(
                f"\n[VLT-5003] [SPLIT-BRAIN BLOCKED] O no primario '{primary_host}' ainda esta ATIVO e respondendo como MASTER!\n"
                "Promover a replica agora geraria divergencia irreversivel de dados.\n"
                "Desligue o container do primario antes de promover, ou use --force se o primario foi fisicamente isolado."
            )

        if check_error and not force:
            click.echo(
                f"[Aviso] Nao foi possivel contatar o primario ({check_error}).\n"
                "Para evitar Split-Brain acidental, use 'vaultctl role promote --force' para confirmar que o lider esta inoperante.",
                err=True
            )
            sys.exit(1)

    click.echo(f"Promovendo no PostgreSQL em {pgdata} para primario...")
    res = subprocess.run(["gosu", "postgres", "pg_ctl", "-D", str(pgdata), "promote"])
    if res.returncode != 0:
        raise click.ClickException("[VLT-5002] Falha ao executar promocao no PostgreSQL.")

    cluster_meta["role"] = "primary"
    cluster_file.write_text(json.dumps(cluster_meta, indent=2), encoding="utf-8")

    click.echo("[SUCESSO] No promovido a Lider (Primario). Agora aceita operacoes de escrita.")


@role_group.command("promote")
@click.option("--force", is_flag=True, default=False, help="Ignora a checagem anti-split-brain.")
def role_promote_cmd(force):
    """Promove um no standby a primario de escrita com protecao anti-split-brain."""
    execute_promotion(force=force)


# Alias de alto nivel 'vaultctl promote'
@cli.command("promote")
@click.option("--force", is_flag=True, default=False, help="Ignora a checagem anti-split-brain.")
def promote_alias_cmd(force):
    """Promove um no standby a primario (alias para 'vaultctl role promote')."""
    execute_promotion(force=force)


# =========================================================================
# 6. STATUS: Exibe papel, certificados e replicação
# =========================================================================
@cli.command("status")
def status_cmd():
    """Exibe o estado operacional do no, validade de certificados e replicacao."""
    pgdata = get_pgdata()
    cluster_file = pgdata / "cluster.json"

    click.echo("=======================================================")
    click.echo("                  VAULT CLUSTER STATUS                 ")
    click.echo("=======================================================")

    if not cluster_file.is_file():
        click.echo("• Estado:       NAO CONFIGURADO (unconfigured)")
        click.echo("  Aguardando provisionamento via 'vaultctl configure primary' ou 'vaultctl configure standby'")
        return

    meta = json.loads(cluster_file.read_text(encoding="utf-8"))
    role = meta.get("role", "desconhecido").upper()
    click.echo(f"• Papel:        {role}")
    click.echo(f"• Hostname:     {meta.get('hostname')}")
    click.echo(f"• Tipo de CA:   {meta.get('ca_type')}")
    if meta.get("primary_host"):
        click.echo(f"• Lider Remoto: {meta.get('primary_host')}:{meta.get('primary_port', 5432)}")

    tls_crt = pgdata / "tls" / "cluster.crt"
    if tls_crt.is_file():
        cert = pki.load_certificate(tls_crt.read_bytes())
        days = pki.cert_days_remaining(cert)
        click.echo(f"• Certificado:  {days} dias restantes ({'VALIDO' if days > 0 else 'EXPIRADO'})")
        click.echo(f"• SANs:         {', '.join(pki.get_certificate_sans(cert))}")

    # Consulta replicacao no Postgres
    click.echo("\n[Status PostgreSQL]:")
    if role == "PRIMARY":
        subprocess.run([
            "gosu", "postgres", "psql", "-x", "-c",
            "SELECT client_addr, state, sync_state, replay_lag FROM pg_stat_replication;"
        ])
    else:
        subprocess.run([
            "gosu", "postgres", "psql", "-x", "-c",
            "SELECT status, sender_host, sender_port FROM pg_stat_wal_receiver;"
        ])


# =========================================================================
# 7. CERTS INSPECT & RESCUE
# =========================================================================
@cli.group("certs")
def certs_group():
    """Inspecao e ferramentas de certificados X.509."""
    pass


@certs_group.command("inspect")
@click.argument("cert_file")
def inspect_cert(cert_file):
    """Exibe informacoes detalhadas de um certificado."""
    path = Path(cert_file).expanduser().resolve()
    if not path.is_file():
        raise click.ClickException(f"Arquivo nao encontrado: {path}")

    cert = pki.load_certificate(path.read_bytes())
    days = pki.cert_days_remaining(cert)

    click.echo(f"Certificado: {path.name}")
    click.echo(f"• Subject:     {cert.subject.rfc4514_string()}")
    click.echo(f"• Issuer:      {cert.issuer.rfc4514_string()}")
    click.echo(f"• Serial:      {cert.serial_number}")
    click.echo(f"• Valido de:   {cert.not_valid_before_utc}")
    click.echo(f"• Valido ate:  {cert.not_valid_after_utc}")
    click.echo(f"• Dias rest.:  {days} dias ({'VALIDO' if days > 0 else 'EXPIRADO'})")
    click.echo(f"• SANs:        {', '.join(pki.get_certificate_sans(cert))}")


# Adiciona rescue
cli.add_command(rescue_cmd, name="rescue")


if __name__ == "__main__":
    cli()
