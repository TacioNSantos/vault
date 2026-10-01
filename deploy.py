"""Setup interativo do Vault no Docker (Windows e Linux).
Suporta no unico, cluster com Disaster Recovery (Primario + Standby) e resgate de emergencia (break-glass).
"""

import argparse
import getpass
import http.client
import ipaddress
import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class AlreadyInitializedError(RuntimeError):
    """O banco existente requer sua master key original."""


def run(*args, capture=False, input_text=None):
    cmd = ["docker", *args]
    result = subprocess.run(
        cmd, cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        input=input_text,
    )
    return result.stdout.strip() if capture else None


def ask(label, default=None):
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{label}{suffix}: ").strip()
    return answer or default


def is_port_free(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False


def ask_port(label: str, default: int) -> int:
    while True:
        port_text = ask(label, str(default))
        if not port_text.isdecimal() or not 1 <= int(port_text) <= 65535:
            print("A porta deve ser um número entre 1 e 65535.")
            continue
        port = int(port_text)
        if not is_port_free(port):
            print(f"Atenção: A porta {port} já está em uso na máquina host! Escolha outra porta.")
            continue
        return port


def container_state(name):
    result = subprocess.run(
        ["docker", "container", "inspect", "-f", "{{.State.Running}}", name],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        return None
    return result.stdout.strip() == "true"


def wait_for_postgres(name):
    for _ in range(60):
        ready = subprocess.run(
            ["docker", "exec", name, "test", "-f", "/tmp/postgres-ready"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if ready.returncode == 0:
            check_pg = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-q", "-h", "localhost", "-U", "vault", "-d", "vault"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if check_pg.returncode == 0:
                return
        if container_state(name) is not True:
            break
        time.sleep(1)
    raise RuntimeError(f"Postgres não ficou pronto. Verifique: docker logs {name}")


def is_initialized(name):
    check = (
        "import sys, time\n"
        "from sqlalchemy import inspect\n"
        "from vault.database import engine, SessionLocal\n"
        "from vault.models import VaultConfig\n"
        "from vault import config\n"
        "for attempt in range(5):\n"
        "    try:\n"
        "        exists = inspect(engine).has_table('vault_config')\n"
        "        if exists:\n"
        "            db = SessionLocal()\n"
        "            has_key = db.get(VaultConfig, config.VERIFICATION_CONFIG_KEY) is not None\n"
        "            db.close()\n"
        "            print('yes' if has_key else 'no')\n"
        "        else:\n"
        "            print('no')\n"
        "        sys.exit(0)\n"
        "    except Exception as e:\n"
        "        if attempt == 4:\n"
        "            sys.stderr.write(f'Erro checando status do banco: {e}\\n')\n"
        "            sys.exit(1)\n"
        "        time.sleep(1)\n"
    )
    return run("exec", name, "python", "-c", check, capture=True) == "yes"


def wait_for_api(name, port):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    return data
        except (urllib.error.URLError, TimeoutError, http.client.RemoteDisconnected, ConnectionResetError):
            pass
        if container_state(name) is not True:
            break
        time.sleep(1)
    raise RuntimeError(f"API não ficou pronta. Verifique: docker logs {name}")


def find_running_container_with_volume(volume_name: str) -> str | None:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        return None
    for name in result.stdout.strip().splitlines():
        name = name.strip()
        if not name:
            continue
        inspect_mounts = subprocess.run(
            ["docker", "inspect", name, "--format", "{{json .Mounts}}"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        if inspect_mounts.returncode == 0 and volume_name in inspect_mounts.stdout:
            return name
    return None


def image_exists(image_name: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def ensure_image(image_name: str, force_build: bool = False):
    if not force_build and image_exists(image_name):
        print(f"Imagem Docker '{image_name}' encontrada. Pulando build.")
        return

    dockerfile_path = ROOT / "Dockerfile"
    if dockerfile_path.is_file():
        action = "Reconstruindo" if force_build else "Construindo"
        print(f"\n{action} imagem Docker '{image_name}' a partir do Dockerfile local...")
        run("build", "-t", image_name, ".")
        return

    if force_build:
        raise RuntimeError(f"Opção --build solicitada, mas Dockerfile não foi encontrado em: {dockerfile_path}")

    print(f"\nImagem '{image_name}' não encontrada localmente e Dockerfile ausente. Tentando pull...")
    run("pull", image_name)


# =========================================================================
# 1. BREAK-GLASS: Resgate offline de segredos
# =========================================================================
def rescue_offline(key_path_str: str, volume_name: str, output_file: str | None = None, image: str = "vault"):
    key_path = Path(key_path_str).expanduser().resolve()
    if not key_path.is_file():
        raise ValueError(f"Arquivo master.key não encontrado: {key_path}")

    print("\n[BREAK-GLASS] Iniciando resgate de emergência...")
    print(f"Volume do banco: {volume_name}")
    print(f"Master key:      {key_path}")

    running_container = find_running_container_with_volume(volume_name)

    if running_container:
        print(f"Container ativo '{running_container}' detectado utilizando este volume.")
        print("Executando extração diretamente do processo do container em execução...")
        cmd = [
            "docker", "exec", running_container,
            "vault-rescue", "--master-key", "/run/secrets/master.key",
            "--format", "json" if output_file else "text",
        ]
        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        print("Nenhum container ativo utilizando o volume. Subindo container efêmero isolado (--network none)...")
        rescue_cmd = (
            "export PATH=$(pg_config --bindir):$PATH; "
            "chown -R postgres:postgres /var/lib/postgresql/data; "
            "chmod 700 /var/lib/postgresql/data; "
            "rm -f /var/lib/postgresql/data/postmaster.pid; "
            "export POSTGRES_PASSWORD=$(cat /var/lib/postgresql/data/.db_password 2>/dev/null || echo vault); "
            "export DATABASE_URL=postgresql+psycopg2://vault:$POSTGRES_PASSWORD@localhost:5432/vault; "
            "if ! gosu postgres pg_ctl -D /var/lib/postgresql/data -o \"-c listen_addresses='localhost'\" -w start > /dev/null 2>&1; then "
            "    gosu postgres pg_resetwal -f /var/lib/postgresql/data > /dev/null 2>&1; "
            "    gosu postgres pg_ctl -D /var/lib/postgresql/data -o \"-c listen_addresses='localhost'\" -w start > /dev/null 2>&1; "
            "fi; "
            "vault-rescue --master-key /run/secrets/master.key"
            + (f" --format json" if output_file else " --format text")
            + "; gosu postgres pg_ctl -D /var/lib/postgresql/data -m fast -w stop > /dev/null 2>&1"
        )
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{volume_name}:/var/lib/postgresql/data",
                "--mount", f"type=bind,source={key_path},target=/run/secrets/master.key,readonly",
                "--network", "none",
                "--entrypoint", "bash",
                image, "-c", rescue_cmd
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    if result.returncode != 0:
        raise RuntimeError(f"Falha na extração de emergência: {result.stderr or result.stdout}")

    if output_file:
        out_path = Path(output_file).expanduser().resolve()
        out_path.write_text(result.stdout, encoding="utf-8")
        print(f"\n[SUCESSO] Segredos extraídos e salvos com sucesso em: {out_path}")
    else:
        print(result.stdout)


# =========================================================================
# 2. PROMOÇÃO MANUAL DE STANDBY PARA PRIMÁRIO (COM TRAVA ANTI-SPLIT-BRAIN)
# =========================================================================
def promote_standby(container_name: str, force: bool = False):
    print(f"\n[FAILOVER MANUAL] Verificando condições para promover o container '{container_name}'...")
    state = container_state(container_name)
    if state is None:
        raise ValueError(f"Container '{container_name}' não existe.")
    if state is False:
        raise ValueError(f"Container '{container_name}' está parado. Inicie-o antes de promover.")

    # Inspeciona variáveis de ambiente do container para identificar o PRIMARY_HOST
    inspect_env = subprocess.run(
        ["docker", "inspect", container_name, "--format", "{{json .Config.Env}}"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    primary_host = None
    if inspect_env.returncode == 0 and inspect_env.stdout.strip():
        try:
            for env_entry in json.loads(inspect_env.stdout):
                if env_entry.startswith("PRIMARY_HOST="):
                    primary_host = env_entry.split("=", 1)[1]
                    break
        except Exception:
            pass

    if primary_host and not force:
        # 1. Checa se o container do primário está ativo no Docker
        prim_running = container_state(primary_host)
        if prim_running is True:
            # 2. Checa se a API do primário está respondendo como master
            inspect_port = subprocess.run(
                ["docker", "port", primary_host, "8000"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            is_master = False
            if inspect_port.returncode == 0 and inspect_port.stdout.strip():
                port = inspect_port.stdout.strip().split(":")[-1]
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode())
                            if data.get("role") == "primary":
                                is_master = True
                except Exception:
                    pass

            raise RuntimeError(
                f"[VLT-5003] [SPLIT-BRAIN BLOQUEADO] O nó primário '{primary_host}' ainda está ATIVO e operando como MASTER!\n"
                "Promover o standby agora causaria divergência irreversível de dados (Split-Brain com dois masters).\n"
                f"Para prosseguir com o failover com segurança:\n"
                f"  1. Desligue o primário primeiro: docker stop {primary_host}\n"
                f"  2. Execute a promoção novamente: python deploy.py --promote {container_name}\n"
                "Ou passe --force caso o primário esteja isolado por partição de rede."
            )

    cmd = ["exec", container_name, "vault-promote"]
    if force:
        cmd.append("--force")
    result = run(*cmd, capture=True)
    print(result)

    # Verifica status via rota /health
    inspect_port = subprocess.run(
        ["docker", "port", container_name, "8000"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    if inspect_port.returncode == 0 and inspect_port.stdout.strip():
        port = inspect_port.stdout.strip().split(":")[-1]
        try:
            health = wait_for_api(container_name, int(port))
            print(f"Status atualizado do nó: {health}")
        except Exception:
            pass


# =========================================================================
# 3. WIZARD INTERATIVO DE DEPLOY (NÓ ÚNICO OU CLUSTER COM DR)
# =========================================================================
def interactive_deploy(image: str = "vault", force_build: bool = False):
    print(f"Vault Deploy | Sistema detectado: {platform.system()}")
    run("info", "--format", "{{.ServerVersion}}", capture=True)

    image_name = ask("Imagem Docker do Vault", image)
    enable_dr = ask("Deseja configurar Cluster com Réplica de DR (Hot Standby)? (s/N)", "n").lower() == "s"

    if enable_dr:
        deploy_cluster(image=image_name, force_build=force_build)
    else:
        deploy_standalone(image=image_name, force_build=force_build)


def deploy_standalone(image: str = "vault", force_build: bool = False):
    name = ask("Nome do container", "vault")
    state = container_state(name)
    if state is True:
        print(f"O container '{name}' já está rodando. Verifique: docker logs {name}")
        return
    if state is False:
        if ask(f"O container '{name}' está parado. Iniciar? (s/N)", "n").lower() == "s":
            run("start", name)
            print(f"Container '{name}' iniciado.")
        else:
            print(f"Para recriá-lo, remova-o primeiro com: docker rm {name}")
        return

    volume = ask("Volume Docker para o banco", "vault-data")
    port = ask_port("Porta local da API", 8000)

    folder = Path(ask("Pasta para master.key", str(ROOT / "vault-init-output"))).expanduser().resolve()
    key = folder / "master.key"
    if folder.exists() and not folder.is_dir():
        raise ValueError(f"O caminho não é uma pasta: {folder}")
    fresh = not key.is_file()
    admin_ip, admin_user, admin_password = None, None, None

    if fresh:
        admin_user = ask("Usuário do admin", "admin")
        admin_ip = ask("IP/CIDR autorizado para o admin (obrigatório; 0.0.0.0/0 libera todos)")
        if not admin_ip:
            raise ValueError("Informe o IP/CIDR do admin")
        try:
            ipaddress.ip_network(admin_ip, strict=False)
        except ValueError as error:
            raise ValueError("Informe um IP ou CIDR válido para o admin") from error
        admin_password = getpass.getpass("Senha do admin: ")
        if not admin_password or "\n" in admin_password or "\r" in admin_password:
            raise ValueError("A senha do admin não pode ser vazia nem conter quebras de linha")
        if len(admin_password.encode("utf-8")) > 72:
            raise ValueError("A senha do admin deve ter no máximo 72 bytes (limite do bcrypt)")
        if admin_password != getpass.getpass("Confirme a senha do admin: "):
            raise ValueError("As senhas não coincidem")

    ensure_image(image, force_build=force_build)
    run("volume", "create", volume, capture=True)

    if fresh:
        init_fresh_db(volume, folder, key, admin_user, admin_ip, admin_password, image=image)
    else:
        print(f"Usando master key existente: {key}")

    print("Iniciando API...")
    run("run", "-d", "--name", name, "-p", f"{port}:8000",
        "--mount", f"type=bind,source={key},target=/run/secrets/master.key,readonly",
        "-v", f"{volume}:/var/lib/postgresql/data", image, capture=True)

    health = wait_for_api(name, port)
    print(f"\n[SUCESSO] Vault no ar em http://localhost:{port}/docs | Role: {health.get('role', 'primary')}")


def deploy_cluster(image: str = "vault", force_build: bool = False):
    net_name = ask("Nome da rede Docker interna para o cluster", "vault-cluster-net")
    primary_name = ask("Nome do container Primário", "vault-primary")
    primary_port = int(ask("Porta da API do Primário", "8000"))
    primary_vol = ask("Volume do banco Primário", "vault-primary-data")

    dr_name = ask("Nome do container DR (Standby)", "vault-dr")
    dr_port = int(ask("Porta da API do DR", "8001"))
    dr_vol = ask("Volume do banco DR", "vault-dr-data")

    folder = Path(ask("Pasta para master.key", str(ROOT / "vault-init-output"))).expanduser().resolve()
    key = folder / "master.key"
    fresh = not key.is_file()
    admin_ip, admin_user, admin_password = None, None, None

    if fresh:
        admin_user = ask("Usuário do admin", "admin")
        admin_ip = ask("IP/CIDR autorizado para o admin (obrigatório; 0.0.0.0/0 libera todos)")
        if not admin_ip:
            raise ValueError("Informe o IP/CIDR do admin")
        admin_password = getpass.getpass("Senha do admin: ")
        if admin_password != getpass.getpass("Confirme a senha do admin: "):
            raise ValueError("As senhas não coincidem")

    ensure_image(image, force_build=force_build)

    # Verifica se os containers já existem antes de prosseguir
    for c_name in (primary_name, dr_name):
        c_state = container_state(c_name)
        if c_state is True:
            print(f"O container '{c_name}' já está em execução. Abortando deploy.")
            print(f"Para verificar os logs: docker logs {c_name}")
            return
        if c_state is False:
            if ask(f"O container '{c_name}' já existe (parado). Deseja removê-lo para recriar? (s/N)", "n").lower() != "s":
                print(f"Operação cancelada. Remova o container manualmente com 'docker rm {c_name}' se desejar.")
                return
            run("rm", c_name, capture=True)
            print(f"Container '{c_name}' removido.")

    # Cria rede e volumes
    networks = run("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    if net_name not in networks:
        run("network", "create", net_name, capture=True)

    run("volume", "create", primary_vol, capture=True)
    run("volume", "create", dr_vol, capture=True)

    if fresh:
        init_fresh_db(primary_vol, folder, key, admin_user, admin_ip, admin_password, image=image)

    # Inicia Primário
    print(f"\nIniciando nó Primário ({primary_name})...")
    run("run", "-d", "--name", primary_name, "--network", net_name,
        "-p", f"{primary_port}:8000",
        "-e", "REPLICATION_ROLE=primary",
        "--mount", f"type=bind,source={key},target=/run/secrets/master.key,readonly",
        "-v", f"{primary_vol}:/var/lib/postgresql/data", image, capture=True)

    health_p = wait_for_api(primary_name, primary_port)
    print(f"Nó Primário pronto! Role: {health_p.get('role')} (http://localhost:{primary_port}/docs)")

    # Inicia DR (Standby)
    print(f"\nIniciando nó DR ({dr_name})...")
    run("run", "-d", "--name", dr_name, "--network", net_name,
        "-p", f"{dr_port}:8000",
        "-e", "REPLICATION_ROLE=standby",
        "-e", f"PRIMARY_HOST={primary_name}",
        "--mount", f"type=bind,source={key},target=/run/secrets/master.key,readonly",
        "-v", f"{dr_vol}:/var/lib/postgresql/data", image, capture=True)

    health_dr = wait_for_api(dr_name, dr_port)
    print(f"Nó DR pronto! Role: {health_dr.get('role')} (http://localhost:{dr_port}/docs)")

    print("\n=======================================================")
    print("           CLUSTER DE ALTA DISPONIBILIDADE ATIVO       ")
    print("=======================================================")
    print(f"• Primário: http://localhost:{primary_port}/docs (Escrita & Leitura)")
    print(f"• Standby:  http://localhost:{dr_port}/docs (Somente Leitura - DR)")
    print("\nCOMO REALIZAR FAILOVER MANUAL:")
    print(f"1. De fora do container: python deploy.py --promote {dr_name}")
    print(f"2. De dentro do container: docker exec -it {dr_name} vault-promote")
    print("=======================================================\n")


def init_fresh_db(volume, folder, key, admin_user, admin_ip, admin_password, image: str = "vault"):
    folder.mkdir(parents=True, exist_ok=True)
    setup_name = f"vault-setup-{uuid.uuid4().hex[:8]}"
    print(f"Iniciando Postgres no container temporário {setup_name}...")
    run("run", "-d", "--name", setup_name, "-e", "VAULT_INIT_ONLY=1",
        "-v", f"{volume}:/var/lib/postgresql/data", image, capture=True)
    try:
        wait_for_postgres(setup_name)
        if is_initialized(setup_name):
            raise AlreadyInitializedError(
                f"O volume '{volume}' já contém um Vault inicializado, mas não há master.key em '{folder}'."
            )
        run("exec", "-i", setup_name, "vault-init", "init", "--output-dir", "/tmp/vault-init-output",
            "--admin-name", admin_user, "--admin-ip", admin_ip, "--admin-secret-stdin",
            input_text=admin_password + "\n")
        run("cp", f"{setup_name}:/tmp/vault-init-output/master.key", str(key))
        if not key.is_file():
            raise RuntimeError("Master key não chegou à pasta escolhida")
        if os.name != "nt":
            key.chmod(0o600)
            sudo_uid = os.environ.get("SUDO_UID")
            sudo_gid = os.environ.get("SUDO_GID")
            if sudo_uid and sudo_gid:
                try:
                    uid = int(sudo_uid)
                    gid = int(sudo_gid)
                    os.chown(str(key), uid, gid)
                    os.chown(str(folder), uid, gid)
                except Exception:
                    pass
    finally:
        run("stop", setup_name, capture=True)
        run("rm", setup_name, capture=True)
    print(f"Master key salva em: {key}")


# =========================================================================
# MAIN ENTRYPOINT
# =========================================================================
def main():
    parser = argparse.ArgumentParser(description="Vault Deploy & Cluster Manager")
    parser.add_argument("--image", default="vault", help="Nome ou tag da imagem Docker do Vault (padrão: vault)")
    parser.add_argument("--build", action="store_true", help="Força a reconstrução da imagem Docker mesmo se já existir localmente")
    parser.add_argument("--promote", nargs="?", const="vault-dr", help="Promove um no standby para primario (ex: --promote vault-dr)")
    parser.add_argument("--force", action="store_true", help="Ignora a trava anti-split-brain na promocao")
    parser.add_argument("--rescue", action="store_true", help="Executa extracao de emergencia offline (Break-Glass)")
    parser.add_argument("--key", help="Caminho do master.key (obrigatorio para --rescue)")
    parser.add_argument("--volume", help="Nome do volume Docker do banco (obrigatorio para --rescue)")
    parser.add_argument("--output", help="Arquivo JSON de saida para os segredos (opcional para --rescue)")

    args = parser.parse_args()

    if args.promote:
        promote_standby(args.promote, force=args.force)
    elif args.rescue:
        if not args.key or not args.volume:
            print("Erro: --rescue requer --key <caminho_master.key> e --volume <nome_volume>", file=sys.stderr)
            sys.exit(1)
        rescue_offline(args.key, args.volume, args.output, image=args.image)
    else:
        interactive_deploy(image=args.image, force_build=args.build)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        cmd_str = " ".join(error.cmd) if isinstance(error.cmd, list) else str(error.cmd)
        print(f"\nErro ao executar comando: {cmd_str}", file=sys.stderr)
        if error.stderr:
            print(f"Stderr: {error.stderr.strip()}", file=sys.stderr)
        if error.stdout:
            print(f"Stdout: {error.stdout.strip()}", file=sys.stderr)
        sys.exit(error.returncode or 1)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"\nErro: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrompido.", file=sys.stderr)
        sys.exit(1)
