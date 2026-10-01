"""
Motor PKI Interno (X.509 / mTLS) para o Vault no modelo CyberArk Conjur.
- Certificado único de cluster compartilhado entre líder e standbys (serverAuth + clientAuth).
- Validação estrita de certificados BYO (Bring-Your-Own-Certificate).
- Gerenciamento de chaves privadas cifradas em repouso (*.key.enc via master key).
- Instalação segura em memória volátil (tmpfs /dev/shm) no boot.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID

from vault import crypto


class PKIError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class BYOValidationError(PKIError):
    pass


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Gera chave privada RSA com expoente publico 65537."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def serialize_private_key(key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
    """Serializa chave privada RSA para PEM tradicional OpenSSL."""
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )


def load_private_key(pem_bytes: bytes, password: Optional[str] = None) -> rsa.RSAPrivateKey:
    """Carrega chave privada RSA a partir de bytes PEM."""
    pwd = password.encode("utf-8") if password else None
    try:
        loaded_key = serialization.load_pem_private_key(pem_bytes, password=pwd)
    except Exception as e:
        raise PKIError("VLT-1009", f"Falha ao carregar chave privada PEM: {e}")
    if not isinstance(loaded_key, rsa.RSAPrivateKey):
        raise PKIError("VLT-1009", "A chave privada fornecida nao e do tipo RSA")
    return loaded_key


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serializa certificado X.509 para formato PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem_bytes: bytes) -> x509.Certificate:
    """Carrega certificado X.509 a partir de bytes PEM."""
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as e:
        raise PKIError("VLT-1009", f"Falha ao carregar certificado X.509 PEM: {e}")


def encrypt_private_key(key: rsa.RSAPrivateKey, master_key: bytes) -> bytes:
    """Cifra a chave privada RSA com a master.key (AES-256-GCM) para repouso."""
    pem_bytes = serialize_private_key(key)
    return crypto.encrypt(master_key, pem_bytes)


def decrypt_private_key(enc_bytes: bytes, master_key: bytes) -> rsa.RSAPrivateKey:
    """Decifra chave privada RSA a partir de bytes cifrados com a master.key."""
    try:
        pem_bytes = crypto.decrypt(master_key, enc_bytes)
    except Exception as e:
        raise PKIError("VLT-1004", f"Falha ao decifrar chave privada com a master key: {e}")
    return load_private_key(pem_bytes)


def create_root_ca(
    common_name: str = "Vault Internal Root CA",
    organization: str = "Vault Cluster PKI",
    days_valid: int = 3650,
    key_size: int = 4096,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Cria uma Root CA autoassinada (X.509 v3, CA=True)."""
    ca_key = generate_private_key(key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return cert, ca_key


def _build_san_extension(hostname: str, altnames: List[str]) -> x509.SubjectAlternativeName:
    """Constroi SubjectAlternativeName normalizado com IPAddress e DNSName."""
    entries = set()
    if hostname:
        entries.add(hostname.strip())
    for item in altnames or []:
        cleaned = item.strip()
        if cleaned:
            entries.add(cleaned)

    # Sempre inclui localhost e 127.0.0.1 para healthchecks e administracao local
    entries.add("localhost")
    entries.add("127.0.0.1")

    general_names: list[x509.GeneralName] = []
    for entry in sorted(entries):
        try:
            ip_obj = ipaddress.ip_address(entry)
            general_names.append(x509.IPAddress(ip_obj))
        except ValueError:
            general_names.append(x509.DNSName(entry))

    return x509.SubjectAlternativeName(general_names)


def create_cluster_certificate(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    hostname: str,
    altnames: List[str],
    days_valid: int = 365,
    key_size: int = 2048,
    existing_key: Optional[rsa.RSAPrivateKey] = None,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """
    Emite o Certificado Unico de Cluster (estilo CyberArk Conjur).
    Compartilhado por lider e standbys para HTTPS, Postgres TLS e mTLS replication.
    EKU configurado com serverAuth E clientAuth.
    """
    cluster_key = existing_key or generate_private_key(key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    san_ext = _build_san_extension(hostname, altnames)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(cluster_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            san_ext,
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cluster_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, cluster_key


def cert_days_remaining(cert: x509.Certificate) -> int:
    """Calcula quantos dias restam ate a expiracao do certificado."""
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    delta = not_after - datetime.datetime.now(datetime.timezone.utc)
    return max(0, delta.days)


def is_certificate_valid_for_host(cert: x509.Certificate, host: str) -> bool:
    """Verifica se o certificado contem o IP ou DNS fornecido no SAN ou CN."""
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for name in san:
            if is_ip and isinstance(name, x509.IPAddress) and name.value == ip_obj:
                return True
            if not is_ip and isinstance(name, x509.DNSName) and name.value.lower() == host.lower():
                return True
    except x509.ExtensionNotFound:
        pass

    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if str(attr.value).lower() == host.lower():
            return True
    return False


def get_certificate_sans(cert: x509.Certificate) -> List[str]:
    """Retorna lista de SANs presentes no certificado."""
    results = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for name in san:
            results.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    return sorted(list(set(results)))


def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verifica criptograficamente se o certificado foi assinado pela CA fornecida."""
    try:
        public_key = ca_cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        return False
    except Exception:
        return False


def validate_byo_certificates(
    cert_pem: bytes,
    key_pem: bytes,
    ca_pem: bytes,
    hostname: str,
    altnames: List[str],
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey, x509.Certificate, Optional[str]]:
    """
    Valida rigorosamente os certificados fornecidos externamente (BYO-Cert).
    Garante:
    1. PEMs validos e correspondencia de chave privada.
    2. Cadeia valida contra a CA.
    3. SANs cobrindo hostname e todos os altnames.
    4. EKU contendo serverAuth e clientAuth.
    5. Certificado nao expirado.
    Retorna (cert, key, ca_cert, warning_message).
    """
    cert = load_certificate(cert_pem)
    key = load_private_key(key_pem)
    ca_cert = load_certificate(ca_pem)

    # 1. Correspondencia da chave privada com o certificado
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise BYOValidationError("VLT-1009", "A chave privada fornecida nao corresponde ao certificado do cluster.")

    # 2. Verificacao de cadeia de assinatura
    if not verify_certificate_chain(cert, ca_cert):
        raise BYOValidationError("VLT-1009", "O certificado do cluster nao foi assinado pela CA fornecida.")

    # 3. Cobertura de SANs
    required_hosts = set(altnames or [])
    if hostname:
        required_hosts.add(hostname)
    missing = [h for h in required_hosts if not is_certificate_valid_for_host(cert, h)]
    if missing:
        raise BYOValidationError(
            "VLT-1009",
            f"O certificado fornecido nao cobre os seguintes hostnames/IPs exigidos: {', '.join(missing)}",
        )

    # 4. Validacao de Extended Key Usage (serverAuth + clientAuth)
    try:
        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        has_server = ExtendedKeyUsageOID.SERVER_AUTH in eku_ext
        has_client = ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext
        if not (has_server and has_client):
            raise BYOValidationError(
                "VLT-1009",
                "O certificado do cluster deve possuir ExtendedKeyUsage para Server Auth e Client Auth (mTLS).",
            )
    except x509.ExtensionNotFound:
        raise BYOValidationError(
            "VLT-1009",
            "Extensao ExtendedKeyUsage ausente no certificado. Necessario serverAuth e clientAuth.",
        )

    # 5. Expiracao
    days = cert_days_remaining(cert)
    if days <= 0:
        raise BYOValidationError("VLT-1009", "O certificado fornecido ja esta expirado.")

    warning = None
    if days < 30:
        warning = f"Aviso: O certificado BYO fornecido expira em {days} dias."

    return cert, key, ca_cert, warning


def save_cluster_pki_to_disk(
    storage_dir: Path | str,
    master_key: bytes,
    ca_cert: x509.Certificate,
    cluster_cert: x509.Certificate,
    cluster_key: rsa.RSAPrivateKey,
    ca_key: Optional[rsa.RSAPrivateKey] = None,
) -> Path:
    """
    Grava certificados publicos e chaves privadas cifradas (*.key.enc) no disco.
    Nunca grava chaves privadas em texto puro no volume.
    """
    out = Path(storage_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Certificados publicos
    (out / "ca.crt").write_bytes(serialize_certificate(ca_cert))
    (out / "cluster.crt").write_bytes(serialize_certificate(cluster_cert))

    # Chaves privadas CIFRADAS com a master key
    cluster_enc = encrypt_private_key(cluster_key, master_key)
    (out / "cluster.key.enc").write_bytes(cluster_enc)
    if os.name != "nt":
        (out / "cluster.key.enc").chmod(0o600)

    if ca_key:
        ca_enc = encrypt_private_key(ca_key, master_key)
        (out / "ca.key.enc").write_bytes(ca_enc)
        if os.name != "nt":
            (out / "ca.key.enc").chmod(0o600)

    return out


def install_keys_to_tmpfs(
    storage_dir: Path | str,
    master_key: bytes,
    tmpfs_dir: str = "/dev/shm/vault_tls",
) -> Path:
    """
    Decifra as chaves privadas diretamente para a memoria volátil (tmpfs).
    Utilizado no boot pelo entrypoint para alimentar o PostgreSQL e Uvicorn.
    """
    s_dir = Path(storage_dir).expanduser().resolve()
    target = Path(tmpfs_dir)

    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fallback se /dev/shm nao estiver disponivel
        target = Path("/tmp/vault_tls")
        target.mkdir(parents=True, exist_ok=True)

    if os.name != "nt":
        target.chmod(0o700)

    # Copia certificados publicos
    shutil.copyfile(str(s_dir / "ca.crt"), str(target / "ca.crt"))
    shutil.copyfile(str(s_dir / "cluster.crt"), str(target / "server.crt"))

    # Decifra chave do cluster para memoria
    cluster_enc_path = s_dir / "cluster.key.enc"
    if not cluster_enc_path.is_file():
        raise PKIError("VLT-1008", f"cluster.key.enc ausente em {s_dir}")

    cluster_key = decrypt_private_key(cluster_enc_path.read_bytes(), master_key)
    server_key_path = target / "server.key"
    server_key_path.write_bytes(serialize_private_key(cluster_key))
    if os.name != "nt":
        server_key_path.chmod(0o600)

    # Se houver ca.key.enc, decifra tambem
    ca_enc_path = s_dir / "ca.key.enc"
    if ca_enc_path.is_file():
        ca_key = decrypt_private_key(ca_enc_path.read_bytes(), master_key)
        ca_key_path = target / "ca.key"
        ca_key_path.write_bytes(serialize_private_key(ca_key))
        if os.name != "nt":
            ca_key_path.chmod(0o600)

    # Ajusta dono para usuario postgres se no Linux
    if os.name != "nt" and os.getuid() == 0:
        import pwd
        try:
            pg_uid = pwd.getpwnam("postgres").pw_uid
            pg_gid = pwd.getpwnam("postgres").pw_gid
            os.chown(str(target), pg_uid, pg_gid)
            for f in target.glob("*"):
                os.chown(str(f), pg_uid, pg_gid)
        except Exception:
            pass

    return target


def shred_tmpfs_keys(tmpfs_dir: str = "/dev/shm/vault_tls"):
    """Remove e limpa completamente as chaves em memoria volátil no shutdown."""
    target = Path(tmpfs_dir)
    if target.is_dir():
        for f in target.glob("*"):
            try:
                length = f.stat().st_size
                f.write_bytes(b"\x00" * length)
            except Exception:
                pass
        shutil.rmtree(str(target), ignore_errors=True)
