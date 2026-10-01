"""
Motor PKI Interno (X.509 / mTLS) para o Vault.
Gera Root CA, emite certificados de nos (com SANs para IPs e DNS)
e certificados de clientes para replicacao mutua (mTLS).
Totalmente compativel com Bring-Your-Own-Certificate (BYO-Cert).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path
from typing import List, Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Gera chave privada RSA com expoente publico 65537."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def serialize_private_key(key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
    """Serializa chave privada RSA para PEM (formato PKCS8 tradicional)."""
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
    loaded_key = serialization.load_pem_private_key(pem_bytes, password=pwd)
    if not isinstance(loaded_key, rsa.RSAPrivateKey):
        raise TypeError("A chave privada fornecida nao e do tipo RSA")
    return loaded_key


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serializa certificado X.509 para formato PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem_bytes: bytes) -> x509.Certificate:
    """Carrega certificado X.509 a partir de bytes PEM."""
    return x509.load_pem_x509_certificate(pem_bytes)


def create_root_ca(
    common_name: str = "Vault Internal Root CA",
    organization: str = "Vault Cluster",
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


def _build_san_extension(common_name: str, sans: List[str]) -> x509.SubjectAlternativeName:
    """Constroi SubjectAlternativeName com IPs e DNS Names validos."""
    entries = set(sans or [])
    if common_name:
        entries.add(common_name)

    general_names: list[x509.GeneralName] = []
    for entry in sorted(entries):
        entry_str = entry.strip()
        if not entry_str:
            continue
        try:
            ip_obj = ipaddress.ip_address(entry_str)
            general_names.append(x509.IPAddress(ip_obj))
        except ValueError:
            general_names.append(x509.DNSName(entry_str))

    return x509.SubjectAlternativeName(general_names)


def issue_node_certificate(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str,
    sans: List[str],
    days_valid: int = 365,
    key_size: int = 2048,
    is_server: bool = True,
    is_client: bool = True,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Emite certificado para um no com SANs configurados e suporte a mTLS."""
    node_key = generate_private_key(key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    san_ext = _build_san_extension(common_name, sans)

    eku_oids = []
    if is_server:
        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if is_client:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
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
            x509.ExtendedKeyUsage(eku_oids),
            critical=False,
        )
        .add_extension(
            san_ext,
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(node_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, node_key


def issue_client_certificate(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    common_name: str = "replicator",
    days_valid: int = 365,
    key_size: int = 2048,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Emite certificado estrito de cliente mTLS (para o replicator do PostgreSQL ou API client)."""
    return issue_node_certificate(
        ca_cert=ca_cert,
        ca_key=ca_key,
        common_name=common_name,
        sans=[common_name],
        days_valid=days_valid,
        key_size=key_size,
        is_server=False,
        is_client=True,
    )


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
        san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for name in san:
            if is_ip and isinstance(name, x509.IPAddress) and name.value == ip_obj:
                return True
            if not is_ip and isinstance(name, x509.DNSName) and name.value.lower() == host.lower():
                return True
    except x509.ExtensionNotFound:
        pass

    # Checa CN como fallback
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if str(attr.value).lower() == host.lower():
            return True
    return False


def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verifica se o certificado foi assinado pela CA fornecida."""
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


def save_pki_bundle(
    output_dir: Path | str,
    ca_cert: x509.Certificate,
    ca_key: Optional[rsa.RSAPrivateKey],
    node_cert: x509.Certificate,
    node_key: rsa.RSAPrivateKey,
    client_cert: Optional[x509.Certificate] = None,
    client_key: Optional[rsa.RSAPrivateKey] = None,
) -> Path:
    """Salva os certificados e chaves em output_dir com permissoes seguras."""
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    (out / "ca.crt").write_bytes(serialize_certificate(ca_cert))
    if ca_key:
        ca_key_path = out / "ca.key"
        ca_key_path.write_bytes(serialize_private_key(ca_key))
        if os.name != "nt":
            ca_key_path.chmod(0o600)

    server_crt = out / "server.crt"
    server_crt.write_bytes(serialize_certificate(node_cert))

    server_key = out / "server.key"
    server_key.write_bytes(serialize_private_key(node_key))
    if os.name != "nt":
        server_key.chmod(0o600)

    if client_cert and client_key:
        client_crt_path = out / "client.crt"
        client_crt_path.write_bytes(serialize_certificate(client_cert))
        client_key_path = out / "client.key"
        client_key_path.write_bytes(serialize_private_key(client_key))
        if os.name != "nt":
            client_key_path.chmod(0o600)

    return out
