"""
Envelope encryption.

- Master Key (KEK): existe so em memoria, nunca tocamos disco com ela em claro
  fora do momento do vault-init (onde vira um arquivo entregue ao admin).
- Data Encryption Key (DEK): 1 por secret, gerada aleatoria, criptografada
  pela master key e guardada junto do secret no banco.
- O valor do secret em si eh criptografado pela DEK, nao pela master key
  diretamente (isso permite rotacionar a master key no futuro sem re-
  criptografar todo o payload, so as DEKs).

Formato de blob criptografado, sempre: nonce(12 bytes) + ciphertext(+tag).
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256


def generate_key() -> bytes:
    """Gera uma chave aleatoria de 256 bits (usada para master key e DEKs)."""
    return AESGCM.generate_key(bit_length=256)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("chave precisa ter 32 bytes (AES-256)")
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, associated_data: bytes = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("chave precisa ter 32 bytes (AES-256)")
    if len(blob) < NONCE_SIZE:
        raise ValueError("blob criptografado invalido")
    aesgcm = AESGCM(key)
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def encrypt_dek(master_key: bytes, dek: bytes) -> bytes:
    return encrypt(master_key, dek)


def decrypt_dek(master_key: bytes, encrypted_dek: bytes) -> bytes:
    return decrypt(master_key, encrypted_dek)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
