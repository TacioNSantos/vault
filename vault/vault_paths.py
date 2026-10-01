import re


VAULT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def vault_name_from_secret(name: str) -> str:
    """O primeiro segmento nomeia o cofre; os demais são o caminho interno."""
    parts = name.split("/")
    if len(parts) < 2 or not VAULT_NAME_PATTERN.fullmatch(parts[0]) or any(
        part in ("", ".", "..") for part in parts[1:]
    ):
        raise ValueError("use um nome no formato 'cofre/secret' (subpastas opcionais)")
    return parts[0]


def legacy_vault_name(name: str) -> str:
    """Segredos antigos sem prefixo são agrupados no cofre 'default'."""
    prefix = name.partition("/")[0]
    return prefix if "/" in name and VAULT_NAME_PATTERN.fullmatch(prefix) else "default"
