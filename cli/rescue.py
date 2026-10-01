"""Break-Glass Rescue Tool:
Extracao offline de segredos diretamente do banco de dados utilizando a master.key.
Funciona offline, mesmo com a API web desligada ou o container principal inacessivel.
"""

import base64
import json
import os
import sys

import click

from vault import config, crypto
from vault.database import SessionLocal
from vault.models import Secret, Vault


@click.command()
@click.option("--master-key", "key_path", default=None, help="Caminho do arquivo master.key.")
@click.option("--output", "output_path", default=None, help="Caminho do arquivo JSON de saida (opcional).")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", help="Formato de exibicao.")
def cli(key_path, output_path, fmt):
    """Extrai todos os secrets diretamente do banco de dados em situacao de emergencia (break-glass)."""
    key_path = key_path or config.MASTER_KEY_FILE
    if not os.path.isfile(key_path):
        click.echo(f"[RESCUE ERROR] Arquivo de master key nao encontrado em: {key_path}", err=True)
        sys.exit(1)

    try:
        with open(key_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        key_bytes = base64.b64decode(raw)
        if len(key_bytes) != crypto.KEY_SIZE:
            raise ValueError(f"Tamanho invalido ({len(key_bytes)} bytes; esperado {crypto.KEY_SIZE})")
    except Exception as e:
        click.echo(f"[RESCUE ERROR] Falha ao processar master key: {e}", err=True)
        sys.exit(1)

    db = SessionLocal()
    try:
        secrets = db.query(Secret).join(Vault).order_by(Vault.name, Secret.name).all()
        recovered = []
        for s in secrets:
            try:
                dek = crypto.decrypt_dek(key_bytes, s.encrypted_dek)
                val = crypto.decrypt(dek, s.ciphertext).decode("utf-8")
                recovered.append({
                    "vault": s.vault.name if s.vault else "default",
                    "name": s.name,
                    "version": s.version,
                    "value": val,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                })
            except Exception as decrypt_err:
                recovered.append({
                    "vault": s.vault.name if s.vault else "default",
                    "name": s.name,
                    "version": s.version,
                    "error": f"Falha na decriptografia com a chave fornecida: {decrypt_err}",
                })

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(recovered, f, indent=2, ensure_ascii=False)
            click.echo(f"[RESCUE] {len(recovered)} segredo(s) extraido(s) com sucesso para {output_path}", err=True)
        elif fmt == "json":
            click.echo(json.dumps(recovered, indent=2, ensure_ascii=False))
        else:
            click.echo(f"\n==================================================")
            click.echo(f"   RELATORIO DE RESGATE DE EMERGENCIA (BREAK-GLASS)  ")
            click.echo(f"   Total de segredos localizados: {len(recovered)}")
            click.echo(f"==================================================\n")
            for item in recovered:
                click.echo(f"Cofre:   {item['vault']}")
                click.echo(f"Secret:  {item['name']} (versao {item.get('version', 1)})")
                if "value" in item:
                    click.echo(f"Valor:   {item['value']}")
                else:
                    click.echo(f"Status:  ERRO -> {item['error']}")
                click.echo("-" * 50)
    finally:
        db.close()


if __name__ == "__main__":
    cli()
