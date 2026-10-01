from setuptools import setup, find_packages

setup(
    name="vaultctl",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click==8.1.7",
        "SQLAlchemy==2.0.35",
        "psycopg2-binary==2.9.9",
        "cryptography==43.0.1",
        "bcrypt==4.2.0",
    ],
    entry_points={
        "console_scripts": [
            "vaultctl=cli.vaultctl:cli",
            "vault-rescue=cli.rescue:cli",
            "vault-promote=cli.vault_promote:cli",
        ],
    },
)
