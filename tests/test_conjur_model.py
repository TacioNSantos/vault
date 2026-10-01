import base64
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from click.testing import CliRunner

from cli.vaultctl import cli
from vault import pki, crypto


class TestConjurModelPKIAndCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.runner = CliRunner()
        self.master_key = crypto.generate_key()
        self.master_key_file = os.path.join(self.tmp_dir, "master.key")
        with open(self.master_key_file, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(self.master_key).decode("ascii") + "\n")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # =========================================================================
    # 1. BYO CERTIFICATE VALIDATION TESTS
    # =========================================================================
    def test_byo_valid_case(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault1.exemplo.com", "vault2.exemplo.com", "10.10.20.10", "10.10.20.20"],
            days_valid=365,
            key_size=2048,
        )

        cert_pem = pki.serialize_certificate(cluster_cert)
        key_pem = pki.serialize_private_key(cluster_key)
        ca_pem = pki.serialize_certificate(ca_cert)

        c, k, ca, warning = pki.validate_byo_certificates(
            cert_pem, key_pem, ca_pem,
            hostname="vault.exemplo.com",
            altnames=["vault1.exemplo.com", "10.10.20.10"],
        )
        self.assertIsNotNone(c)
        self.assertIsNotNone(k)
        self.assertIsNotNone(ca)
        self.assertIsNone(warning)

    def test_byo_key_mismatch(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, _ = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["10.10.20.10"],
            key_size=2048,
        )
        wrong_key = pki.generate_private_key(key_size=2048)

        with self.assertRaises(pki.BYOValidationError) as ctx:
            pki.validate_byo_certificates(
                pki.serialize_certificate(cluster_cert),
                pki.serialize_private_key(wrong_key),
                pki.serialize_certificate(ca_cert),
                hostname="vault.exemplo.com",
                altnames=["10.10.20.10"],
            )
        self.assertIn("nao corresponde", ctx.exception.message)

    def test_byo_ca_mismatch(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["10.10.20.10"],
            key_size=2048,
        )
        different_ca_cert, _ = pki.create_root_ca(common_name="Other CA", key_size=2048)

        with self.assertRaises(pki.BYOValidationError) as ctx:
            pki.validate_byo_certificates(
                pki.serialize_certificate(cluster_cert),
                pki.serialize_private_key(cluster_key),
                pki.serialize_certificate(different_ca_cert),
                hostname="vault.exemplo.com",
                altnames=["10.10.20.10"],
            )
        self.assertIn("nao foi assinado pela CA", ctx.exception.message)

    def test_byo_missing_san(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault1.exemplo.com"],
            key_size=2048,
        )

        with self.assertRaises(pki.BYOValidationError) as ctx:
            pki.validate_byo_certificates(
                pki.serialize_certificate(cluster_cert),
                pki.serialize_private_key(cluster_key),
                pki.serialize_certificate(ca_cert),
                hostname="vault.exemplo.com",
                altnames=["vault1.exemplo.com", "vault2.exemplo.com"],  # vault2 ausente
            )
        self.assertIn("nao cobre os seguintes hostnames", ctx.exception.message)
        self.assertIn("vault2.exemplo.com", ctx.exception.message)

    def test_byo_expired_cert(self):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_key = pki.generate_private_key(key_size=2048)
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "vault.exemplo.com")]))
            .issuer_name(ca_cert.subject)
            .public_key(cluster_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=60))
            .not_valid_after(now - datetime.timedelta(days=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(pki._build_san_extension("vault.exemplo.com", ["10.10.20.10"]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        with self.assertRaises(pki.BYOValidationError) as ctx:
            pki.validate_byo_certificates(
                pki.serialize_certificate(expired_cert),
                pki.serialize_private_key(cluster_key),
                pki.serialize_certificate(ca_cert),
                hostname="vault.exemplo.com",
                altnames=["10.10.20.10"],
            )
        self.assertIn("expirado", ctx.exception.message)

    def test_byo_missing_client_auth_eku(self):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_key = pki.generate_private_key(key_size=2048)
        no_client_auth_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "vault.exemplo.com")]))
            .issuer_name(ca_cert.subject)
            .public_key(cluster_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(pki._build_san_extension("vault.exemplo.com", ["10.10.20.10"]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        with self.assertRaises(pki.BYOValidationError) as ctx:
            pki.validate_byo_certificates(
                pki.serialize_certificate(no_client_auth_cert),
                pki.serialize_private_key(cluster_key),
                pki.serialize_certificate(ca_cert),
                hostname="vault.exemplo.com",
                altnames=["10.10.20.10"],
            )
        self.assertIn("ExtendedKeyUsage", ctx.exception.message)

    # =========================================================================
    # 2. SEED SECURITY: NO PLAINTEXT KEYS, NO MASTER.KEY
    # =========================================================================
    def test_seed_security_properties(self):
        pgdata = Path(self.tmp_dir) / "pgdata"
        tls_dir = pgdata / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)

        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault2.exemplo.com", "10.10.20.20"],
            days_valid=365,
            key_size=2048,
        )

        pki.save_cluster_pki_to_disk(
            tls_dir, self.master_key, ca_cert, cluster_cert, cluster_key, ca_key
        )

        cluster_meta = {
            "role": "primary",
            "hostname": "vault.exemplo.com",
            "altnames": ["vault2.exemplo.com", "10.10.20.20"],
            "ca_type": "internal",
        }
        (pgdata / "cluster.json").write_text(json.dumps(cluster_meta), encoding="utf-8")

        seed_output = Path(self.tmp_dir) / "test.seed.tar"

        env = {
            "PGDATA": str(pgdata),
            "MASTER_KEY_FILE": self.master_key_file,
        }

        res = self.runner.invoke(
            cli,
            ["seed", "standby", "vault2.exemplo.com", "--output", str(seed_output)],
            env=env,
        )
        self.assertEqual(res.exit_code, 0, msg=res.output)
        self.assertTrue(seed_output.is_file())

        with tarfile.open(seed_output, "r") as tar:
            names = tar.getnames()

            # 1. master.key NUNCA deve estar dentro do seed
            self.assertNotIn("master.key", names)
            self.assertNotIn("./master.key", names)

            # 2. Chaves privadas em texto puro NUNCA devem existir
            self.assertNotIn("cluster.key", names)
            self.assertNotIn("ca.key", names)
            self.assertNotIn("server.key", names)

            # 3. As chaves devem estar cifradas como *.key.enc
            self.assertIn("cluster.key.enc", names)
            self.assertIn("ca.key.enc", names)
            self.assertIn("cluster.crt", names)
            self.assertIn("ca.crt", names)
            self.assertIn("seed.json", names)

            # 4. Verifica que cluster.key.enc decifra com a master.key
            cluster_enc = tar.extractfile("cluster.key.enc").read()
            decrypted_key = pki.decrypt_private_key(cluster_enc, self.master_key)
            self.assertEqual(decrypted_key.key_size, 2048)

    # =========================================================================
    # 3. UNPACK VIA STDIN (-) AND MASTER.KEY VALIDATION
    # =========================================================================
    def test_unpack_via_stdin_and_key_validation(self):
        # Gera seed
        pgdata_leader = Path(self.tmp_dir) / "leader_data"
        tls_dir = pgdata_leader / "tls"
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault2.exemplo.com"],
            key_size=2048,
        )
        pki.save_cluster_pki_to_disk(
            tls_dir, self.master_key, ca_cert, cluster_cert, cluster_key, ca_key
        )
        (pgdata_leader / "cluster.json").write_text(json.dumps({
            "role": "primary", "hostname": "vault.exemplo.com", "altnames": ["vault2.exemplo.com"],
        }), encoding="utf-8")

        seed_file = Path(self.tmp_dir) / "standby.seed.tar"
        self.runner.invoke(
            cli,
            ["seed", "standby", "vault2.exemplo.com", "--output", str(seed_file)],
            env={"PGDATA": str(pgdata_leader), "MASTER_KEY_FILE": self.master_key_file},
        )
        seed_bytes = seed_file.read_bytes()

        # Testa unpack via stdin '-' com master.key correta
        pgdata_standby = Path(self.tmp_dir) / "standby_data"
        pgdata_standby.mkdir(parents=True, exist_ok=True)

        res_unpack = self.runner.invoke(
            cli,
            ["unpack", "seed", "-"],
            input=seed_bytes,
            env={"PGDATA": str(pgdata_standby), "MASTER_KEY_FILE": self.master_key_file},
        )
        self.assertEqual(res_unpack.exit_code, 0, msg=res_unpack.output)
        self.assertTrue((pgdata_standby / "seed_stage" / "cluster.crt").is_file())
        self.assertTrue((pgdata_standby / "seed_stage" / "cluster.key.enc").is_file())

        # Testa unpack com master.key ERRADA
        wrong_master_key_file = Path(self.tmp_dir) / "wrong.key"
        wrong_master_key_file.write_text(base64.b64encode(crypto.generate_key()).decode("ascii") + "\n")

        pgdata_standby_err = Path(self.tmp_dir) / "standby_err_data"
        pgdata_standby_err.mkdir(parents=True, exist_ok=True)

        res_err = self.runner.invoke(
            cli,
            ["unpack", "seed", "-"],
            input=seed_bytes,
            env={"PGDATA": str(pgdata_standby_err), "MASTER_KEY_FILE": str(wrong_master_key_file)},
        )
        self.assertNotEqual(res_err.exit_code, 0)
        self.assertIn("VLT-1004", res_err.output)

    # =========================================================================
    # 4. VAULTCTL CA ISSUE --FORCE
    # =========================================================================
    def test_ca_issue_reissues_cert_with_new_sans(self):
        pgdata = Path(self.tmp_dir) / "pgdata_ca"
        tls_dir = pgdata / "tls"
        ca_cert, ca_key = pki.create_root_ca(days_valid=365, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert, ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault1.exemplo.com"],
            key_size=2048,
        )
        pki.save_cluster_pki_to_disk(
            tls_dir, self.master_key, ca_cert, cluster_cert, cluster_key, ca_key
        )
        (pgdata / "cluster.json").write_text(json.dumps({
            "role": "primary",
            "hostname": "vault.exemplo.com",
            "altnames": ["vault1.exemplo.com"],
            "ca_type": "internal",
        }), encoding="utf-8")

        # Antes: não tem vault3.exemplo.com
        old_cert = pki.load_certificate((tls_dir / "cluster.crt").read_bytes())
        self.assertFalse(pki.is_certificate_valid_for_host(old_cert, "vault3.exemplo.com"))

        # Executa ca issue
        res_issue = self.runner.invoke(
            cli,
            ["ca", "issue", "vault3.exemplo.com", "10.10.30.30", "--force"],
            env={"PGDATA": str(pgdata), "MASTER_KEY_FILE": self.master_key_file},
        )
        self.assertEqual(res_issue.exit_code, 0, msg=res_issue.output)

        # Depois: tem vault3.exemplo.com e 10.10.30.30
        new_cert = pki.load_certificate((tls_dir / "cluster.crt").read_bytes())
        self.assertTrue(pki.is_certificate_valid_for_host(new_cert, "vault3.exemplo.com"))
        self.assertTrue(pki.is_certificate_valid_for_host(new_cert, "10.10.30.30"))
        self.assertTrue(pki.is_certificate_valid_for_host(new_cert, "vault1.exemplo.com"))

        # cluster.json foi atualizado
        meta = json.loads((pgdata / "cluster.json").read_text(encoding="utf-8"))
        self.assertIn("vault3.exemplo.com", meta["altnames"])
        self.assertIn("10.10.30.30", meta["altnames"])


if __name__ == "__main__":
    unittest.main()
