import os
import shutil
import tempfile
import unittest
from click.testing import CliRunner

from cli.vaultctl import cli
from vault import pki, crypto


class TestVaultctlCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_seed_and_join_flow(self):
        # 1. Cria ambiente simulando o output do primário
        master_key_file = os.path.join(self.tmp_dir, "master.key")
        with open(master_key_file, "wb") as f:
            f.write(b"dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLXNlY3JldCE=")

        tls_dir = os.path.join(self.tmp_dir, "tls")
        os.makedirs(tls_dir, exist_ok=True)
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        node_cert, node_key = pki.issue_node_certificate(ca_cert, ca_key, "vault-primary", ["127.0.0.1"])
        client_cert, client_key = pki.issue_client_certificate(ca_cert, ca_key, "replicator")
        pki.save_pki_bundle(tls_dir, ca_cert, ca_key, node_cert, node_key, client_cert, client_key)

        seed_file = os.path.join(self.tmp_dir, "replica.seed.tar")

        # 2. Executa comando 'vaultctl seed standby'
        res_seed = self.runner.invoke(cli, [
            "seed", "standby", "10.10.20.20",
            "--key", master_key_file,
            "--tls-dir", tls_dir,
            "--output", seed_file,
            "--primary-host", "10.10.20.10",
        ])
        self.assertEqual(res_seed.exit_code, 0, msg=res_seed.output)
        self.assertTrue(os.path.isfile(seed_file))

        # 3. Executa comando 'vaultctl join' na pasta de destino da réplica
        standby_conf_dir = os.path.join(self.tmp_dir, "standby-config")
        res_join = self.runner.invoke(cli, [
            "join",
            "--seed", seed_file,
            "--output-dir", standby_conf_dir,
        ])
        self.assertEqual(res_join.exit_code, 0, msg=res_join.output)

        # 4. Valida se os arquivos necessários para mTLS e boot estão desempacotados
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "master.key")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "tls", "ca.crt")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "tls", "server.crt")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "tls", "server.key")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "tls", "client.crt")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "tls", "client.key")))
        self.assertTrue(os.path.isfile(os.path.join(standby_conf_dir, "seed.json")))

        # 5. Testa 'vaultctl certs inspect'
        cert_path = os.path.join(standby_conf_dir, "tls", "server.crt")
        res_inspect = self.runner.invoke(cli, ["certs", "inspect", cert_path])
        self.assertEqual(res_inspect.exit_code, 0)
        self.assertIn("VÁLIDO", res_inspect.output)
        self.assertIn("10.10.20.20", res_inspect.output)


if __name__ == "__main__":
    unittest.main()
