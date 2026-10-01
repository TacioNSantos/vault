import os
import shutil
import tempfile
import unittest

from vault import pki


class TestPKIEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_create_root_ca(self):
        ca_cert, ca_key = pki.create_root_ca(
            common_name="Test Root CA",
            organization="Test Corp",
            days_valid=365,
            key_size=2048,
        )
        self.assertIsNotNone(ca_cert)
        self.assertIsNotNone(ca_key)

        pem_cert = pki.serialize_certificate(ca_cert)
        self.assertTrue(pem_cert.startswith(b"-----BEGIN CERTIFICATE-----"))

        pem_key = pki.serialize_private_key(ca_key)
        self.assertTrue(b"PRIVATE KEY-----" in pem_key)

        loaded_cert = pki.load_certificate(pem_cert)
        self.assertEqual(loaded_cert.serial_number, ca_cert.serial_number)

        loaded_key = pki.load_private_key(pem_key)
        self.assertEqual(loaded_key.key_size, 2048)

    def test_issue_node_certificate_with_sans(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        node_cert, node_key = pki.issue_node_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name="vault-primary",
            sans=["127.0.0.1", "10.10.20.10", "localhost", "vault-primary"],
            days_valid=30,
            key_size=2048,
        )

        self.assertIsNotNone(node_cert)
        self.assertIsNotNone(node_key)
        self.assertTrue(pki.verify_certificate_chain(node_cert, ca_cert))

        # Testa validacao de hosts no SAN
        self.assertTrue(pki.is_certificate_valid_for_host(node_cert, "127.0.0.1"))
        self.assertTrue(pki.is_certificate_valid_for_host(node_cert, "10.10.20.10"))
        self.assertTrue(pki.is_certificate_valid_for_host(node_cert, "localhost"))
        self.assertTrue(pki.is_certificate_valid_for_host(node_cert, "vault-primary"))
        self.assertFalse(pki.is_certificate_valid_for_host(node_cert, "192.168.1.99"))
        self.assertFalse(pki.is_certificate_valid_for_host(node_cert, "outro-host"))

        # Dias restantes
        self.assertGreaterEqual(pki.cert_days_remaining(node_cert), 28)

    def test_issue_client_certificate(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        client_cert, client_key = pki.issue_client_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name="replicator",
            days_valid=30,
            key_size=2048,
        )
        self.assertIsNotNone(client_cert)
        self.assertTrue(pki.verify_certificate_chain(client_cert, ca_cert))
        self.assertTrue(pki.is_certificate_valid_for_host(client_cert, "replicator"))

    def test_save_and_load_pki_bundle(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        node_cert, node_key = pki.issue_node_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name="vault-node1",
            sans=["127.0.0.1"],
            days_valid=30,
            key_size=2048,
        )
        client_cert, client_key = pki.issue_client_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            common_name="replicator",
            days_valid=30,
            key_size=2048,
        )

        pki.save_pki_bundle(
            output_dir=self.tmp_dir,
            ca_cert=ca_cert,
            ca_key=ca_key,
            node_cert=node_cert,
            node_key=node_key,
            client_cert=client_cert,
            client_key=client_key,
        )

        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "ca.crt")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "ca.key")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "server.crt")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "server.key")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "client.crt")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp_dir, "client.key")))


if __name__ == "__main__":
    unittest.main()
