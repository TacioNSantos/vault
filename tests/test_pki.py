import os
import shutil
import tempfile
import unittest

from vault import pki, crypto


class TestPKIEngine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.master_key = crypto.generate_key()

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

    def test_create_cluster_certificate_with_sans_and_dual_eku(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            hostname="vault.exemplo.com",
            altnames=["vault1.exemplo.com", "vault2.exemplo.com", "10.10.20.10", "10.10.20.20"],
            days_valid=30,
            key_size=2048,
        )

        self.assertIsNotNone(cluster_cert)
        self.assertIsNotNone(cluster_key)
        self.assertTrue(pki.verify_certificate_chain(cluster_cert, ca_cert))

        # Testa validacao de hosts no SAN
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "vault.exemplo.com"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "vault1.exemplo.com"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "vault2.exemplo.com"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "10.10.20.10"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "10.10.20.20"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "localhost"))
        self.assertTrue(pki.is_certificate_valid_for_host(cluster_cert, "127.0.0.1"))
        self.assertFalse(pki.is_certificate_valid_for_host(cluster_cert, "outro-host"))

        # Dias restantes
        self.assertGreaterEqual(pki.cert_days_remaining(cluster_cert), 28)

    def test_save_encrypted_and_install_to_tmpfs(self):
        ca_cert, ca_key = pki.create_root_ca(days_valid=30, key_size=2048)
        cluster_cert, cluster_key = pki.create_cluster_certificate(
            ca_cert=ca_cert,
            ca_key=ca_key,
            hostname="vault.cluster",
            altnames=["10.10.20.10"],
            days_valid=30,
            key_size=2048,
        )

        storage_dir = os.path.join(self.tmp_dir, "storage_tls")
        pki.save_cluster_pki_to_disk(
            storage_dir=storage_dir,
            master_key=self.master_key,
            ca_cert=ca_cert,
            cluster_cert=cluster_cert,
            cluster_key=cluster_key,
            ca_key=ca_key,
        )

        # Chaves privadas no disco sao SEMPRE cifradas (*.key.enc)
        self.assertTrue(os.path.isfile(os.path.join(storage_dir, "ca.crt")))
        self.assertTrue(os.path.isfile(os.path.join(storage_dir, "cluster.crt")))
        self.assertTrue(os.path.isfile(os.path.join(storage_dir, "ca.key.enc")))
        self.assertTrue(os.path.isfile(os.path.join(storage_dir, "cluster.key.enc")))
        self.assertFalse(os.path.isfile(os.path.join(storage_dir, "server.key")))
        self.assertFalse(os.path.isfile(os.path.join(storage_dir, "cluster.key")))

        # Instala chaves decifradas em tmpfs
        tmpfs_dir = os.path.join(self.tmp_dir, "tmpfs_tls")
        target = pki.install_keys_to_tmpfs(storage_dir, self.master_key, tmpfs_dir=tmpfs_dir)

        self.assertTrue(os.path.isfile(os.path.join(str(target), "ca.crt")))
        self.assertTrue(os.path.isfile(os.path.join(str(target), "server.crt")))
        self.assertTrue(os.path.isfile(os.path.join(str(target), "server.key")))
        self.assertTrue(os.path.isfile(os.path.join(str(target), "ca.key")))

        # Testa limpeza segura (shred)
        pki.shred_tmpfs_keys(str(target))
        self.assertFalse(os.path.exists(str(target)))


if __name__ == "__main__":
    unittest.main()
