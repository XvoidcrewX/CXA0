# CXA - Complete Test Suite Tests all system

import unittest
import tempfile
import os
import sys
import io
from PIL import Image

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from main import (
        AdvancedCryptoEngine, AdvancedKeyManager, SecureMemoryManager,
        TextSteganography, ImageSteganography, AuditSystem, SecurityMonitor,
        SecureDataEraser, KeyType, SecurityLevel, UltraResistanceLevel
    )
    IMPORT_SUCCESS = True
except ImportError as e:
    print(f"Import error: {e}")
    IMPORT_SUCCESS = False


class TestCryptoEngine(unittest.TestCase):
    
    def setUp(self):
        self.crypto = AdvancedCryptoEngine()
        self.test_data = b"Test secret message"
        self.test_password = "TestPassword123!"
    
    def test_aes_gcm_encryption(self):
        key = self.crypto.generate_symmetric_key(256)
        ciphertext, nonce = self.crypto.encrypt_aes_gcm(key, self.test_data)
        plaintext = self.crypto.decrypt_aes_gcm(key, ciphertext, nonce)
        self.assertEqual(plaintext, self.test_data)
    
    def test_chacha20_encryption(self):
        key = self.crypto.generate_symmetric_key(256)
        ciphertext, nonce = self.crypto.encrypt_chacha20(key, self.test_data)
        plaintext = self.crypto.decrypt_chacha20(key, ciphertext, nonce)
        self.assertEqual(plaintext, self.test_data)
    
    def test_rsa_key_generation(self):
        public_key, private_key = self.crypto.generate_rsa_keypair(2048)
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)
        self.assertIn(b'PUBLIC KEY', public_key)
    
    def test_rsa_encryption(self):
        public_key, private_key = self.crypto.generate_rsa_keypair(2048)
        ciphertext = self.crypto.encrypt_rsa_oaep(public_key, self.test_data)
        plaintext = self.crypto.decrypt_rsa_oaep(private_key, ciphertext)
        self.assertEqual(plaintext, self.test_data)
    
    def test_key_derivation(self):
        salt = os.urandom(32)
        derived_key = self.crypto.derive_key(self.test_password, salt, 100000)
        self.assertEqual(len(derived_key), 32)
    
    def test_digital_signatures(self):
        public_key, private_key = self.crypto.generate_rsa_keypair(2048)
        signature_result = self.crypto.sign_message_rsa(private_key, self.test_data)
        self.assertTrue(signature_result['success'])
        
        verification_result = self.crypto.verify_signature_rsa(
            public_key, 
            signature_result['signature'], 
            self.test_data
        )
        self.assertTrue(verification_result['valid'])


class TestKeyManager(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.temp_dir, "test_keystore.vault")
        self.key_manager = AdvancedKeyManager(self.keystore_path)
        self.test_password = "TestMasterPassword123!"
        self.key_manager.initialize_master_key(self.test_password)
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_master_key_initialization(self):
        self.assertIsNotNone(self.key_manager.master_key)
        self.assertEqual(len(self.key_manager.master_key), 32)
    
    def test_rsa_key_generation(self):
        key_id = self.key_manager.generate_key_pair(
            KeyType.RSA_4096, 
            SecurityLevel.HIGH,
            expires_days=30
        )
        self.assertIsNotNone(key_id)
        self.assertIn(key_id, self.key_manager.keys)
    
    def test_aes_key_generation(self):
        key_id = self.key_manager.generate_key_pair(
            KeyType.AES_256,
            SecurityLevel.HIGH
        )
        key_entry = self.key_manager.get_key(key_id)
        self.assertIsNotNone(key_entry.symmetric_key)
        self.assertEqual(len(key_entry.symmetric_key), 32)
    
    def test_key_retrieval(self):
        key_id = self.key_manager.generate_key_pair(KeyType.AES_256, SecurityLevel.HIGH)
        retrieved_key = self.key_manager.get_key(key_id)
        self.assertIsNotNone(retrieved_key)
        self.assertEqual(retrieved_key.meta.key_id, key_id)
    
    def test_keystore_persistence(self):
        key_id = self.key_manager.generate_key_pair(KeyType.AES_256, SecurityLevel.HIGH)
        self.key_manager._save_keystore()
        self.assertTrue(os.path.exists(self.keystore_path))
        
        new_manager = AdvancedKeyManager(self.keystore_path)
        new_manager.master_key = self.key_manager.master_key
        new_manager._load_keystore()
        self.assertIn(key_id, new_manager.keys)


class TestSteganography(unittest.TestCase):
    
    def setUp(self):
        self.test_secret = b"Secret hidden message!"
        self.carrier_text = "Normal text document " * 50
        
        self.test_image = Image.new('RGB', (100, 100), color='red')
        self.image_buffer = io.BytesIO()
        self.test_image.save(self.image_buffer, format='PNG')
        self.image_data = self.image_buffer.getvalue()
        
        self.text_stego = TextSteganography()
        self.image_stego = ImageSteganography()
        self.encryption_key = os.urandom(32)
    
    def test_text_steganography_basic(self):
        stego_text, embedding_map = self.text_stego.embed_in_text_lsb(
            self.test_secret, 
            self.carrier_text,
            encryption_key=None
        )
        extracted_data = self.text_stego.extract_from_text_lsb(
            stego_text,
            embedding_map,
            decryption_key=None
        )
        self.assertEqual(extracted_data, self.test_secret)
    
    def test_text_steganography_encrypted(self):
        stego_text, embedding_map = self.text_stego.embed_in_text_lsb(
            self.test_secret,
            self.carrier_text,
            encryption_key=self.encryption_key
        )
        extracted_data = self.text_stego.extract_from_text_lsb(
            stego_text,
            embedding_map,
            decryption_key=self.encryption_key
        )
        self.assertEqual(extracted_data, self.test_secret)
    
    def test_image_steganography_basic(self):
        stego_image, embedding_map = self.image_stego.embed_in_image_lsb(
            self.test_secret,
            self.image_data,
            encryption_key=None
        )
        extracted_data = self.image_stego.extract_from_image_lsb(
            stego_image,
            embedding_map,
            decryption_key=None
        )
        self.assertEqual(extracted_data, self.test_secret)


class TestMemoryManager(unittest.TestCase):
    
    def setUp(self):
        self.memory_manager = SecureMemoryManager()
        self.sensitive_data = b"Sensitive data in memory"
    
    def test_secure_store_retrieve(self):
        buffer_id = self.memory_manager.secure_store_encrypted(self.sensitive_data)
        retrieved_data = self.memory_manager.secure_retrieve_decrypted(buffer_id)
        self.assertEqual(retrieved_data, self.sensitive_data)
    
    def test_secure_deletion(self):
        buffer_id = self.memory_manager.secure_store_encrypted(self.sensitive_data)
        self.assertIn(buffer_id, self.memory_manager._secure_buffers)
        
        self.memory_manager.secure_delete(buffer_id)
        self.assertNotIn(buffer_id, self.memory_manager._secure_buffers)
    
    def test_memory_encryption(self):
        self.memory_manager.encryption_enabled = True
        buffer_id = self.memory_manager.secure_store_encrypted(self.sensitive_data)
        self.assertIn(buffer_id, self.memory_manager.memory_guards)
        
        retrieved_data = self.memory_manager.secure_retrieve_decrypted(buffer_id)
        self.assertEqual(retrieved_data, self.sensitive_data)


class TestSecuritySystems(unittest.TestCase):
    
    def setUp(self):
        self.audit_system = AuditSystem()
        self.security_monitor = SecurityMonitor()
        self.data_eraser = SecureDataEraser()
    
    def test_audit_logging(self):
        self.audit_system.log_event("TEST_EVENT", "Test details", True, "LOW")
        self.audit_system.log_sensitive_operation("KEY_GENERATION", "test_user", "Generated key")
        self.assertTrue(os.path.exists('security_audit.log'))
    
    def test_audit_sanitization(self):
        sensitive_details = "Password: secret123, key: KEY-12345"
        sanitized = self.audit_system.sanitize_log_details(sensitive_details)
        self.assertNotIn("secret123", sanitized)
        self.assertIn("[REDACTED]", sanitized)
    
    def test_security_monitoring(self):
        self.security_monitor.monitor_system_calls("rm -rf /", "test_user")
        self.assertGreaterEqual(len(self.security_monitor.incident_log), 1)
    
    def test_secure_file_deletion(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"Test data")
            temp_path = temp_file.name
        
        self.data_eraser.secure_wipe_file(temp_path, passes=3)
        self.assertFalse(os.path.exists(temp_path))


class TestIntegrationScenarios(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.keystore_path = os.path.join(self.temp_dir, "integration_test.vault")
        self.key_manager = AdvancedKeyManager(self.keystore_path)
        self.key_manager.initialize_master_key("TestPassword123!")
        
        self.crypto_engine = AdvancedCryptoEngine()
        self.text_stego = TextSteganography(encryption_enabled=True)
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_complete_encryption_workflow(self):
        key_id = self.key_manager.generate_key_pair(KeyType.AES_256, SecurityLevel.HIGH)
        key_entry = self.key_manager.get_key(key_id)
        
        test_data = b"Confidential business data"
        ciphertext, nonce = self.crypto_engine.encrypt_aes_gcm(key_entry.symmetric_key, test_data)
        plaintext = self.crypto_engine.decrypt_aes_gcm(key_entry.symmetric_key, ciphertext, nonce)
        
        self.assertEqual(plaintext, test_data)
    
    def test_secure_communication(self):
        rsa_key_id = self.key_manager.generate_key_pair(KeyType.RSA_4096, SecurityLevel.ULTRA)
        rsa_key = self.key_manager.get_key(rsa_key_id)
        
        session_key = self.crypto_engine.generate_symmetric_key(256)
        message = b"Secret message"
        encrypted_message, nonce = self.crypto_engine.encrypt_aes_gcm(session_key, message)
        encrypted_session_key = self.crypto_engine.encrypt_rsa_oaep(rsa_key.public_key, session_key)
        
        decrypted_session_key = self.crypto_engine.decrypt_rsa_oaep(rsa_key.encrypted_private_key, encrypted_session_key)
        decrypted_message = self.crypto_engine.decrypt_aes_gcm(decrypted_session_key, encrypted_message, nonce)
        
        self.assertEqual(decrypted_message, message)


class TestPerformanceAndStress(unittest.TestCase):
    
    def setUp(self):
        self.crypto_engine = AdvancedCryptoEngine()
        self.memory_manager = SecureMemoryManager()
    
    def test_encryption_performance(self):
        test_sizes = [1024, 10240, 102400]
        key = self.crypto_engine.generate_symmetric_key(256)
        
        for size in test_sizes:
            test_data = os.urandom(size)
            
            import time
            start_time = time.time()
            ciphertext, nonce = self.crypto_engine.encrypt_aes_gcm(key, test_data)
            encryption_time = time.time() - start_time
            
            start_time = time.time()
            plaintext = self.crypto_engine.decrypt_aes_gcm(key, ciphertext, nonce)
            decryption_time = time.time() - start_time
            
            self.assertEqual(plaintext, test_data)
            self.assertLess(encryption_time, 5.0)
            self.assertLess(decryption_time, 5.0)
    
    def test_memory_stress(self):
        buffer_ids = []
        for i in range(10):
            large_data = os.urandom(1024 * 1024)
            buffer_id = self.memory_manager.secure_store_encrypted(large_data, f"stress_test_{i}")
            buffer_ids.append(buffer_id)
        
        for buffer_id in buffer_ids:
            retrieved = self.memory_manager.secure_retrieve_decrypted(buffer_id)
            self.assertIsNotNone(retrieved)
        
        for buffer_id in buffer_ids:
            self.memory_manager.secure_delete(buffer_id)
        
        usage_stats = self.memory_manager.get_memory_usage()
        self.assertEqual(usage_stats['total_buffers'], 0)


def run_comprehensive_tests():
    if not IMPORT_SUCCESS:
        print("❌ Cannot run tests - Required modules not available")
        return False
    
    print("🧪 RUNNING CXA CRYPTO SYSTEM TESTS")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyManager))
    suite.addTests(loader.loadTestsFromTestCase(TestSteganography))
    suite.addTests(loader.loadTestsFromTestCase(TestMemoryManager))
    suite.addTests(loader.loadTestsFromTestCase(TestSecuritySystems))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegrationScenarios))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceAndStress))
    
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    print("=" * 60)
    print(f"📊 TEST SUMMARY:")
    print(f"   Tests Run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    print(f"   Success: {result.wasSuccessful()}")
    
    if result.wasSuccessful():
        print("🎉 ALL TESTS PASSED! System is operational.")
    else:
        print("❌ SOME TESTS FAILED! Review errors above.")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)
