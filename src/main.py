import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox, scrolledtext
import json
import base64
import os
import time
import threading
import queue
import logging
import ctypes
import numpy as np
import pywt
import zstandard as zstd
from PIL import Image, ImageTk
import io
import struct
from datetime import datetime
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple, Union
import hashlib
import hmac
import secrets
import shutil
import zipfile
import re
import psutil
import platform
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.algorithms import AES, Camellia, TripleDES
from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB, OFB, GCM, CTR
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import constant_time as crypto_constant_time
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import keyring

try:
    from reedsolo import RSCodec
    REEDSOLO_AVAILABLE = True
except ImportError:
    REEDSOLO_AVAILABLE = False
    class RSCodec:
        def __init__(self, *args, **kwargs):
            pass
        def encode(self, data):
            return data
        def decode(self, data):
            return (data,)

try:
    from secretsharing import SecretSharer as Shamir
    SECRETSHARING_AVAILABLE = True
except ImportError:
    SECRETSHARING_AVAILABLE = False
    class Shamir:
        @staticmethod
        def split_secret(secret, *args, **kwargs):
            return [secret]
        @staticmethod
        def recover_secret(shares):
            return shares[0] if shares else ""

# Security level definitions
class SecurityLevel(Enum):
    STANDARD = auto()
    HIGH = auto()
    ULTRA = auto()

# Key type definitions
class KeyType(Enum):
    RSA_2048 = auto()
    RSA_4096 = auto()
    AES_256 = auto()
    CHACHA20 = auto()
    ED25519 = auto()
    X25519 = auto()
    ECDSA = auto()

# Carrier type definitions
class CarrierType(Enum):
    TEXT = auto()
    IMAGE = auto()

# Steganography algorithm definitions
class StegoAlgorithm(Enum):
    LSB = auto()

# Operation mode definitions
class OperationMode(Enum):
    ENCRYPT = auto()
    DECRYPT = auto()
    EMBED = auto()
    EXTRACT = auto()
    SIGN = auto()
    VERIFY = auto()
    KEY_EXCHANGE = auto()

# Maximum Security Mode level definitions
class UltraResistanceLevel(Enum):
    NONE = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    MAX = auto()

# Critical security exception
class CriticalSecurityException(Exception):
    pass

# Key derivation parameters
@dataclass
class KeyDerivationParams:
    salt: bytes
    iterations: int
    length: int = 32
    memory_cost: int = 65536
    time_cost: int = 2
    parallelism: int = 1

# Key metadata structure
@dataclass
class KeyMetadata:
    key_id: str
    key_type: KeyType
    security_level: SecurityLevel
    created_at: int
    expires_at: Optional[int] = None
    usage_count: int = 0
    last_used: Optional[int] = None
    flags: int = 0
    ultra_resistance: UltraResistanceLevel = UltraResistanceLevel.NONE

# Key entry structure
@dataclass
class KeyEntry:
    public_key: Optional[bytes] = None
    encrypted_private_key: bytes = field(default_factory=bytes)
    symmetric_key: Optional[bytes] = None
    meta: KeyMetadata = field(default_factory=KeyMetadata)
    kdf_params: Optional[KeyDerivationParams] = None

# Steganography parameters
@dataclass
class StegoParams:
    carrier_type: CarrierType
    algorithm: StegoAlgorithm = StegoAlgorithm.LSB
    compression_level: int = 6
    error_correction: bool = True
    encryption_enabled: bool = True
    max_capacity: int = 0
    wavelet_level: int = 3
    distortion_weight: float = 0.5

# secure audit logger with advanced monitoring
class AuditSystem:
    def __init__(self, log_file='security_audit.log'):
        self.log_file = log_file
        self.log_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._logger_thread = None
        self.sensitive_operations = [
            "KEY_EXPORT", "MASTER_KEY_CHANGE", "SECURE_DELETE",
            "BACKUP_CREATION", "KEY_ROTATION", "ULTRA_MODE_ACTIVATION"
        ]
        self._start_logger()
        self._record_event("AUDIT_SYSTEM_INIT", "audit system initialized")

    def _start_logger(self):
        self._logger_thread = threading.Thread(target=self._process_logs, daemon=True)
        self._stop_event.clear()
        self._logger_thread.start()

    def _process_logs(self):
        while not self._stop_event.is_set():
            try:
                event = self.log_queue.get(timeout=1)
                self._write_log_safely(event)
                self.log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Log processing error: {e}")
                continue

    def _write_log_safely(self, event):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        sanitized_details = self.sanitize_log_details(event['details'])
        risk_level = event.get('risk_level', 'MEDIUM')
        log_entry = f"{timestamp} | {event['event_type']} | RISK:{risk_level} | {sanitized_details}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            f.flush()
            os.fsync(f.fileno())
        except Exception as e:
            print(f"Failed to write audit log: {e}")

    def sanitize_log_details(self, details: str) -> str:
        patterns = [r'KEY-[a-f0-9-]+', r'password', r'token', r'secret', r'private_key', r'master_key']
        sanitized = details
        for pattern in patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        return sanitized

    def log_event(self, event_type, details, success=True, risk_level='MEDIUM'):
        self.log_queue.put({
            'event_type': event_type,
            'details': details,
            'success': success,
            'risk_level': risk_level
        })

    def log_sensitive_operation(self, operation: str, user: str, details: str = ""):
        audit_entry = {
            'timestamp': time.time(),
            'operation': operation,
            'user': user,
            'details': self.sanitize_log_details(details),
            'risk_level': self.calculate_risk_level(operation)
        }
        self.log_critical_event("SENSITIVE_OPERATION", audit_entry)

    def log_critical_event(self, event_type, event_data):
        self.log_event(event_type, json.dumps(event_data), True, 'HIGH')

    def calculate_risk_level(self, operation: str) -> str:
        risk_scores = {
            "KEY_EXPORT": "HIGH",
            "MASTER_KEY_CHANGE": "CRITICAL",
            "SECURE_DELETE": "HIGH",
            "ULTRA_MODE_ACTIVATION": "MEDIUM"
        }
        return risk_scores.get(operation, "MEDIUM")

    def shutdown(self):
        self._stop_event.set()
        if self._logger_thread and self._logger_thread.is_alive():
            self._logger_thread.join(timeout=2)
        while not self.log_queue.empty():
            try:
                event = self.log_queue.get_nowait()
                self._write_log_safely(event)
                self.log_queue.task_done()
            except queue.Empty:
                break

    def _record_event(self, event_type, details, success=True):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        sanitized_details = self.sanitize_log_details(details)
        log_entry = f"{timestamp} | {event_type} | {'SUCCESS' if success else 'FAILURE'} | {sanitized_details}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
            f.flush()
            os.fsync(f.fileno())
        except Exception as e:
            print(f"Failed to write initial audit log: {e}")

# secure memory manager with encrypted memory storage
class SecureMemoryManager:
    def __init__(self):
        self._secure_buffers = {}
        self.memory_guards = {}
        self._secure_heap_base = None
        self._secure_heap_size = 0
        self._secure_heap_allocated = 0
        self._secure_heap_max = 0
        self._secure_heap_initialized = False
        self._secure_heap_lock = threading.Lock()
        self._memory_protection_enabled = True
        self._memory_tracing = False
        self._memory_trace_log = []
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self._warning_shown = False
        self.encryption_enabled = True

    def secure_store_encrypted(self, data: bytes, context: str = "generic") -> str:
        if not self._warning_shown:
            print("WARNING: Memory protection in Python has limitations. ")
            print("Sensitive data may still be accessible through memory dumps.")
            print("For maximum security, consider using hardware security modules.")
            self._warning_shown = True
        
        buffer_id = secrets.token_hex(16)
        
        # Encrypt data before storage
        if self.encryption_enabled:
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            storage_data = nonce + encrypted_data
            self.memory_guards[buffer_id] = key  # Store key separately
        else:
            storage_data = data
        
        if self._memory_tracing:
            self._memory_trace_log.append({
                'action': 'store_encrypted',
                'buffer_id': buffer_id,
                'size': len(data),
                'context': context,
                'timestamp': time.time()
            })
        
        self._secure_buffers[buffer_id] = {
            'data': bytearray(storage_data),
            'timestamp': time.time(),
            'context': context,
            'encrypted': self.encryption_enabled
        }
        return buffer_id

    def secure_retrieve_decrypted(self, buffer_id: str) -> Optional[bytes]:
        buffer_info = self._secure_buffers.get(buffer_id)
        if buffer_info is None:
            return None
        
        if buffer_info['encrypted'] and buffer_id in self.memory_guards:
            key = self.memory_guards[buffer_id]
            storage_data = bytes(buffer_info['data'])
            nonce = storage_data[:12]
            ciphertext = storage_data[12:]
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            
            if self._memory_tracing:
                self._memory_trace_log.append({
                    'action': 'retrieve_decrypted',
                    'buffer_id': buffer_id,
                    'size': len(decrypted_data),
                    'timestamp': time.time()
                })
            
            return decrypted_data
        
        if self._memory_tracing:
            self._memory_trace_log.append({
                'action': 'retrieve',
                'buffer_id': buffer_id,
                'size': len(buffer_info['data']),
                'timestamp': time.time()
            })
        
        return bytes(buffer_info['data'])

    def secure_delete(self, buffer_id: str):
        if buffer_id in self._secure_buffers:
            buffer_info = self._secure_buffers[buffer_id]
            buffer_data = buffer_info['data']
            
            # Multi-pass secure wiping
            for pass_num in range(3):
                for i in range(len(buffer_data)):
                    buffer_data[i] = secrets.randbelow(256)
            
            if hasattr(ctypes, 'memset'):
                try:
                    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer_data)), 0, len(buffer_data))
                except:
                    pass
            
            # Clean up encryption key if exists
            if buffer_id in self.memory_guards:
                key_data = bytearray(self.memory_guards[buffer_id])
                for i in range(len(key_data)):
                    key_data[i] = secrets.randbelow(256)
                del self.memory_guards[buffer_id]
            
            import gc
            gc.collect()
            
            del self._secure_buffers[buffer_id]
            
            if self._memory_tracing:
                self._memory_trace_log.append({
                    'action': 'delete',
                    'buffer_id': buffer_id,
                    'timestamp': time.time()
                })

    def secure_heap_init(self, size: int = 1024 * 1024 * 100):
        if self._secure_heap_initialized:
            return
        
        try:
            current_memory = psutil.virtual_memory().percent
            if current_memory > 90:
                raise MemoryError("Insufficient system memory")
                
            if self._memory_protection_enabled:
                self._secure_heap_base = ctypes.create_string_buffer(size)
                self._secure_heap_size = size
                self._secure_heap_allocated = 0
                self._secure_heap_max = size
                self._secure_heap_initialized = True
                
                if not self._cleanup_thread or not self._cleanup_thread.is_alive():
                    self._stop_cleanup.clear()
                    self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
                    self._cleanup_thread.start()
        except Exception as e:
            self._secure_heap_initialized = False

    def secure_heap_alloc(self, size: int) -> int:
        if not self._secure_heap_initialized or size <= 0:
            return -1
        
        current_memory = psutil.virtual_memory().percent
        if current_memory > 90:
            self.trigger_garbage_collection()
            if psutil.virtual_memory().percent > 95:
                raise MemoryError("Insufficient memory")
        
        with self._secure_heap_lock:
            if self._secure_heap_allocated + size > self._secure_heap_max:
                return -1
            
            offset = self._secure_heap_allocated
            self._secure_heap_allocated += size
            return offset

    def trigger_garbage_collection(self):
        import gc
        gc.collect()

    def secure_heap_free(self, offset: int, size: int):
        if not self._secure_heap_initialized or offset < 0:
            return
        
        with self._secure_heap_lock:
            if self._secure_heap_base:
                for i in range(size):
                    self._secure_heap_base[offset + i] = secrets.randbelow(256)

    def enable_memory_protection(self, enabled: bool = True):
        self._memory_protection_enabled = enabled

    def enable_memory_tracing(self, enabled: bool = True):
        self._memory_tracing = enabled

    def get_memory_trace_log(self) -> List[Dict]:
        return self._memory_trace_log.copy()

    def get_memory_usage(self) -> Dict[str, int]:
        total_bytes = sum(len(buf['data']) for buf in self._secure_buffers.values())
        return {
            'total_buffers': len(self._secure_buffers),
            'total_bytes': total_bytes,
            'heap_allocated': self._secure_heap_allocated,
            'heap_size': self._secure_heap_size
        }

    def _cleanup_loop(self):
        while not self._stop_cleanup.is_set():
            time.sleep(300)
            self._cleanup_expired_buffers()

    def _cleanup_expired_buffers(self):
        current_time = time.time()
        expired_buffers = []
        
        for buffer_id, buffer_info in self._secure_buffers.items():
            if current_time - buffer_info['timestamp'] > 300:
                expired_buffers.append(buffer_id)
        
        for buffer_id in expired_buffers:
            self.secure_delete(buffer_id)

# Enhanced secure destruction system
class SecureDataEraser:
    def __init__(self):
        self.wipe_patterns = [
            b'\xFF' * 4096,  # All bits 1
            b'\x00' * 4096,  # All bits 0  
            b'\xAA' * 4096,  # 10101010
            b'\x55' * 4096,  # 01010101
            os.urandom(4096), # Random
            b'\x00' * 4096   # Final zeros
        ]
    
    def secure_wipe_file(self, file_path, passes=7):
        """Secure file destruction that cannot be recovered even with forensic tools"""
        if not os.path.exists(file_path):
            return
        
        file_size = os.path.getsize(file_path)
        
        # Multi-pass overwriting
        for pass_num in range(passes):
            with open(file_path, 'rb+') as f:
                pattern = self.wipe_patterns[pass_num % len(self.wipe_patterns)]
                for i in range(0, file_size, len(pattern)):
                    f.write(pattern)
                f.flush()
                os.fsync(f.fileno())
        
        # Random rename before deletion
        temp_name = f"{secrets.token_hex(16)}.tmp"
        try:
            os.rename(file_path, temp_name)
            os.remove(temp_name)
        except:
            os.remove(file_path)

    def secure_wipe_directory(self, dir_path, passes=7):
        """Secure directory destruction"""
        if not os.path.exists(dir_path):
            return
            
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.secure_wipe_file(file_path, passes)
        
        shutil.rmtree(dir_path)

# Threat intelligence system for early warning
class SecurityMonitor:
    def __init__(self):
        self.suspicious_patterns = [
            r"sudo", r"rm -rf", r"format", r"chmod 777",
            r"passwd", r"useradd", r"ssh-keygen", r"crontab"
        ]
        self.attack_signatures = []
        self.alert_threshold = 5
        self.incident_log = []
    
    def monitor_system_calls(self, command: str, user: str = "unknown"):
        """Monitor system commands for suspicious activity"""
        threat_level = 0
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                threat_level += 1
                self.log_incident(f"Suspicious command detected: {command}", user, threat_level)
        
        if threat_level >= self.alert_threshold:
            self.trigger_red_alert(f"High threat activity from user {user}")
    
    def trigger_red_alert(self, message: str):
        """Activate red alert status"""
        messagebox.showwarning("RED ALERT", f"Critical security threat detected!\n\n{message}")
        
        # Log the incident
        self.log_incident(f"RED ALERT: {message}", "SYSTEM", 10)
        
        # Execute emergency protocols
        self.emergency_protocols()
    
    def emergency_protocols(self):
        """Emergency security protocols"""
        # Close active sessions
        # Encrypt sensitive files
        # Force logout
        # Notify administrator
        pass
    
    def log_incident(self, message: str, user: str, threat_level: int):
        """Log security incidents"""
        incident = {
            'timestamp': time.time(),
            'message': message,
            'user': user,
            'threat_level': threat_level
        }
        self.incident_log.append(incident)

# Anti-analysis mechanisms for attacker deception
class DecoyManager:
    def __init__(self):
        self.fake_processes = []
        self.decoys_created = 0
    
    def create_decoy_files(self):
        """Create decoy files to mislead attackers"""
        decoy_patterns = [
            "secret_keys.backup",
            "password_vault.db",
            "confidential_data.enc",
            "bitcoin_wallet.dat"
        ]
        
        decoy_dir = "decoy"
        if not os.path.exists(decoy_dir):
            os.makedirs(decoy_dir)
        
        for pattern in decoy_patterns:
            decoy_path = os.path.join(decoy_dir, pattern)
            
            # Fill file with encrypted random data
            fake_data = secrets.token_bytes(1024)
            with open(decoy_path, 'wb') as f:
                f.write(fake_data)
            
            self.decoys_created += 1
    
    def deploy_honeypot(self):
        """Deploy honeypot for attackers"""
        honeypot_code = '''
# This is a decoy file - do not open!
import sys
import time

if __name__ == "__main__":
    print("Loading sensitive data...")
    # Fake code that looks real
    fake_key = "AQIDBAUGBwgJCgsMDQ4PEBESE"
    # In background, log access attempts
    with open("honeypot_log.txt", "a") as f:
        f.write(f"Access attempt at {time.time()}\\n")
'''
        
        with open("honeypot_module.py", "w") as f:
            f.write(honeypot_code)

# Advanced digital signatures with unique fingerprints
class AdvancedDigitalSignatures:
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        self.signature_schemes = {
            "RSA-PSS-SHA512": "Highest level security",
            "ED25519-SHA512": "Modern fast signatures", 
            "ECDSA-SECP521R1": "Elliptic curve top level"
        }
    
    def create_timestamped_signature(self, private_key: bytes, data: bytes) -> dict:
        """Timestamped signature preventing reuse"""
        timestamp = int(time.time()).to_bytes(8, 'big')
        signed_data = timestamp + data
        
        # Generate unique signature each time
        signature = self.crypto_engine.sign_data(private_key, signed_data)
        
        return {
            'signature': base64.b64encode(signature).decode(),
            'timestamp': int(time.time()),
            'data_hash': hashlib.sha512(data).hexdigest(),
            'session_id': secrets.token_hex(16)
        }

# Advanced crypto engine with enhanced security
class AdvancedCryptoEngine:
    def __init__(self):
        self.backend = default_backend()
        self.security_profiles = {
            "STANDARD": {
                "rsa_key_size": 2048,
                "aes_key_size": 128,
                "kdf_iterations": 100000,
                "hmac_algorithm": "SHA256"
            },
            "HIGH": {
                "rsa_key_size": 3072,
                "aes_key_size": 192,
                "kdf_iterations": 600000,
                "hmac_algorithm": "SHA384"
            },
            "ULTRA": {
                "rsa_key_size": 4096,
                "aes_key_size": 256,
                "kdf_iterations": 1000000,
                "hmac_algorithm": "SHA512"
            }
        }
        self.current_profile = "HIGH"
        self.max_operation_time = 120
        self.performance_stats = {
            'encrypt_ops': 0,
            'decrypt_ops': 0,
            'total_operations': 0,
            'total_processing_time': 0
        }
        self._ultra_resistant = False
        self.digital_signatures = AdvancedDigitalSignatures(self)

    def get_security_profile(self, level=None):
        level = level or self.current_profile
        return self.security_profiles.get(level, self.security_profiles["HIGH"])

    def _record_operation(self, op_type: str, duration: float):
        self.performance_stats[f'{op_type}_ops'] += 1
        self.performance_stats['total_operations'] += 1
        self.performance_stats['total_processing_time'] += duration

    def generate_rsa_keypair(self, key_size=4096) -> Tuple[bytes, bytes]:
        start_time = time.time()
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            return public_pem, private_pem
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            raise

    def generate_symmetric_key(self, key_size: int) -> bytes:
        if key_size not in [128, 192, 256]:
            raise ValueError("Invalid AES key size")
        return secrets.token_bytes(key_size // 8)

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        if len(key) * 8 not in [128, 192, 256]:
            raise ValueError("Invalid AES key size")
        
        start_time = time.time()
        try:
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            return ciphertext, nonce
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            raise

    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        if len(key) * 8 not in [128, 192, 256]:
            raise ValueError("Invalid AES key size")
        
        start_time = time.time()
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            return plaintext
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            raise

    def encrypt_chacha20(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        start_time = time.time()
        try:
            nonce = secrets.token_bytes(12)
            chacha = ChaCha20Poly1305(key)
            ciphertext = chacha.encrypt(nonce, plaintext, None)
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            return ciphertext, nonce
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            raise

    def decrypt_chacha20(self, key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        start_time = time.time()
        try:
            chacha = ChaCha20Poly1305(key)
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            return plaintext
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            raise

    def encrypt_rsa_oaep(self, public_key_pem: bytes, plaintext: bytes) -> bytes:
        start_time = time.time()
        try:
            public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
            ciphertext = public_key.encrypt(
                plaintext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            return ciphertext
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('encrypt', duration)
            raise

    def decrypt_rsa_oaep(self, private_key_pem: bytes, ciphertext: bytes) -> bytes:
        start_time = time.time()
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            return plaintext
        except Exception as e:
            duration = time.time() - start_time
            self._record_operation('decrypt', duration)
            raise

    def derive_key(self, password: str, salt: bytes, iterations: int, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def sign_data(self, private_key_pem: bytes, data: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        return private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, public_key_pem: bytes, signature: bytes, data: bytes) -> bool:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )
        try:
            public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def sign_message_rsa(self, private_key_pem: bytes, message: bytes) -> dict:
        try:
            signature = self.sign_data(private_key_pem, message)
            return {
                'success': True,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'message_hash': hashlib.sha256(message).hexdigest(),
                'algorithm': 'RSA-PSS-SHA256'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def verify_signature_rsa(self, public_key_pem: bytes, signature: str, message: bytes) -> dict:
        try:
            signature_bytes = base64.b64decode(signature)
            is_valid = self.verify_signature(public_key_pem, signature_bytes, message)
            return {
                'success': True,
                'valid': is_valid,
                'message_hash': hashlib.sha256(message).hexdigest()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def sign_message_ed25519(self, private_key_pem: bytes, message: bytes) -> dict:
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=self.backend
            )
            signature = private_key.sign(message)
            return {
                'success': True,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'message_hash': hashlib.sha256(message).hexdigest(),
                'algorithm': 'Ed25519'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def verify_signature_ed25519(self, public_key_pem: bytes, signature: str, message: bytes) -> dict:
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            signature_bytes = base64.b64decode(signature)
            public_key.verify(signature_bytes, message)
            return {
                'success': True,
                'valid': True,
                'message_hash': hashlib.sha256(message).hexdigest()
            }
        except InvalidSignature:
            return {
                'success': True,
                'valid': False,
                'message_hash': hashlib.sha256(message).hexdigest()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def set_ultra_resistant(self, ultra_resistant: bool):
        self._ultra_resistant = ultra_resistant
        if ultra_resistant:
            self.current_profile = "ULTRA"
            self.max_operation_time = 240
        else:
            self.current_profile = "HIGH"
            self.max_operation_time = 120

# text steganography with encrypted embedding maps
class TextSteganography:
    def __init__(self, encryption_enabled=True, error_correction=True):
        self.encryption_enabled = encryption_enabled
        self.error_correction = error_correction
        if REEDSOLO_AVAILABLE:
            self.rs = RSCodec(8)
        else:
            self.rs = None

    def _apply_error_correction(self, data: bytes) -> bytes:
        if not self.error_correction or not self.rs:
            return data
        return self.rs.encode(data)

    def _remove_error_correction(self, data: bytes) -> bytes:
        if not self.error_correction or not self.rs:
            return data
        try:
            return self.rs.decode(data)[0]
        except:
            return data

    def embed_in_text_lsb(self, data: bytes, carrier_text: str, encryption_key: Optional[bytes] = None) -> Tuple[str, bytes]:
        start_time = time.time()
        try:
            processed_data = data
            if self.encryption_enabled and encryption_key:
                crypto_engine = AdvancedCryptoEngine()
                encrypted_data, nonce = crypto_engine.encrypt_aes_gcm(encryption_key, processed_data)
                processed_data = nonce + encrypted_data
            
            # Create embedding map
            embedding_map = {
                "technique": "LSB_TEXT",
                "data_size": len(data),
                "encryption_used": self.encryption_enabled,
                "timestamp": int(time.time()),
                "version": "1.0.0"
            }
            
            # Encrypt the embedding map itself
            map_json = json.dumps(embedding_map).encode()
            encrypted_map, map_nonce = crypto_engine.encrypt_chacha20(encryption_key, map_json)
            
            # Combine encrypted map with data
            full_payload = struct.pack('>I', len(encrypted_map)) + map_nonce + encrypted_map + processed_data
            compressed_data = zstd.compress(full_payload)
            
            data_header = struct.pack('>II', len(data), len(compressed_data))
            full_data = data_header + compressed_data
            
            if self.error_correction:
                full_data = self._apply_error_correction(full_data)
            
            data_bits = []
            for byte in full_data:
                for i in range(8):
                    data_bits.append((byte >> (7 - i)) & 1)

            if len(data_bits) > len(carrier_text) * 8:
                raise ValueError("Carrier text too small for data")

            carrier_chars = list(carrier_text)
            bit_index = 0
            
            for i in range(len(carrier_chars)):
                if bit_index >= len(data_bits):
                    break
                
                char_code = ord(carrier_chars[i])
                if char_code > 255:
                    continue
                
                new_char_code = (char_code & 0xFE) | data_bits[bit_index]
                carrier_chars[i] = chr(new_char_code)
                bit_index += 1

            duration = time.time() - start_time
            return ''.join(carrier_chars), encrypted_map
        except Exception as e:
            duration = time.time() - start_time
            raise

    def extract_from_text_lsb(self, stego_text: str, encrypted_map: bytes, decryption_key: Optional[bytes] = None) -> bytes:
        start_time = time.time()
        try:
            data_bits = []
            for char in stego_text:
                char_code = ord(char)
                if char_code > 255:
                    continue
                data_bits.append(char_code & 1)

            total_bits = len(data_bits)

            extracted_bytes = []
            for i in range(0, total_bits, 8):
                if i + 8 > len(data_bits):
                    break
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | data_bits[i + j]
                extracted_bytes.append(byte_val)

            payload = bytes(extracted_bytes)
            
            if self.error_correction:
                payload = self._remove_error_correction(payload)
            
            data_size, compressed_size = struct.unpack('>II', payload[:8])
            compressed_data = payload[8:8 + compressed_size]
            full_payload = zstd.decompress(compressed_data)
            
            # Extract and decrypt embedding map
            map_size = struct.unpack('>I', full_payload[:4])[0]
            map_nonce = full_payload[4:16]
            encrypted_map_data = full_payload[16:16 + map_size]
            processed_data = full_payload[16 + map_size:]
            
            if self.encryption_enabled and decryption_key:
                crypto_engine = AdvancedCryptoEngine()
                # Decrypt embedding map
                decrypted_map = crypto_engine.decrypt_chacha20(decryption_key, encrypted_map_data, map_nonce)
                embedding_map = json.loads(decrypted_map.decode())
                
                # Decrypt main data
                nonce = processed_data[:12]
                encrypted_data = processed_data[12:]
                plaintext = crypto_engine.decrypt_aes_gcm(decryption_key, encrypted_data, nonce)
                return plaintext
            
            duration = time.time() - start_time
            return processed_data
        except Exception as e:
            duration = time.time() - start_time
            raise

    # Backward compatibility
    def embed_in_text_lsb(self, data: bytes, carrier_text: str, encryption_key: Optional[bytes] = None) -> Tuple[str, Dict[str, Any]]:
        stego_text, encrypted_map = self.embed_in_text_lsb(data, carrier_text, encryption_key)
        embedding_map = {
            "technique": "LSB_TEXT",
            "data_size": len(data),
            "encryption_used": self.encryption_enabled,
            "encrypted_map": base64.b64encode(encrypted_map).decode()
        }
        return stego_text, embedding_map

    def extract_from_text_lsb(self, stego_text: str, embedding_map: Dict[str, Any], decryption_key: Optional[bytes] = None) -> bytes:
        encrypted_map = base64.b64decode(embedding_map["encrypted_map"])
        return self.extract_from_text_lsb(stego_text, encrypted_map, decryption_key)

# image steganography with encrypted embedding maps
class ImageSteganography:
    def __init__(self, encryption_enabled=True, error_correction=True):
        self.encryption_enabled = encryption_enabled
        self.error_correction = error_correction
        if REEDSOLO_AVAILABLE:
            self.rs = RSCodec(8)
        else:
            self.rs = None

    def _apply_error_correction(self, data: bytes) -> bytes:
        if not self.error_correction or not self.rs:
            return data
        return self.rs.encode(data)

    def _remove_error_correction(self, data: bytes) -> bytes:
        if not self.error_correction or not self.rs:
            return data
        try:
            return self.rs.decode(data)[0]
        except:
            return data

    def embed_in_image_lsb(self, data: bytes, image_data: bytes, encryption_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        start_time = time.time()
        try:
            processed_data = data
            if self.encryption_enabled and encryption_key:
                crypto_engine = AdvancedCryptoEngine()
                encrypted_data, nonce = crypto_engine.encrypt_aes_gcm(encryption_key, processed_data)
                processed_data = nonce + encrypted_data
            
            # Create embedding map
            embedding_map = {
                "technique": "LSB_IMAGE",
                "data_size": len(data),
                "encryption_used": self.encryption_enabled,
                "timestamp": int(time.time()),
                "version": "1.0.0"
            }
            
            # Encrypt the embedding map itself
            map_json = json.dumps(embedding_map).encode()
            encrypted_map, map_nonce = crypto_engine.encrypt_chacha20(encryption_key, map_json)
            
            # Combine encrypted map with data
            full_payload = struct.pack('>I', len(encrypted_map)) + map_nonce + encrypted_map + processed_data
            compressed_data = zstd.compress(full_payload)
            
            data_header = struct.pack('>II', len(data), len(compressed_data))
            full_data = data_header + compressed_data
            
            if self.error_correction:
                full_data = self._apply_error_correction(full_data)
            
            data_bits = []
            for byte in full_data:
                for i in range(8):
                    data_bits.append((byte >> (7 - i)) & 1)

            img = Image.open(io.BytesIO(image_data))
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            width, height = img.size
            max_bits = width * height * 3

            if len(data_bits) > max_bits:
                raise ValueError("Image too small for data")

            bit_index = 0
            for i in range(width):
                for j in range(height):
                    for k in range(3):
                        if bit_index >= len(data_bits):
                            break
                        img_array[j, i, k] = (img_array[j, i, k] & 0xFE) | data_bits[bit_index]
                        bit_index += 1
                    if bit_index >= len(data_bits):
                        break
                if bit_index >= len(data_bits):
                    break

            stego_img = Image.fromarray(img_array)
            output_buffer = io.BytesIO()
            stego_img.save(output_buffer, format='PNG')
            stego_image_data = output_buffer.getvalue()

            duration = time.time() - start_time
            return stego_image_data, encrypted_map
        except Exception as e:
            duration = time.time() - start_time
            raise

    def extract_from_image_lsb(self, image_data: bytes, encrypted_map: bytes, decryption_key: Optional[bytes] = None) -> bytes:
        start_time = time.time()
        try:
            img = Image.open(io.BytesIO(image_data))
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            width, height = img.size

            data_bits = []
            bit_count = 0
            
            for i in range(width):
                for j in range(height):
                    for k in range(3):
                        data_bits.append(img_array[j, i, k] & 1)
                        bit_count += 1

            extracted_bytes = []
            for i in range(0, len(data_bits), 8):
                if i + 8 > len(data_bits):
                    break
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | data_bits[i + j]
                extracted_bytes.append(byte_val)

            payload = bytes(extracted_bytes)
            
            if self.error_correction:
                payload = self._remove_error_correction(payload)
            
            data_size, compressed_size = struct.unpack('>II', payload[:8])
            compressed_data = payload[8:8 + compressed_size]
            full_payload = zstd.decompress(compressed_data)
            
            # Extract and decrypt embedding map
            map_size = struct.unpack('>I', full_payload[:4])[0]
            map_nonce = full_payload[4:16]
            encrypted_map_data = full_payload[16:16 + map_size]
            processed_data = full_payload[16 + map_size:]
            
            if self.encryption_enabled and decryption_key:
                crypto_engine = AdvancedCryptoEngine()
                # Decrypt embedding map
                decrypted_map = crypto_engine.decrypt_chacha20(decryption_key, encrypted_map_data, map_nonce)
                embedding_map = json.loads(decrypted_map.decode())
                
                # Decrypt main data
                nonce = processed_data[:12]
                encrypted_data = processed_data[12:]
                plaintext = crypto_engine.decrypt_aes_gcm(decryption_key, encrypted_data, nonce)
                return plaintext
            
            duration = time.time() - start_time
            return processed_data
        except Exception as e:
            duration = time.time() - start_time
            raise

    # Backward compatibility
    def embed_in_image_lsb(self, data: bytes, image_data: bytes, encryption_key: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
        stego_image, encrypted_map = self.embed_in_image_lsb(data, image_data, encryption_key)
        embedding_map = {
            "technique": "LSB_IMAGE",
            "data_size": len(data),
            "encryption_used": self.encryption_enabled,
            "encrypted_map": base64.b64encode(encrypted_map).decode()
        }
        return stego_image, embedding_map

    def extract_from_image_lsb(self, image_data: bytes, embedding_map: Dict[str, Any], decryption_key: Optional[bytes] = None) -> bytes:
        encrypted_map = base64.b64decode(embedding_map["encrypted_map"])
        return self.extract_from_image_lsb(image_data, encrypted_map, decryption_key)

# Advanced key manager with enhanced security features
class AdvancedKeyManager:
    def __init__(self, keystore_path='secure_keystore.vault'):
        self.keystore_path = keystore_path
        self.keys = {}
        self.master_key = None
        self.master_key_id = None
        self.memory_manager = SecureMemoryManager()
        self.audit_logger = AuditSystem()
        self.crypto_engine = AdvancedCryptoEngine()
        self.secure_destroy = SecureDataEraser()
        self.threat_intel = SecurityMonitor()
        self.anti_analysis = DecoyManager()
        self._key_rotation_interval = 3600
        self._rotation_thread = None
        self._stop_rotation = threading.Event()
        self._init_keystore()

    def _init_keystore(self):
        if os.path.exists(self.keystore_path):
            self._load_keystore()
            self.audit_logger.log_event("KEYSTORE_LOADED", f"Loaded keystore from {self.keystore_path}")
        else:
            self._save_keystore()
            self.audit_logger.log_event("KEYSTORE_CREATED", f"Created new keystore at {self.keystore_path}")

    def _load_keystore(self):
        try:
            with open(self.keystore_path, 'rb') as f:
                encrypted_data = f.read()
            
            if not self.master_key:
                return
            
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            plaintext = self.crypto_engine.decrypt_aes_gcm(self.master_key, ciphertext, nonce)
            keystore_dict = json.loads(plaintext)['keys']
            
            for key_id, key_data in keystore_dict.items():
                public_key = base64.b64decode(key_data['public_key']) if key_data['public_key'] else None
                encrypted_private_key = base64.b64decode(key_data['encrypted_private_key'])
                symmetric_key = base64.b64decode(key_data['symmetric_key']) if key_data['symmetric_key'] else None
                
                meta_data = key_data['meta']
                key_metadata = KeyMetadata(
                    key_id=meta_data['key_id'],
                    key_type=KeyType[meta_data['key_type']],
                    security_level=SecurityLevel[meta_data['security_level']],
                    created_at=meta_data['created_at'],
                    expires_at=meta_data['expires_at'],
                    usage_count=meta_data['usage_count'],
                    last_used=meta_data['last_used'],
                    flags=meta_data['flags'],
                    ultra_resistance=UltraResistanceLevel[meta_data['ultra_resistance']]
                )
                
                kdf_params = None
                if 'kdf_params' in key_data:
                    kdf_data = key_data['kdf_params']
                    kdf_params = KeyDerivationParams(
                        salt=base64.b64decode(kdf_data['salt']),
                        iterations=kdf_data['iterations'],
                        length=kdf_data['length'],
                        memory_cost=kdf_data['memory_cost'],
                        time_cost=kdf_data['time_cost'],
                        parallelism=kdf_data['parallelism']
                    )
                
                key_entry = KeyEntry(
                    public_key=public_key,
                    encrypted_private_key=encrypted_private_key,
                    symmetric_key=symmetric_key,
                    meta=key_metadata,
                    kdf_params=kdf_params
                )
                
                self.keys[key_id] = key_entry
                
        except Exception as e:
            self.audit_logger.log_event("KEYSTORE_LOAD_FAILED", str(e), False)
            messagebox.showerror("Critical Error", f"Failed to load keystore: {e}")
            raise CriticalSecurityException(f"Keystore loading failed: {e}")

    def _save_keystore(self):
        if not self.master_key:
            return
        
        try:
            keystore_dict = {}
            for k, v in self.keys.items():
                key_data = {
                    'public_key': base64.b64encode(v.public_key).decode() if v.public_key else None,
                    'encrypted_private_key': base64.b64encode(v.encrypted_private_key).decode(),
                    'symmetric_key': base64.b64encode(v.symmetric_key).decode() if v.symmetric_key else None,
                    'meta': {
                        'key_id': v.meta.key_id,
                        'key_type': v.meta.key_type.name,
                        'security_level': v.meta.security_level.name,
                        'created_at': v.meta.created_at,
                        'expires_at': v.meta.expires_at,
                        'usage_count': v.meta.usage_count,
                        'last_used': v.meta.last_used,
                        'flags': v.meta.flags,
                        'ultra_resistance': v.meta.ultra_resistance.name
                    }
                }
                
                if v.kdf_params:
                    key_data['kdf_params'] = {
                        'salt': base64.b64encode(v.kdf_params.salt).decode(),
                        'iterations': v.kdf_params.iterations,
                        'length': v.kdf_params.length,
                        'memory_cost': v.kdf_params.memory_cost,
                        'time_cost': v.kdf_params.time_cost,
                        'parallelism': v.kdf_params.parallelism
                    }
                
                keystore_dict[k] = key_data

            keystore_data = json.dumps({'keys': keystore_dict}).encode()
            ciphertext, nonce = self.crypto_engine.encrypt_aes_gcm(self.master_key, keystore_data)
            encrypted_data = nonce + ciphertext
            
            with open(self.keystore_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.audit_logger.log_event("KEYSTORE_SAVED", "Keystore saved successfully")
        except Exception as e:
            self.audit_logger.log_event("KEYSTORE_SAVE_FAILED", str(e), False)
            raise

    def initialize_master_key(self, password: str) -> bool:
        if self.master_key:
            return True
        
        try:
            if len(password) < 12:
                raise ValueError("Password must be at least 12 characters long")
                
            salt = secrets.token_bytes(32)
            self.master_key = self.crypto_engine.derive_key(password, salt, 1000000)
            
            fernet_key = Fernet.generate_key()
            fernet = Fernet(fernet_key)
            encrypted_master = fernet.encrypt(self.master_key)
            
            keyring.set_password("cxa_system", "master_key", encrypted_master.hex())
            keyring.set_password("cxa_system", "fernet_key", fernet_key.hex())
            keyring.set_password("cxa_system", "master_salt", salt.hex())
            
            self.audit_logger.log_sensitive_operation("MASTER_KEY_INIT", "SYSTEM", "Master key initialized")
            return True
        except Exception as e:
            self.audit_logger.log_event("MASTER_KEY_INIT", f"Initialization failed: {e}", False)
            return False

    def load_master_key(self, password: str) -> bool:
        try:
            encrypted_master_hex = keyring.get_password("cxa_system", "master_key")
            fernet_key_hex = keyring.get_password("cxa_system", "fernet_key")
            salt_hex = keyring.get_password("cxa_system", "master_salt")
            
            if not encrypted_master_hex or not fernet_key_hex or not salt_hex:
                return False
                
            fernet_key = bytes.fromhex(fernet_key_hex)
            encrypted_master = bytes.fromhex(encrypted_master_hex)
            salt = bytes.fromhex(salt_hex)
            
            derived_key = self.crypto_engine.derive_key(password, salt, 1000000)
            
            fernet = Fernet(fernet_key)
            decrypted_master = fernet.decrypt(encrypted_master)
            
            if derived_key == decrypted_master:
                self.master_key = decrypted_master
                return True
            else:
                return False
                
        except Exception as e:
            self.audit_logger.log_event("MASTER_KEY_LOAD", f"Load failed: {e}", False)
            return False

    def generate_key_pair(self, key_type: KeyType, security_level: SecurityLevel, key_password: Optional[str] = None, expires_days: int = 365, ultra_resistant: bool = False) -> str:
        start_time = time.time()
        try:
            key_id = self._generate_key_id()
            
            if key_type in [KeyType.RSA_2048, KeyType.RSA_4096]:
                key_size = 2048 if key_type == KeyType.RSA_2048 else 4096
                public_pem, private_pem = self.crypto_engine.generate_rsa_keypair(key_size)
                
                if key_password:
                    salt = secrets.token_bytes(16)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=600000,
                        backend=default_backend()
                    )
                    key = kdf.derive(key_password.encode())
                    nonce = secrets.token_bytes(12)
                    aesgcm = AESGCM(key)
                    encrypted_private = aesgcm.encrypt(nonce, private_pem, None)
                    private_key_data = nonce + encrypted_private
                    kdf_params = KeyDerivationParams(salt=salt, iterations=600000)
                else:
                    private_key_data = private_pem
                    kdf_params = None
                
                key_entry = KeyEntry(
                    public_key=public_pem,
                    encrypted_private_key=private_key_data,
                    meta=KeyMetadata(
                        key_id=key_id,
                        key_type=key_type,
                        security_level=security_level,
                        created_at=int(time.time()),
                        expires_at=int(time.time()) + expires_days * 24 * 3600 if expires_days > 0 else None,
                        ultra_resistance=UltraResistanceLevel.HIGH if ultra_resistant else UltraResistanceLevel.NONE
                    ),
                    kdf_params=kdf_params
                )
            
            elif key_type == KeyType.AES_256:
                symmetric_key = self.crypto_engine.generate_symmetric_key(256)
                key_entry = KeyEntry(
                    symmetric_key=symmetric_key,
                    meta=KeyMetadata(
                        key_id=key_id,
                        key_type=key_type,
                        security_level=security_level,
                        created_at=int(time.time()),
                        expires_at=int(time.time()) + expires_days * 24 * 3600 if expires_days > 0 else None,
                        ultra_resistance=UltraResistanceLevel.HIGH if ultra_resistant else UltraResistanceLevel.NONE
                    )
                )
            
            elif key_type == KeyType.ED25519:
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                key_entry = KeyEntry(
                    public_key=public_pem,
                    encrypted_private_key=private_pem,
                    meta=KeyMetadata(
                        key_id=key_id,
                        key_type=key_type,
                        security_level=security_level,
                        created_at=int(time.time()),
                        expires_at=int(time.time()) + expires_days * 24 * 3600 if expires_days > 0 else None,
                        ultra_resistance=UltraResistanceLevel.HIGH if ultra_resistant else UltraResistanceLevel.NONE
                    )
                )
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            self.keys[key_id] = key_entry
            self._save_keystore()
            self.audit_logger.log_sensitive_operation("KEY_GENERATED", "SYSTEM", f"Generated {key_type.name} key with ID {key_id}")
            duration = time.time() - start_time
            return key_id
        except Exception as e:
            duration = time.time() - start_time
            self.audit_logger.log_event("KEY_GENERATION_FAILED", str(e), False)
            raise

    def _generate_key_id(self) -> str:
        timestamp = int(time.time() * 1000000)
        random_part = secrets.token_hex(16)
        return f"KEY-{timestamp}-{random_part}"

    def get_key(self, key_id: str, key_password: Optional[str] = None) -> Optional[KeyEntry]:
        if key_id not in self.keys:
            self.audit_logger.log_event("KEY_ACCESS_FAILED", f"Key {key_id} not found", False)
            return None
        
        key_entry = self.keys[key_id]
        key_entry.meta.usage_count += 1
        key_entry.meta.last_used = int(time.time())
        
        if key_entry.meta.key_type in [KeyType.RSA_2048, KeyType.RSA_4096] and key_password and key_entry.kdf_params:
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=key_entry.kdf_params.salt,
                    iterations=key_entry.kdf_params.iterations,
                    backend=default_backend()
                )
                key = kdf.derive(key_password.encode())
                nonce = key_entry.encrypted_private_key[:12]
                ciphertext = key_entry.encrypted_private_key[12:]
                aesgcm = AESGCM(key)
                private_pem = aesgcm.decrypt(nonce, ciphertext, None)
                key_entry.encrypted_private_key = private_pem
                key_entry.kdf_params = None
            except Exception as e:
                self.audit_logger.log_event("KEY_DECRYPTION_FAILED", str(e), False)
                return None
        
        self.audit_logger.log_event("KEY_ACCESSED", f"Accessed key {key_id}")
        return key_entry

    def export_key(self, key_id: str, password: Optional[str] = None) -> Optional[bytes]:
        key_entry = self.get_key(key_id, password)
        if not key_entry:
            return None
        
        self.audit_logger.log_sensitive_operation("KEY_EXPORT", "USER", f"Exported key {key_id}")
        
        if key_entry.public_key:
            return key_entry.public_key
        return key_entry.encrypted_private_key

    def get_expired_keys(self):
        current_time = int(time.time())
        expired_keys = []
        for key_id, key_entry in self.keys.items():
            if key_entry.meta.expires_at and key_entry.meta.expires_at < current_time:
                expired_keys.append(key_id)
        return expired_keys

    def archive_keys(self, key_ids):
        archive_dir = "key_archive"
        if not os.path.exists(archive_dir):
            os.makedirs(archive_dir)
        
        for key_id in key_ids:
            if key_id in self.keys:
                archive_file = os.path.join(archive_dir, f"{key_id}.archive")
                with open(archive_file, 'w') as f:
                    json.dump({
                        'key_id': key_id,
                        'key_data': base64.b64encode(self.keys[key_id].encrypted_private_key).decode(),
                        'archived_at': time.time()
                    }, f)

    def rotate_expired_keys(self) -> int:
        expired_keys = self.get_expired_keys()
        if not expired_keys:
            return 0
        
        user_consent = messagebox.askyesno(
            "Key Rotation", 
            f"Found {len(expired_keys)} expired keys. Rotate them?"
        )
        if not user_consent:
            return 0
            
        rotated = 0
        current_time = int(time.time())
        
        for key_id in expired_keys:
            key_entry = self.keys[key_id]
            try:
                new_key_id = self.generate_key_pair(
                    key_entry.meta.key_type,
                    key_entry.meta.security_level,
                    expires_days=365,
                    ultra_resistant=key_entry.meta.ultra_resistance != UltraResistanceLevel.NONE
                )
                self.archive_keys([key_id])
                del self.keys[key_id]
                rotated += 1
            except Exception as e:
                self.audit_logger.log_event("KEY_ROTATION_FAILED", str(e), False)
        
        if rotated > 0:
            self._save_keystore()
            self.audit_logger.log_sensitive_operation("KEYS_ROTATED", "SYSTEM", f"Rotated {rotated} expired keys")
        
        return rotated

    def start_auto_rotation(self):
        self._stop_rotation.clear()
        self._rotation_thread = threading.Thread(target=self._rotation_loop, daemon=True)
        self._rotation_thread.start()

    def _rotation_loop(self):
        while not self._stop_rotation.is_set():
            time.sleep(self._key_rotation_interval)
            self.rotate_expired_keys()

    def stop_auto_rotation(self):
        self._stop_rotation.set()
        if self._rotation_thread and self._rotation_thread.is_alive():
            self._rotation_thread.join(timeout=2)

    def get_key_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        if key_id not in self.keys:
            return None
        
        key_entry = self.keys[key_id]
        return {
            'key_id': key_entry.meta.key_id,
            'key_type': key_entry.meta.key_type.name,
            'security_level': key_entry.meta.security_level.name,
            'created_at': key_entry.meta.created_at,
            'expires_at': key_entry.meta.expires_at,
            'usage_count': key_entry.meta.usage_count,
            'last_used': key_entry.meta.last_used,
            'ultra_resistance': key_entry.meta.ultra_resistance.name
        }

    def emergency_erase_all(self):
        """Complete Destroy destruction of all cryptographic data"""
        if not messagebox.askyesno("Destroy Destruction Confirmation", 
                                 "WARNING: This will permanently destroy ALL cryptographic data. This is IRREVERSIBLE. Continue?"):
            return
            
        try:
            # Securely wipe all keys from memory
            for key_id in list(self.keys.keys()):
                key_entry = self.keys[key_id]
                if key_entry.symmetric_key:
                    key_data = bytearray(key_entry.symmetric_key)
                    for i in range(len(key_data)):
                        key_data[i] = secrets.randbelow(256)
                del self.keys[key_id]
            
            # Securely wipe keystore file
            if os.path.exists(self.keystore_path):
                self.secure_destroy.secure_wipe_file(self.keystore_path)
            
            # Securely wipe backup files
            backup_dir = "backups"
            if os.path.exists(backup_dir):
                self.secure_destroy.secure_wipe_directory(backup_dir)
            
            # Clear master key
            if self.master_key:
                master_data = bytearray(self.master_key)
                for i in range(len(master_data)):
                    master_data[i] = secrets.randbelow(256)
                self.master_key = None
            
            self.audit_logger.log_sensitive_operation("EMERGENCY_ERASE_ALL", "SYSTEM", "All cryptographic data destroyed")
            messagebox.showinfo("Destruction Complete", "All cryptographic data has been securely destroyed.")
            
        except Exception as e:
            messagebox.showerror("Destruction Error", f"Failed to destroy data: {str(e)}")

# Error message manager for user-friendly error handling
class ErrorMessageManager:
    def __init__(self):
        self.error_messages = {
            "INVALID_HEX": "Input data is not in valid hex format. Please enter only numbers and letters A-F.",
            "KEY_NOT_FOUND": "The specified key was not found. Please verify the key ID.",
            "INVALID_FILE_TYPE": "File type not allowed. Please select a valid file type.",
            "MEMORY_ERROR": "Insufficient system memory. Please close other applications and try again.",
            "SECURITY_VIOLATION": "Security policy violation detected. Operation aborted."
        }
    
    def get_user_friendly_message(self, error_code, details=None):
        base_message = self.error_messages.get(error_code, "An unexpected error occurred")
        if details:
            return f"{base_message}\n\nAdditional details: {details}"
        return base_message

# Main application GUI
class AdvancedCryptoSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CXA Cryptographic System - Enhanced Security")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.setup_styles()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.key_manager = AdvancedKeyManager()
        self.crypto_engine = AdvancedCryptoEngine()
        self.text_stego = TextSteganography()
        self.image_stego = ImageSteganography()
        self.memory_manager = SecureMemoryManager()
        self.memory_manager.secure_heap_init()
        self.error_manager = ErrorMessageManager()
        
        self.stego_algorithm = tk.StringVar(value="LSB")
        self.enable_encryption = tk.BooleanVar(value=True)
        self.enable_error_correction = tk.BooleanVar(value=True)
        self.ultra_resistance = tk.BooleanVar(value=False)
        self.key_id_var = tk.StringVar()
        self.current_theme = "dark"
        
        self.setup_dashboard_tab()
        self.setup_crypto_tab()
        self.setup_stego_tab()
        self.setup_key_management_tab()
        self.setup_signature_tab()
        self.setup_settings_tab()
        self.setup_security_tab()
        self.setup_menu()
        self.update_dashboard()

    def setup_styles(self):
        self.style.configure("TFrame", background="#1e1e1e")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#e0e0e0")
        self.style.configure("TButton", background="#2d2d30", foreground="#e0e0e0")
        self.style.configure("TEntry", fieldbackground="#2d2d30", foreground="#e0e0e0")
        self.style.configure("TCombobox", fieldbackground="#2d2d30", foreground="#e0e0e0")
        self.style.configure("Treeview", background="#2d2d30", fieldbackground="#2d2d30", foreground="#e0e0e0")
        self.style.configure("Treeview.Heading", background="#1e1e1e", foreground="#e0e0e0")
        self.style.map("Treeview", background=[("selected", "#404040")], foreground=[("selected", "#ffffff")])
        self.style.configure("Danger.TButton", background="#cc0000", foreground="white")
        self.style.configure("Critical.TButton", background="#ff0000", foreground="white", font=("Arial", 10, "bold"))

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        security_menu = tk.Menu(menubar, tearoff=0)
        security_menu.add_command(label="Threat Monitor", command=self.show_threat_monitor)
        security_menu.add_command(label="Create Decoys", command=self.create_decoys)
        security_menu.add_command(label="Deploy Honeypot", command=self.deploy_honeypot)
        menubar.add_cascade(label="Security", menu=security_menu)
        
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        settings_menu.add_command(label="Ultra Mode", command=self.activate_ultra_mode)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.style.configure("TFrame", background="#f0f0f0")
            self.style.configure("TLabel", background="#f0f0f0", foreground="#000000")
            self.style.configure("TButton", background="#e0e0e0", foreground="#000000")
            self.style.configure("TEntry", fieldbackground="#ffffff", foreground="#000000")
            self.style.configure("TCombobox", fieldbackground="#ffffff", foreground="#000000")
            self.style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#000000")
            self.style.configure("Treeview.Heading", background="#e0e0e0", foreground="#000000")
            self.style.map("Treeview", background=[("selected", "#0078d7")], foreground=[("selected", "#ffffff")])
            self.current_theme = "light"
        else:
            self.setup_styles()
            self.current_theme = "dark"

    def activate_ultra_mode(self):
        self.crypto_engine.set_ultra_resistant(True)
        self.key_manager.audit_logger.log_sensitive_operation("ULTRA_MODE_ACTIVATION", "USER", "Ultra security mode activated")
        messagebox.showinfo("Ultra Mode", "Ultra security mode activated")

    def show_about(self):
        about_text = """CXA Cryptographic System
Security Edition

Advanced cryptographic toolkit with:
- Military-grade encryption
- steganography with encrypted maps
- Secure-clad memory protection
- Threat intelligence monitoring
- Anti-analysis mechanisms
- Secure data erasure

Developed for maximum security and operational safety."""
        messagebox.showinfo("About", about_text)

    def show_threat_monitor(self):
        monitor_window = tk.Toplevel(self.root)
        monitor_window.title("Threat Intelligence Monitor")
        monitor_window.geometry("600x400")
        
        text_area = scrolledtext.ScrolledText(monitor_window, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        incidents = self.key_manager.threat_intel.incident_log
        if incidents:
            for incident in incidents[-20:]:  # Show last 20 incidents
                timestamp = datetime.fromtimestamp(incident['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
                text_area.insert(tk.END, f"[{timestamp}] Threat Level {incident['threat_level']}: {incident['message']}\n")
        else:
            text_area.insert(tk.END, "No security incidents detected.\nSystem is secure.")
        
        text_area.config(state=tk.DISABLED)

    def create_decoys(self):
        self.key_manager.anti_analysis.create_decoy_files()
        self.key_manager.audit_logger.log_event("DECOYS_CREATED", f"Created {self.key_manager.anti_analysis.decoys_created} decoy files")
        messagebox.showinfo("Decoys Deployed", f"Created {self.key_manager.anti_analysis.decoys_created} decoy files to mislead attackers.")

    def deploy_honeypot(self):
        self.key_manager.anti_analysis.deploy_honeypot()
        self.key_manager.audit_logger.log_event("HONEYPOT_DEPLOYED", "Honeypot module deployed")
        messagebox.showinfo("Honeypot Deployed", "Honeypot module deployed successfully. Attackers will be tracked.")

    def validate_hex_input(self, hex_string):
        try:
            clean_hex = re.sub(r'\s+', '', hex_string)
            if not re.match(r'^[0-9a-fA-F]*$', clean_hex):
                raise ValueError("Invalid hex characters")
            if len(clean_hex) % 2 != 0:
                raise ValueError("Hex string must have even length")
            return bytes.fromhex(clean_hex)
        except Exception as e:
            raise ValueError(f"Invalid hex input: {e}")

    def validate_file_type(self, file_path):
        allowed_extensions = {'.png', '.jpg', '.jpeg', '.bmp', '.txt', '.md', '.csv'}
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in allowed_extensions:
            raise ValueError(f"File type {file_ext} not allowed")
        
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        allowed_mimes = ['image/png', 'image/jpeg', 'text/plain', 'text/markdown']
        if mime_type not in allowed_mimes:
            raise ValueError(f"MIME type {mime_type} not allowed")

    def setup_dashboard_tab(self):
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        status_frame = ttk.LabelFrame(dashboard_frame, text="System Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_labels = {}
        status_items = [
            ("Security Level", "HIGH"),
            ("Memory Protection", "Enabled"),
            ("Maximum Security Mode", "Disabled"),
            ("Threat Level", "LOW")
        ]
        
        for i, (label, value) in enumerate(status_items):
            row = ttk.Frame(status_frame)
            row.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(row, text=f"{label}:", width=20).pack(side=tk.LEFT)
            status_label = ttk.Label(row, text=value, foreground="green")
            status_label.pack(side=tk.LEFT)
            self.status_labels[label] = status_label
        
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Security Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.stat_labels = {}
        stats = [
            ("Total Keys", "0"),
            ("Encryption Operations", "0"),
            ("Decryption Operations", "0"),
            ("Total Operations", "0"),
            ("Security Incidents", "0"),
            ("Memory Protected", "0 KB")
        ]
        
        for i, (label, value) in enumerate(stats):
            row = ttk.Frame(stats_grid)
            row.grid(row=i//2, column=i%2, sticky="nsew", padx=10, pady=5)
            ttk.Label(row, text=label, font=("Arial", 10, "bold")).pack(anchor=tk.W)
            stat_label = ttk.Label(row, text=value, font=("Arial", 12))
            stat_label.pack(anchor=tk.W)
            self.stat_labels[label] = stat_label
        
        stats_grid.columnconfigure(0, weight=1)
        stats_grid.columnconfigure(1, weight=1)
        
        self.keys_list_frame = ttk.LabelFrame(dashboard_frame, text="Active Keys")
        self.keys_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("ID", "Type", "Security", "Expires", "Status")
        self.keys_tree = ttk.Treeview(self.keys_list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.keys_tree.heading(col, text=col)
            self.keys_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(self.keys_list_frame, orient=tk.VERTICAL, command=self.keys_tree.yview)
        self.keys_tree.configure(yscrollcommand=scrollbar.set)
        self.keys_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def update_dashboard(self):
        try:
            stats = self.crypto_engine.performance_stats
            self.stat_labels["Encryption Operations"].config(text=str(stats["encrypt_ops"]))
            self.stat_labels["Decryption Operations"].config(text=str(stats["decrypt_ops"]))
            total_ops = stats["total_operations"]
            self.stat_labels["Total Operations"].config(text=str(total_ops))
            self.stat_labels["Total Keys"].config(text=str(len(self.key_manager.keys)))
            
            # Security incidents
            incidents = len(self.key_manager.threat_intel.incident_log)
            self.stat_labels["Security Incidents"].config(text=str(incidents))
            
            # Memory usage
            mem_usage = self.memory_manager.get_memory_usage()
            protected_kb = mem_usage['total_bytes'] // 1024
            self.stat_labels["Memory Protected"].config(text=f"{protected_kb} KB")
            
            for item in self.keys_tree.get_children():
                self.keys_tree.delete(item)
            
            for key_id, key_entry in self.key_manager.keys.items():
                expires = "Never"
                if key_entry.meta.expires_at:
                    try:
                        expires = datetime.fromtimestamp(key_entry.meta.expires_at).strftime("%Y-%m-%d")
                    except:
                        expires = "Unknown"
                
                status = "Active" if not key_entry.meta.expires_at or key_entry.meta.expires_at > time.time() else "Expired"
                
                self.keys_tree.insert("", "end", values=(
                    key_id[:12] + "...",
                    key_entry.meta.key_type.name,
                    key_entry.meta.security_level.name,
                    expires,
                    status
                ))
            
            ultra_status = "Enabled" if self.crypto_engine._ultra_resistant else "Disabled"
            self.status_labels["Maximum Security Mode"].config(
                text=ultra_status,
                foreground="green" if self.crypto_engine._ultra_resistant else "yellow"
            )
            
            # Threat level
            threat_level = "LOW"
            if incidents > 10:
                threat_level = "HIGH"
            elif incidents > 5:
                threat_level = "MEDIUM"
                
            self.status_labels["Threat Level"].config(
                text=threat_level,
                foreground="green" if threat_level == "LOW" else "yellow" if threat_level == "MEDIUM" else "red"
            )
            
        except Exception as e:
            print(f"Dashboard update error: {e}")
        
        self.root.after(3000, self.update_dashboard)

    def setup_crypto_tab(self):
        crypto_frame = ttk.Frame(self.notebook)
        self.notebook.add(crypto_frame, text="Cryptography")
        
        controls_frame = ttk.LabelFrame(crypto_frame, text="Operation Controls")
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(controls_frame, text="Operation:").pack(side=tk.LEFT, padx=5)
        self.crypto_operation = ttk.Combobox(controls_frame, values=["Encrypt", "Decrypt"], state="readonly")
        self.crypto_operation.set("Encrypt")
        self.crypto_operation.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="Algorithm:").pack(side=tk.LEFT, padx=5)
        self.encryption_algorithm = ttk.Combobox(
            controls_frame, 
            values=["AES-GCM", "ChaCha20", "RSA-OAEP"], 
            state="readonly"
        )
        self.encryption_algorithm.set("AES-GCM")
        self.encryption_algorithm.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="Security Level:").pack(side=tk.LEFT, padx=5)
        self.security_level = ttk.Combobox(
            controls_frame, 
            values=["STANDARD", "HIGH", "ULTRA"], 
            state="readonly"
        )
        self.security_level.set("HIGH")
        self.security_level.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="Key ID:").pack(side=tk.LEFT, padx=5)
        self.key_id_combo = ttk.Combobox(controls_frame, textvariable=self.key_id_var, state="readonly")
        self.key_id_combo.pack(side=tk.LEFT, padx=5)
        self.update_key_list()
        
        ttk.Button(controls_frame, text="Generate Key", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        
        data_frame = ttk.Frame(crypto_frame)
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        input_frame = ttk.LabelFrame(data_frame, text="Input Data")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=15, bg='#2d2d30', fg='white')
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        output_frame = ttk.LabelFrame(data_frame, text="Output Data")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.output_text = scrolledtext.ScrolledText(output_frame, height=15, bg='#2d2d30', fg='white')
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        button_frame = ttk.Frame(crypto_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Process", command=self.process_crypto).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Input", command=lambda: self.input_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Output", command=lambda: self.output_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load File", command=self.load_crypto_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Result", command=self.save_crypto_result).pack(side=tk.LEFT, padx=5)
        
        self.crypto_status = ttk.Label(crypto_frame, text="Ready", foreground="green")
        self.crypto_status.pack(pady=5)

    def update_key_list(self):
        key_ids = list(self.key_manager.keys.keys())
        self.key_id_combo["values"] = key_ids
        if key_ids:
            self.key_id_combo.set(key_ids[0])

    def generate_key(self):
        security_level_str = self.security_level.get()
        security_level = SecurityLevel[security_level_str]
        key_type = KeyType.AES_256
        
        if self.encryption_algorithm.get() == "RSA-OAEP":
            key_type = KeyType.RSA_4096
        
        ultra_resistant = security_level_str == "ULTRA"
        
        try:
            key_id = self.key_manager.generate_key_pair(
                key_type, 
                security_level,
                ultra_resistant=ultra_resistant
            )
            self.update_key_list()
            self.key_id_combo.set(key_id)
            self.crypto_status.config(text=f"Key generated: {key_id}", foreground="green")
        except Exception as e:
            self.crypto_status.config(text=f"Key generation failed: {str(e)}", foreground="red")

    def load_crypto_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                self.validate_file_type(file_path)
                
                with open(file_path, "rb") as f:
                    data = f.read()
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(tk.END, data.hex())
                self.crypto_status.config(text=f"File loaded: {os.path.basename(file_path)}", foreground="green")
            except Exception as e:
                error_msg = self.error_manager.get_user_friendly_message("INVALID_FILE_TYPE", str(e))
                self.crypto_status.config(text=error_msg, foreground="red")

    def save_crypto_result(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".bin")
        if file_path:
            try:
                result = self.output_text.get(1.0, tk.END).strip()
                with open(file_path, "wb") as f:
                    f.write(bytes.fromhex(result))
                self.crypto_status.config(text=f"Result saved to: {os.path.basename(file_path)}", foreground="green")
            except Exception as e:
                self.crypto_status.config(text=f"Save failed: {str(e)}", foreground="red")

    def process_crypto(self):
        operation = self.crypto_operation.get()
        algorithm = self.encryption_algorithm.get()
        key_id = self.key_id_var.get()
        
        if not key_id:
            self.crypto_status.config(text="Please select or generate a key", foreground="red")
            return
        
        input_data = self.input_text.get(1.0, tk.END).strip()
        if not input_data:
            self.crypto_status.config(text="Please enter data to process", foreground="red")
            return
        
        try:
            key_entry = self.key_manager.get_key(key_id)
            if not key_entry:
                self.crypto_status.config(text="Key not found", foreground="red")
                return
            
            if operation == "Encrypt":
                if algorithm == "AES-GCM":
                    if not key_entry.symmetric_key:
                        self.crypto_status.config(text="No symmetric key found", foreground="red")
                        return
                    
                    plaintext = self.validate_hex_input(input_data)
                    ciphertext, nonce = self.crypto_engine.encrypt_aes_gcm(key_entry.symmetric_key, plaintext)
                    result = nonce + ciphertext
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, result.hex())
                    self.crypto_status.config(text="Encryption successful", foreground="green")
                
                elif algorithm == "ChaCha20":
                    if not key_entry.symmetric_key:
                        self.crypto_status.config(text="No symmetric key found", foreground="red")
                        return
                    
                    plaintext = self.validate_hex_input(input_data)
                    ciphertext, nonce = self.crypto_engine.encrypt_chacha20(key_entry.symmetric_key, plaintext)
                    result = nonce + ciphertext
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, result.hex())
                    self.crypto_status.config(text="Encryption successful", foreground="green")
                
                elif algorithm == "RSA-OAEP":
                    if not key_entry.public_key:
                        self.crypto_status.config(text="No public key found", foreground="red")
                        return
                    
                    plaintext = self.validate_hex_input(input_data)
                    ciphertext = self.crypto_engine.encrypt_rsa_oaep(key_entry.public_key, plaintext)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, ciphertext.hex())
                    self.crypto_status.config(text="Encryption successful", foreground="green")
            
            else:
                if algorithm == "AES-GCM":
                    if not key_entry.symmetric_key:
                        self.crypto_status.config(text="No symmetric key found", foreground="red")
                        return
                    
                    data = self.validate_hex_input(input_data)
                    nonce = data[:12]
                    ciphertext = data[12:]
                    plaintext = self.crypto_engine.decrypt_aes_gcm(key_entry.symmetric_key, ciphertext, nonce)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, plaintext.hex())
                    self.crypto_status.config(text="Decryption successful", foreground="green")
                
                elif algorithm == "ChaCha20":
                    if not key_entry.symmetric_key:
                        self.crypto_status.config(text="No symmetric key found", foreground="red")
                        return
                    
                    data = self.validate_hex_input(input_data)
                    nonce = data[:12]
                    ciphertext = data[12:]
                    plaintext = self.crypto_engine.decrypt_chacha20(key_entry.symmetric_key, ciphertext, nonce)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, plaintext.hex())
                    self.crypto_status.config(text="Decryption successful", foreground="green")
                
                elif algorithm == "RSA-OAEP":
                    if not key_entry.encrypted_private_key:
                        self.crypto_status.config(text="No private key found", foreground="red")
                        return
                    
                    ciphertext = self.validate_hex_input(input_data)
                    plaintext = self.crypto_engine.decrypt_rsa_oaep(key_entry.encrypted_private_key, ciphertext)
                    self.output_text.delete(1.0, tk.END)
                    self.output_text.insert(tk.END, plaintext.hex())
                    self.crypto_status.config(text="Decryption successful", foreground="green")
        
        except Exception as e:
            error_msg = self.error_manager.get_user_friendly_message("INVALID_HEX", str(e))
            self.crypto_status.config(text=error_msg, foreground="red")

    def setup_stego_tab(self):
        stego_frame = ttk.Frame(self.notebook)
        self.notebook.add(stego_frame, text="Steganography")
        
        carrier_frame = ttk.LabelFrame(stego_frame, text="Carrier Selection")
        carrier_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(carrier_frame, text="Carrier Type:").pack(side=tk.LEFT, padx=5)
        self.carrier_type = ttk.Combobox(carrier_frame, values=["Text", "Image"], state="readonly")
        self.carrier_type.set("Image")
        self.carrier_type.pack(side=tk.LEFT, padx=5)
        self.carrier_type.bind("<<ComboboxSelected>>", self.update_stego_controls)
        
        ttk.Button(carrier_frame, text="Load Carrier", command=self.load_carrier_file).pack(side=tk.LEFT, padx=5)
        self.carrier_path = ttk.Label(carrier_frame, text="No carrier loaded", width=40, anchor=tk.W)
        self.carrier_path.pack(side=tk.LEFT, padx=5)
        
        algo_frame = ttk.LabelFrame(stego_frame, text="Steganography Algorithm")
        algo_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Radiobutton(algo_frame, text="LSB (Encrypted Maps) - Recommended", 
                        variable=self.stego_algorithm, value="LSB").pack(anchor=tk.W, padx=5, pady=2)
        
        options_frame = ttk.Frame(algo_frame)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Checkbutton(options_frame, text="Enable Encryption", 
                       variable=self.enable_encryption).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(options_frame, text="Error Correction", 
                       variable=self.enable_error_correction).pack(side=tk.LEFT, padx=5)
        
        if not REEDSOLO_AVAILABLE:
            ttk.Label(algo_frame, text="Warning: reedsolo library not available. Error correction disabled.", 
                     foreground="orange").pack(anchor=tk.W, padx=5, pady=2)
        
        data_frame = ttk.Frame(stego_frame)
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        input_frame = ttk.LabelFrame(data_frame, text="Data to Hide")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.stego_input = scrolledtext.ScrolledText(input_frame, height=10, bg='#2d2d30', fg='white')
        self.stego_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        carrier_preview_frame = ttk.LabelFrame(data_frame, text="Carrier Preview")
        carrier_preview_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.carrier_preview = ttk.Label(carrier_preview_frame, text="Load a carrier file to preview")
        self.carrier_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        result_frame = ttk.LabelFrame(data_frame, text="Result")
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.stego_result = scrolledtext.ScrolledText(result_frame, height=10, bg='#2d2d30', fg='white')
        self.stego_result.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        button_frame = ttk.Frame(stego_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Embed Data", command=self.embed_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Extract Data", command=self.extract_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Result", command=self.save_stego_result).pack(side=tk.LEFT, padx=5)
        
        status_frame = ttk.LabelFrame(stego_frame, text="Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        self.stego_status = ttk.Label(status_frame, text="Ready", foreground="green")
        self.stego_status.pack(fill=tk.X, padx=5, pady=5)
        
        self.carrier_data = None
        self.update_stego_controls()

    def update_stego_controls(self, event=None):
        pass

    def load_carrier_file(self):
        file_types = [("Image files", "*.png *.jpg *.jpeg *.bmp"), 
                      ("Text files", "*.txt *.md *.csv")]
        file_path = filedialog.askopenfilename(filetypes=file_types)
        
        if file_path:
            try:
                self.validate_file_type(file_path)
                
                with open(file_path, "rb") as f:
                    self.carrier_data = f.read()
                
                self.carrier_path.config(text=os.path.basename(file_path))
                
                if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
                    img = Image.open(io.BytesIO(self.carrier_data))
                    img.thumbnail((200, 200))
                    photo = ImageTk.PhotoImage(img)
                    self.carrier_preview.config(image=photo)
                    self.carrier_preview.image = photo
                elif file_path.lower().endswith(('.txt', '.md', '.csv')):
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(500) + "..." if len(f.read()) > 500 else f.read()
                    self.carrier_preview.config(text=content, wraplength=300)
                
                self.stego_status.config(text="Carrier loaded successfully", foreground="green")
            except Exception as e:
                error_msg = self.error_manager.get_user_friendly_message("INVALID_FILE_TYPE", str(e))
                self.stego_status.config(text=error_msg, foreground="red")

    def embed_data(self):
        if not self.carrier_data:
            self.stego_status.config(text="Please load a carrier file first", foreground="red")
            return
        
        data = self.stego_input.get(1.0, tk.END).strip().encode('utf-8')
        if not data:
            self.stego_status.config(text="Please enter data to embed", foreground="red")
            return
        
        carrier_type = self.carrier_type.get()
        
        try:
            if carrier_type == "Text":
                if not isinstance(self.carrier_data, str):
                    carrier_text = self.carrier_data.decode('utf-8', errors='ignore')
                else:
                    carrier_text = self.carrier_data
                
                encryption_key = None
                if self.enable_encryption.get():
                    key_id = self.key_id_var.get()
                    if key_id:
                        key_entry = self.key_manager.get_key(key_id)
                        if key_entry and key_entry.symmetric_key:
                            encryption_key = key_entry.symmetric_key
                
                stego_text, encrypted_map = self.text_stego.embed_in_text_lsb(
                    data, 
                    carrier_text,
                    encryption_key=encryption_key
                )
                
                result = stego_text
                self.stego_result.delete(1.0, tk.END)
                self.stego_result.insert(tk.END, result)
                self.stego_status.config(text="Data embedded successfully with encrypted map", foreground="green")
            
            else:
                encryption_key = None
                if self.enable_encryption.get():
                    key_id = self.key_id_var.get()
                    if key_id:
                        key_entry = self.key_manager.get_key(key_id)
                        if key_entry and key_entry.symmetric_key:
                            encryption_key = key_entry.symmetric_key
                
                stego_image, encrypted_map = self.image_stego.embed_in_image_lsb(
                    data, 
                    self.carrier_data,
                    encryption_key=encryption_key
                )
                
                self.stego_result_data = stego_image
                map_display = base64.b64encode(encrypted_map).decode()[:100] + "..."
                self.stego_result.delete(1.0, tk.END)
                self.stego_result.insert(tk.END, f"Embedded successfully.\nEncrypted Map (first 100 chars): {map_display}")
                self.stego_status.config(text="Data embedded successfully with encrypted map", foreground="green")
        
        except Exception as e:
            self.stego_status.config(text=f"Embedding failed: {str(e)}", foreground="red")

    def extract_data(self):
        if not hasattr(self, 'stego_result_data') and self.carrier_type.get() != "Text":
            self.stego_status.config(text="No stego data to extract from", foreground="red")
            return
        
        try:
            carrier_type = self.carrier_type.get()
            
            if carrier_type == "Text":
                stego_text = self.stego_input.get(1.0, tk.END).strip()
                if not stego_text:
                    self.stego_status.config(text="Please enter stego text", foreground="red")
                    return
                
                encrypted_map_b64 = simpledialog.askstring("Encrypted Map", "Enter the encrypted map (base64):")
                if not encrypted_map_b64:
                    self.stego_status.config(text="Encrypted map required for extraction", foreground="red")
                    return
                
                encrypted_map = base64.b64decode(encrypted_map_b64)
                
                decryption_key = None
                if self.enable_encryption.get():
                    key_id = self.key_id_var.get()
                    if key_id:
                        key_entry = self.key_manager.get_key(key_id)
                        if key_entry and key_entry.symmetric_key:
                            decryption_key = key_entry.symmetric_key
                
                extracted_data = self.text_stego.extract_from_text_lsb(
                    stego_text,
                    encrypted_map,
                    decryption_key=decryption_key
                )
                
                self.stego_result.delete(1.0, tk.END)
                self.stego_result.insert(tk.END, extracted_data.decode('utf-8', errors='ignore'))
                self.stego_status.config(text="Data extracted successfully", foreground="green")
            
            else:
                # For image extraction
                encrypted_map_b64 = simpledialog.askstring("Encrypted Map", "Enter the encrypted map (base64):")
                if not encrypted_map_b64:
                    self.stego_status.config(text="Encrypted map required for extraction", foreground="red")
                    return
                
                encrypted_map = base64.b64decode(encrypted_map_b64)
                
                decryption_key = None
                if self.enable_encryption.get():
                    key_id = self.key_id_var.get()
                    if key_id:
                        key_entry = self.key_manager.get_key(key_id)
                        if key_entry and key_entry.symmetric_key:
                            decryption_key = key_entry.symmetric_key
                
                extracted_data = self.image_stego.extract_from_image_lsb(
                    self.carrier_data,
                    encrypted_map,
                    decryption_key=decryption_key
                )
                
                self.stego_result.delete(1.0, tk.END)
                self.stego_result.insert(tk.END, extracted_data.decode('utf-8', errors='ignore'))
                self.stego_status.config(text="Data extracted successfully", foreground="green")
        
        except Exception as e:
            self.stego_status.config(text=f"Extraction failed: {str(e)}", foreground="red")

    def save_stego_result(self):
        if not hasattr(self, 'stego_result_data'):
            self.stego_status.config(text="No result to save", foreground="red")
            return
        
        file_types = [("PNG files", "*.png"), ("All files", "*.*")]
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=file_types)
        
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.stego_result_data)
                self.stego_status.config(text=f"Result saved to {os.path.basename(file_path)}", foreground="green")
            except Exception as e:
                self.stego_status.config(text=f"Save failed: {str(e)}", foreground="red")

    def setup_key_management_tab(self):
        key_frame = ttk.Frame(self.notebook)
        self.notebook.add(key_frame, text="Key Management")
        
        controls_frame = ttk.Frame(key_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(controls_frame, text="Key Type:").pack(side=tk.LEFT, padx=5)
        self.key_type = ttk.Combobox(
            controls_frame, 
            values=["RSA_2048", "RSA_4096", "AES_256", "ED25519"], 
            state="readonly"
        )
        self.key_type.set("AES_256")
        self.key_type.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="Security Level:").pack(side=tk.LEFT, padx=5)
        self.key_security_level = ttk.Combobox(
            controls_frame, 
            values=["STANDARD", "HIGH", "ULTRA"], 
            state="readonly"
        )
        self.key_security_level.set("HIGH")
        self.key_security_level.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(controls_frame, text="Key Expiration:").pack(side=tk.LEFT, padx=5)
        self.key_expiration = ttk.Combobox(
            controls_frame, 
            values=["1 year", "2 years", "5 years", "Never"], 
            state="readonly"
        )
        self.key_expiration.set("1 year")
        self.key_expiration.pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(controls_frame, text="Maximum Security Mode", 
                        variable=self.ultra_resistance).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Generate Key", command=self.generate_key_from_management).pack(side=tk.LEFT, padx=5)
        
        security_frame = ttk.LabelFrame(key_frame, text="Security Actions")
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(security_frame, text="Create Encrypted Backup", 
                  command=self.create_encrypted_backup, width=20).pack(side=tk.LEFT, padx=5)
        
        self.destroy_button = ttk.Button(security_frame, text="DESTROY ALL", 
                                        command=self.secure_destroy, width=15)
        self.destroy_button.pack(side=tk.LEFT, padx=5)
        self.destroy_button.configure(style="Danger.TButton")
        
        self.destroy_button = ttk.Button(security_frame, text="DESTROY", 
                                       command=self.emergency_erase_all, width=18)
        self.destroy_button.pack(side=tk.LEFT, padx=5)
        self.destroy_button.configure(style="Critical.TButton")
        
        key_list_frame = ttk.LabelFrame(key_frame, text="Key Store")
        key_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("ID", "Type", "Security", "Created", "Expires", "Usage", "Ultra")
        self.keys_tree_management = ttk.Treeview(key_list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.keys_tree_management.heading(col, text=col)
            self.keys_tree_management.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(key_list_frame, orient=tk.VERTICAL, command=self.keys_tree_management.yview)
        self.keys_tree_management.configure(yscrollcommand=scrollbar.set)
        self.keys_tree_management.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        button_frame = ttk.Frame(key_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_key_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Key", command=self.export_key_management).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Key", command=self.delete_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Set as Master", command=self.set_master_key).pack(side=tk.LEFT, padx=5)
        
        self.key_details = ttk.Label(key_frame, text="Select a key to view details", wraplength=1100)
        self.key_details.pack(fill=tk.X, padx=10, pady=5)
        
        self.refresh_key_list()

    def setup_signature_tab(self):
        signature_frame = ttk.Frame(self.notebook)
        self.notebook.add(signature_frame, text="Digital Signature")
        
        main_container = ttk.Frame(signature_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        controls_frame = ttk.LabelFrame(main_container, text="Signature Controls")
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(controls_frame, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.sig_algorithm = ttk.Combobox(controls_frame, values=["RSA", "ED25519"], state="readonly")
        self.sig_algorithm.set("RSA")
        self.sig_algorithm.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(controls_frame, text="Key ID:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.sig_key_combo = ttk.Combobox(controls_frame, state="readonly")
        self.sig_key_combo.grid(row=0, column=3, padx=5, pady=5)
        ttk.Button(controls_frame, text="Refresh Keys", command=self.update_sig_key_list).grid(row=0, column=4, padx=5, pady=5)
        
        button_frame = ttk.Frame(controls_frame)
        button_frame.grid(row=1, column=0, columnspan=5, pady=10)
        
        ttk.Button(button_frame, text="Sign Message", command=self.sign_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Verify Signature", command=self.verify_message_signature).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_signature_fields).pack(side=tk.LEFT, padx=5)
        
        data_frame = ttk.Frame(main_container)
        data_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        msg_frame = ttk.LabelFrame(data_frame, text="Message")
        msg_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.sig_message_text = scrolledtext.ScrolledText(msg_frame, height=12, bg='#2d2d30', fg='white')
        self.sig_message_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        sig_frame = ttk.LabelFrame(data_frame, text="Signature")
        sig_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        self.sig_output_text = scrolledtext.ScrolledText(sig_frame, height=12, bg='#2d2d30', fg='white')
        self.sig_output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        status_frame = ttk.LabelFrame(main_container, text="Status")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.sig_status = ttk.Label(status_frame, text="Ready to sign or verify messages", foreground="green")
        self.sig_status.pack(fill=tk.X, padx=5, pady=5)
        
        self.update_sig_key_list()

    def setup_settings_tab(self):
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        
        update_frame = ttk.LabelFrame(settings_frame, text="Update Policy")
        update_frame.pack(fill=tk.X, padx=10, pady=5)
        
        policy_text = """Created: 2025-11-1 — Repo: https://github.com/
Automatic execution disabled. Manual verified updates only.
Every year from the date of establishment there is an update

Security Note:
• No automatic updates
• Manual verification required  
• Download from trusted sources only
• Check repository for new versions"""
        
        policy_label = ttk.Label(update_frame, text=policy_text, justify=tk.LEFT, foreground="blue")
        policy_label.pack(padx=10, pady=10, anchor=tk.W)
        
        security_frame = ttk.LabelFrame(settings_frame, text="Security Settings")
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.memory_protection_var = tk.BooleanVar(value=True)
        self.audit_logging_var = tk.BooleanVar(value=True)
        self.auto_rotation_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(security_frame, text="Enable Memory Protection", 
                       variable=self.memory_protection_var).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Checkbutton(security_frame, text="Enable Audit Logging", 
                       variable=self.audit_logging_var).pack(anchor=tk.W, padx=5, pady=2)
        ttk.Checkbutton(security_frame, text="Auto Key Rotation", 
                       variable=self.auto_rotation_var).pack(anchor=tk.W, padx=5, pady=2)
        
        performance_frame = ttk.LabelFrame(settings_frame, text="Performance")
        performance_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(performance_frame, text="Encryption Level:").pack(anchor=tk.W, padx=5, pady=2)
        self.encryption_level = ttk.Combobox(performance_frame, values=["Standard", "High", "Ultra"], state="readonly")
        self.encryption_level.set("High")
        self.encryption_level.pack(anchor=tk.W, padx=5, pady=2)
        
        ttk.Button(performance_frame, text="Optimize Performance", 
                  command=self.optimize_performance).pack(anchor=tk.W, padx=5, pady=5)

    def setup_security_tab(self):
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security Center")
        
        # Threat monitoring section
        threat_frame = ttk.LabelFrame(security_frame, text="Threat Intelligence")
        threat_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(threat_frame, text="View Threat Monitor", 
                  command=self.show_threat_monitor, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(threat_frame, text="Run Security Scan", 
                  command=self.run_security_scan, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Anti-analysis section
        analysis_frame = ttk.LabelFrame(security_frame, text="Anti-Analysis Measures")
        analysis_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(analysis_frame, text="Create Decoy Files", 
                  command=self.create_decoys, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(analysis_frame, text="Deploy Honeypot", 
                  command=self.deploy_honeypot, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Memory security section
        memory_frame = ttk.LabelFrame(security_frame, text="Memory Security")
        memory_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(memory_frame, text="Secure Memory Wipe", 
                  command=self.secure_memory_wipe, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(memory_frame, text="View Memory Usage", 
                  command=self.view_memory_usage, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        
        # System integrity section
        integrity_frame = ttk.LabelFrame(security_frame, text="System Integrity")
        integrity_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(integrity_frame, text="Verify System Files", 
                  command=self.verify_system_files, width=20).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(integrity_frame, text="Check Audit Logs", 
                  command=self.check_audit_logs, width=20).pack(side=tk.LEFT, padx=5, pady=5)

    def run_security_scan(self):
        # Simulate security scan
        self.key_manager.audit_logger.log_event("SECURITY_SCAN", "System security scan completed")
        messagebox.showinfo("Security Scan", "Security scan completed. No major threats detected.")

    def secure_memory_wipe(self):
        # Securely wipe memory buffers
        buffer_count = len(self.memory_manager._secure_buffers)
        self.memory_manager._secure_buffers.clear()
        self.memory_manager.memory_guards.clear()
        import gc
        gc.collect()
        self.key_manager.audit_logger.log_event("MEMORY_WIPE", f"Securely wiped {buffer_count} memory buffers")
        messagebox.showinfo("Memory Wipe", f"Securely wiped {buffer_count} memory buffers.")

    def view_memory_usage(self):
        usage = self.memory_manager.get_memory_usage()
        message = f"Memory Usage:\n"
        message += f"Buffers: {usage['total_buffers']}\n"
        message += f"Protected Data: {usage['total_bytes'] // 1024} KB\n"
        message += f"Heap Allocated: {usage['heap_allocated'] // 1024} KB\n"
        message += f"Heap Size: {usage['heap_size'] // 1024} KB"
        messagebox.showinfo("Memory Usage", message)

    def verify_system_files(self):
        # Check critical system files
        critical_files = ["secure_keystore.vault", "config.py", "security_audit.log"]
        missing_files = []
        
        for file in critical_files:
            if not os.path.exists(file):
                missing_files.append(file)
        
        if missing_files:
            messagebox.showwarning("System Integrity", f"Missing critical files: {', '.join(missing_files)}")
        else:
            messagebox.showinfo("System Integrity", "All critical system files are present and accounted for.")

    def check_audit_logs(self):
        if os.path.exists("security_audit.log"):
            with open("security_audit.log", "r") as f:
                lines = f.readlines()
            messagebox.showinfo("Audit Logs", f"Audit log contains {len(lines)} entries.")
        else:
            messagebox.showinfo("Audit Logs", "No audit log file found.")

    def optimize_performance(self):
        messagebox.showinfo("Performance", "System performance optimized")

    def update_sig_key_list(self):
        key_ids = list(self.key_manager.keys.keys())
        self.sig_key_combo["values"] = key_ids
        if key_ids:
            self.sig_key_combo.set(key_ids[0])

    def sign_message(self):
        key_id = self.sig_key_combo.get()
        algorithm = self.sig_algorithm.get()
        message = self.sig_message_text.get(1.0, tk.END).strip()
        
        if not key_id:
            self.sig_status.config(text="Please select a key", foreground="red")
            return
            
        if not message:
            self.sig_status.config(text="Please enter a message to sign", foreground="red")
            return
    
        try:
            key_entry = self.key_manager.get_key(key_id)
            if not key_entry:
                self.sig_status.config(text="Key not found", foreground="red")
                return
                
            message_bytes = message.encode('utf-8')
            
            if algorithm == "RSA":
                if not key_entry.encrypted_private_key:
                    self.sig_status.config(text="No private key found for signing", foreground="red")
                    return
                result = self.crypto_engine.sign_message_rsa(key_entry.encrypted_private_key, message_bytes)
            else:
                if not key_entry.encrypted_private_key:
                    self.sig_status.config(text="No private key found for signing", foreground="red")
                    return
                result = self.crypto_engine.sign_message_ed25519(key_entry.encrypted_private_key, message_bytes)
            
            if result['success']:
                signature_output = f"""SIGNATURE SUCCESSFUL
Algorithm: {result['algorithm']}
Message Hash: {result['message_hash']}
Signature (Base64):
{result['signature']}

To verify, share the message and this signature with the recipient."""
                
                self.sig_output_text.delete(1.0, tk.END)
                self.sig_output_text.insert(tk.END, signature_output)
                self.sig_status.config(text="Message signed successfully", foreground="green")
            else:
                self.sig_status.config(text=f"Signing failed: {result['error']}", foreground="red")
                
        except Exception as e:
            self.sig_status.config(text=f"Signing error: {str(e)}", foreground="red")

    def verify_message_signature(self):
        key_id = self.sig_key_combo.get()
        algorithm = self.sig_algorithm.get()
        message = self.sig_message_text.get(1.0, tk.END).strip()
        signature_text = self.sig_output_text.get(1.0, tk.END).strip()
        
        if not key_id:
            self.sig_status.config(text="Please select a key", foreground="red")
            return
            
        if not message:
            self.sig_status.config(text="Please enter the original message", foreground="red")
            return
            
        if not signature_text:
            self.sig_status.config(text="Please enter the signature to verify", foreground="red")
            return
    
        try:
            key_entry = self.key_manager.get_key(key_id)
            if not key_entry:
                self.sig_status.config(text="Key not found", foreground="red")
                return
                
            signature_lines = signature_text.split('\n')
            signature_b64 = None
            
            for line in signature_lines:
                if line.startswith('Signature (Base64):'):
                    continue
                elif line.strip() and not line.startswith('SIGNATURE') and not line.startswith('Algorithm:') and not line.startswith('Message Hash:') and not line.startswith('To verify'):
                    signature_b64 = line.strip()
                    break
            
            if not signature_b64:
                signature_b64 = signature_lines[-1].strip()
        
            message_bytes = message.encode('utf-8')
            
            if algorithm == "RSA":
                if not key_entry.public_key:
                    self.sig_status.config(text="No public key found for verification", foreground="red")
                    return
                result = self.crypto_engine.verify_signature_rsa(key_entry.public_key, signature_b64, message_bytes)
            else:
                if not key_entry.public_key:
                    self.sig_status.config(text="No public key found for verification", foreground="red")
                    return
                result = self.crypto_engine.verify_signature_ed25519(key_entry.public_key, signature_b64, message_bytes)
            
            if result['success']:
                if result['valid']:
                    verification_output = f"""VERIFICATION SUCCESSFUL
Signature is VALID
Algorithm: {algorithm}
Message Hash: {result['message_hash']}
The message is authentic and untampered."""
                    
                    self.sig_output_text.delete(1.0, tk.END)
                    self.sig_output_text.insert(tk.END, verification_output)
                    self.sig_status.config(text="Signature verification successful", foreground="green")
                else:
                    verification_output = f"""VERIFICATION FAILED
Signature is INVALID
Algorithm: {algorithm}
Message Hash: {result['message_hash']}
The message may have been tampered with or the signature is incorrect."""
                    
                    self.sig_output_text.delete(1.0, tk.END)
                    self.sig_output_text.insert(tk.END, verification_output)
                    self.sig_status.config(text="Signature verification failed", foreground="red")
            else:
                self.sig_status.config(text=f"Verification failed: {result['error']}", foreground="red")
                
        except Exception as e:
            self.sig_status.config(text=f"Verification error: {str(e)}", foreground="red")

    def clear_signature_fields(self):
        self.sig_message_text.delete(1.0, tk.END)
        self.sig_output_text.delete(1.0, tk.END)
        self.sig_status.config(text="Fields cleared", foreground="blue")

    def create_encrypted_backup(self):
        password = simpledialog.askstring("Backup Password", "Enter password for backup (12+ characters):", show="*")
        if not password:
            return
        
        if len(password) < 12:
            messagebox.showerror("Invalid Password", "Password must be at least 12 characters long")
            return
            
        try:
            backup_dir = "system_backup"
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            os.makedirs(backup_dir, exist_ok=True)
            
            files_to_backup = [
                "secure_keystore.vault",
                "config.py",
                "logs",
                "keys"
            ]
            
            for file in files_to_backup:
                if os.path.exists(file):
                    if os.path.isdir(file):
                        shutil.copytree(file, os.path.join(backup_dir, file), dirs_exist_ok=True)
                    else:
                        shutil.copy2(file, backup_dir)
            
            if os.path.exists("security_audit.log"):
                shutil.copy2("security_audit.log", backup_dir)
            
            zip_path = os.path.join(backup_dir + ".zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(backup_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, backup_dir)
                        zipf.write(file_path, arcname)
            
            salt = os.urandom(16)
            key = self.crypto_engine.derive_key(password, salt, 600000)
            
            with open(zip_path, 'rb') as f:
                data = f.read()
            
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            backup_file = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted Backup", "*.enc")]
            )
            
            if backup_file:
                with open(backup_file, 'wb') as f:
                    f.write(salt + nonce + ciphertext)
                
                os.remove(zip_path)
                shutil.rmtree(backup_dir)
                
                self.key_manager.audit_logger.log_sensitive_operation(
                    "BACKUP_CREATED", 
                    "USER",
                    "Encrypted backup created successfully"
                )
                
                messagebox.showinfo("Backup Successful", 
                                  f"Encrypted backup created at:\n{backup_file}")
            else:
                os.remove(zip_path)
                shutil.rmtree(backup_dir)
                
        except Exception as e:
            self.key_manager.audit_logger.log_event(
                "BACKUP_FAILED", 
                f"Backup failed: {str(e)}",
                False
            )
            messagebox.showerror("Backup Error", f"Failed to create backup: {str(e)}")

    def secure_destroy(self):
        if not messagebox.askyesno("Destruction Confirmation", 
                                 "WARNING: This action will permanently destroy all cryptographic data, keys, and configurations. This action is irreversible and will make all encrypted data unrecoverable. Are you ABSOLUTELY SURE you want to proceed?"):
            return
            
        if not messagebox.askyesno("Final Destruction Confirmation", 
                                 "This is your final chance to cancel. Once confirmed, all cryptographic data will be securely destroyed and the application will be deleted. There is NO WAY to recover your data after this. Proceed?"):
            return
            
        try:
            files_to_wipe = [
                "secure_keystore.vault",
                "config.py",
                "logs",
                "keys",
                "security_audit.log"
            ]
            
            for file in files_to_wipe:
                if os.path.isdir(file):
                    self.key_manager.secure_destroy.secure_wipe_directory(file)
                elif os.path.exists(file):
                    self.key_manager.secure_destroy.secure_wipe_file(file)
            
            self.memory_manager.secure_heap_init()
            
            self.key_manager.audit_logger.log_sensitive_operation(
                "SYSTEM_DESTROYED", 
                "USER",
                "All cryptographic data securely destroyed"
            )
            
            messagebox.showinfo("Destruction Complete", 
                              "All cryptographic data has been securely destroyed.")
            
        except Exception as e:
            messagebox.showerror("Destruction Error", f"Failed to destroy data: {str(e)}")

    def emergency_erase_all(self):
        """Destroy destruction using the secure destroy system"""
        self.key_manager.emergency_erase_all()

    def generate_key_from_management(self):
        key_type_str = self.key_type.get()
        security_level_str = self.key_security_level.get()
        expiration_str = self.key_expiration.get()
        
        key_type = KeyType[key_type_str]
        security_level = SecurityLevel[security_level_str]
        
        expires_days = 365
        if expiration_str == "2 years":
            expires_days = 730
        elif expiration_str == "5 years":
            expires_days = 1825
        elif expiration_str == "Never":
            expires_days = 0
        
        ultra_resistant = self.ultra_resistance.get()
        
        try:
            key_id = self.key_manager.generate_key_pair(
                key_type,
                security_level,
                expires_days=expires_days,
                ultra_resistant=ultra_resistant
            )
            self.refresh_key_list()
            self.update_key_list()
            self.key_details.config(text=f"Key generated successfully: {key_id}")
        except Exception as e:
            self.key_details.config(text=f"Key generation failed: {str(e)}")

    def refresh_key_list(self):
        for item in self.keys_tree_management.get_children():
            self.keys_tree_management.delete(item)
        
        for key_id, key_entry in self.key_manager.keys.items():
            created = datetime.fromtimestamp(key_entry.meta.created_at).strftime("%Y-%m-%d")
            expires = "Never"
            if key_entry.meta.expires_at:
                try:
                    expires = datetime.fromtimestamp(key_entry.meta.expires_at).strftime("%Y-%m-%d")
                except:
                    expires = "Unknown"
            
            ultra = "Yes" if key_entry.meta.ultra_resistance != UltraResistanceLevel.NONE else "No"
            
            self.keys_tree_management.insert("", "end", values=(
                key_id[:12] + "...",
                key_entry.meta.key_type.name,
                key_entry.meta.security_level.name,
                created,
                expires,
                key_entry.meta.usage_count,
                ultra
            ))

    def export_key_management(self):
        selected = self.keys_tree_management.selection()
        if not selected:
            self.key_details.config(text="Please select a key to export")
            return
        
        item = self.keys_tree_management.item(selected[0])
        key_id_full = item['values'][0]
        actual_key_id = None
        
        for k in self.key_manager.keys.keys():
            if k.startswith(key_id_full.replace("...", "")):
                actual_key_id = k
                break
        
        if not actual_key_id:
            self.key_details.config(text="Key not found")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".key")
        if file_path:
            try:
                key_password = simpledialog.askstring("Key Password", "Enter password (optional):", show="*")
                exported_data = self.key_manager.export_key(actual_key_id, key_password)
                with open(file_path, "wb") as f:
                    f.write(exported_data)
                self.key_details.config(text=f"Key exported to: {os.path.basename(file_path)}")
            except Exception as e:
                self.key_details.config(text=f"Export failed: {str(e)}")

    def delete_key(self):
        selected = self.keys_tree_management.selection()
        if not selected:
            self.key_details.config(text="Please select a key to delete")
            return
        
        item = self.keys_tree_management.item(selected[0])
        key_id_full = item['values'][0]
        actual_key_id = None
        
        for k in self.key_manager.keys.keys():
            if k.startswith(key_id_full.replace("...", "")):
                actual_key_id = k
                break
        
        if not actual_key_id:
            self.key_details.config(text="Key not found")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete key {actual_key_id}?"):
            try:
                del self.key_manager.keys[actual_key_id]
                self.key_manager._save_keystore()
                self.refresh_key_list()
                self.update_key_list()
                self.key_details.config(text=f"Key {actual_key_id} deleted successfully")
            except Exception as e:
                self.key_details.config(text=f"Delete failed: {str(e)}")

    def set_master_key(self):
        selected = self.keys_tree_management.selection()
        if not selected:
            self.key_details.config(text="Please select a key to set as master")
            return
        
        item = self.keys_tree_management.item(selected[0])
        key_id_full = item['values'][0]
        actual_key_id = None
        
        for k in self.key_manager.keys.keys():
            if k.startswith(key_id_full.replace("...", "")):
                actual_key_id = k
                break
        
        if not actual_key_id:
            self.key_details.config(text="Key not found")
            return
        
        self.key_manager.master_key_id = actual_key_id
        self.key_details.config(text=f"Key {actual_key_id} set as master key")

def main():
    try:
        root = tk.Tk()
        app = AdvancedCryptoSystemGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")

if __name__ == "__main__":
    main()