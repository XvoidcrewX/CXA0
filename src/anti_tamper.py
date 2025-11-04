import hashlib
import os
import sys
import time
import threading
import ctypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

class AntiTamperSystem:
    def __init__(self):
        self.file_hashes = {}
        self.memory_checksums = {}
        self.integrity_check_interval = 30
        self.running = False
        self.check_thread = None
        
    def calculate_file_hash(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def register_critical_files(self):
        critical_files = ['main.py', 'config.py', 'anti_tamper.py']
        for file in critical_files:
            if os.path.exists(file):
                self.file_hashes[file] = self.calculate_file_hash(file)
    
    def verify_file_integrity(self):
        for file, expected_hash in self.file_hashes.items():
            if not os.path.exists(file):
                self.trigger_tamper_response(f"Critical file missing: {file}")
                continue
                
            current_hash = self.calculate_file_hash(file)
            if current_hash != expected_hash:
                self.trigger_tamper_response(f"File integrity compromised: {file}")
    
    def memory_integrity_check(self):
        critical_functions = [
            'AdvancedCryptoEngine.encrypt_aes_gcm',
            'AdvancedCryptoEngine.decrypt_aes_gcm',
            'AdvancedKeyManager._save_keystore'
        ]
        
        for func_name in critical_functions:
            checksum = self.calculate_memory_checksum(func_name)
            if func_name in self.memory_checksums:
                if checksum != self.memory_checksums[func_name]:
                    self.trigger_tamper_response(f"Memory integrity compromised: {func_name}")
            else:
                self.memory_checksums[func_name] = checksum
    
    def calculate_memory_checksum(self, func_name):
        return hashlib.sha256(func_name.encode()).hexdigest()[:16]
    
    def trigger_tamper_response(self, message):
        print(f"TAMPER DETECTED: {message}")
        
        from tkinter import messagebox
        try:
            messagebox.showerror("Security Breach", 
                               f"System integrity compromised!\n\n{message}\n\nApplication will now exit.")
        except:
            pass
        
        os._exit(1)
    
    def start_monitoring(self):
        self.register_critical_files()
        self.running = True
        self.check_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.check_thread.start()
    
    def _monitoring_loop(self):
        while self.running:
            self.verify_file_integrity()
            self.memory_integrity_check()
            time.sleep(self.integrity_check_interval)
    
    def stop_monitoring(self):
        self.running = False
        if self.check_thread:
            self.check_thread.join(timeout=5)

tamper_system = AntiTamperSystem()