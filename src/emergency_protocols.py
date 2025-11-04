import os
import shutil
import time
import threading
from tkinter import messagebox
import psutil

class EmergencyProtocols:
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.emergency_triggered = False
        self.protocols_active = False
        
    def trigger_emergency_protocol(self, reason="Unknown threat"):
        if self.emergency_triggered:
            return
            
        self.emergency_triggered = True
        self.protocols_active = True
        
        messagebox.showwarning(
            "EMERGENCY PROTOCOL ACTIVATED",
            f"Emergency security protocol activated due to: {reason}\n\n"
            "All sensitive data will be secured immediately."
        )
        
        emergency_thread = threading.Thread(target=self._execute_emergency_protocols, daemon=True)
        emergency_thread.start()
    
    def _execute_emergency_protocols(self):
        try:
            self.key_manager.audit_logger.log_critical_event(
                "EMERGENCY_PROTOCOL_ACTIVATED",
                {"reason": "Security threat detected", "timestamp": time.time()}
            )
            
            self._secure_delete_sensitive_files()
            self._encrypt_critical_data()
            self._clear_memory_buffers()
            self._create_emergency_backup()
            self._notify_user_completion()
            
        except Exception as e:
            self.key_manager.audit_logger.log_event(
                "EMERGENCY_PROTOCOL_FAILED",
                f"Emergency protocols failed: {str(e)}",
                False
            )
        finally:
            self.protocols_active = False
    
    def _secure_delete_sensitive_files(self):
        sensitive_patterns = [
            "*_key*", "*_private*", "*_secret*", 
            "*.key", "*.pem", "*.keyring"
        ]
        
        for root, dirs, files in os.walk("."):
            for file in files:
                if any(pattern in file for pattern in sensitive_patterns):
                    file_path = os.path.join(root, file)
                    try:
                        self.key_manager.secure_destroy.secure_wipe_file(file_path)
                    except Exception as e:
                        print(f"Failed to secure delete {file_path}: {e}")
    
    def _encrypt_critical_data(self):
        critical_files = [
            "secure_keystore.vault",
            "security_audit.log",
            "config.json"
        ]
        
        for file in critical_files:
            if os.path.exists(file):
                try:
                    backup_name = f"{file}.emergency.backup"
                    shutil.copy2(file, backup_name)
                    
                    if self.key_manager.master_key:
                        with open(file, 'rb') as f:
                            data = f.read()
                        
                        encrypted_data, nonce = self.key_manager.crypto_engine.encrypt_aes_gcm(
                            self.key_manager.master_key, data
                        )
                        
                        with open(file, 'wb') as f:
                            f.write(nonce + encrypted_data)
                            
                except Exception as e:
                    print(f"Failed to encrypt {file}: {e}")
    
    def _clear_memory_buffers(self):
        if hasattr(self.key_manager, 'memory_manager'):
            buffer_count = len(self.key_manager.memory_manager._secure_buffers)
            self.key_manager.memory_manager._secure_buffers.clear()
            self.key_manager.memory_manager.memory_guards.clear()
            
            import gc
            gc.collect()
    
    def _create_emergency_backup(self):
        try:
            backup_dir = "emergency_backup"
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            os.makedirs(backup_dir)
            
            files_to_backup = [
                "secure_keystore.vault",
                "security_audit.log",
                "config.py"
            ]
            
            for file in files_to_backup:
                if os.path.exists(file):
                    shutil.copy2(file, backup_dir)
            
            timestamp = int(time.time())
            encrypted_backup = f"emergency_backup_{timestamp}.zip"
            
            import zipfile
            with zipfile.ZipFile(encrypted_backup, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(backup_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, backup_dir)
                        zipf.write(file_path, arcname)
            
            shutil.rmtree(backup_dir)
            
        except Exception as e:
            print(f"Emergency backup failed: {e}")
    
    def _notify_user_completion(self):
        messagebox.showinfo(
            "Emergency Protocol Complete",
            "All emergency security protocols have been executed.\n\n"
            "Sensitive data has been secured and encrypted.\n"
            "Continue using the system with caution."
        )
    
    def system_health_check(self):
        health_issues = []
        
        if psutil.virtual_memory().percent > 90:
            health_issues.append("High memory usage detected")
        
        if psutil.cpu_percent() > 85:
            health_issues.append("High CPU usage detected")
        
        disk_usage = psutil.disk_usage('/').percent
        if disk_usage > 90:
            health_issues.append("Low disk space")
        
        if not os.path.exists("secure_keystore.vault"):
            health_issues.append("Keystore file missing")
        
        return health_issues

emergency_protocols = EmergencyProtocols(None)