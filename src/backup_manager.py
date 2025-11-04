import os
import shutil
import zipfile
import json
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class BackupManager:
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.backup_dir = "system_backups"
        self.auto_backup_interval = 24 * 3600
        self.max_backups = 10
        self.last_backup_time = 0
        
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def create_backup(self, password=None, description=""):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
            temp_dir = os.path.join(self.backup_dir, backup_name)
            
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)
            
            files_to_backup = self._get_files_to_backup()
            
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    if os.path.isdir(file_path):
                        shutil.copytree(file_path, os.path.join(temp_dir, os.path.basename(file_path)))
                    else:
                        shutil.copy2(file_path, temp_dir)
            
            metadata = {
                "timestamp": time.time(),
                "description": description,
                "version": "1.0.0",
                "file_count": len(files_to_backup),
                "created_by": "CXA Crypto System"
            }
            
            with open(os.path.join(temp_dir, "backup_metadata.json"), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            zip_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
            
            shutil.rmtree(temp_dir)
            
            if password:
                encrypted_zip_path = self._encrypt_backup(zip_path, password)
                os.remove(zip_path)
                final_path = encrypted_zip_path
            else:
                final_path = zip_path
            
            self._cleanup_old_backups()
            
            self.key_manager.audit_logger.log_event(
                "BACKUP_CREATED",
                f"Backup created: {os.path.basename(final_path)}",
                True
            )
            
            return final_path
            
        except Exception as e:
            self.key_manager.audit_logger.log_event(
                "BACKUP_FAILED",
                f"Backup creation failed: {str(e)}",
                False
            )
            raise
    
    def _get_files_to_backup(self):
        return [
            "secure_keystore.vault",
            "config.py",
            "security_audit.log",
            "key_archive"
        ]
    
    def _encrypt_backup(self, zip_path, password):
        salt = secrets.token_bytes(16)
        key = self.key_manager.crypto_engine.derive_key(password, salt, 600000)
        
        with open(zip_path, 'rb') as f:
            data = f.read()
        
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        encrypted_path = zip_path.replace('.zip', '.enc')
        
        with open(encrypted_path, 'wb') as f:
            f.write(salt + nonce + ciphertext)
        
        return encrypted_path
    
    def restore_backup(self, backup_path, password=None):
        try:
            if backup_path.endswith('.enc'):
                if not password:
                    raise ValueError("Password required for encrypted backup")
                
                decrypted_path = self._decrypt_backup(backup_path, password)
                backup_path = decrypted_path
            
            temp_extract = "temp_restore"
            if os.path.exists(temp_extract):
                shutil.rmtree(temp_extract)
            os.makedirs(temp_extract)
            
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(temp_extract)
            
            metadata_path = os.path.join(temp_extract, "backup_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                if metadata.get('version') != "1.0.0":
                    raise ValueError("Incompatible backup version")
            
            for item in os.listdir(temp_extract):
                if item == "backup_metadata.json":
                    continue
                    
                source = os.path.join(temp_extract, item)
                destination = item
                
                if os.path.exists(destination):
                    if os.path.isdir(destination):
                        shutil.rmtree(destination)
                    else:
                        os.remove(destination)
                
                if os.path.isdir(source):
                    shutil.copytree(source, destination)
                else:
                    shutil.copy2(source, destination)
            
            shutil.rmtree(temp_extract)
            
            if backup_path.endswith('.decrypted'):
                os.remove(backup_path)
            
            self.key_manager.audit_logger.log_event(
                "BACKUP_RESTORED",
                f"Backup restored: {os.path.basename(backup_path)}",
                True
            )
            
        except Exception as e:
            self.key_manager.audit_logger.log_event(
                "BACKUP_RESTORE_FAILED",
                f"Backup restoration failed: {str(e)}",
                False
            )
            raise
    
    def _decrypt_backup(self, encrypted_path, password):
        with open(encrypted_path, 'rb') as f:
            data = f.read()
        
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        key = self.key_manager.crypto_engine.derive_key(password, salt, 600000)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        decrypted_path = encrypted_path.replace('.enc', '.decrypted')
        
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        return decrypted_path
    
    def _cleanup_old_backups(self):
        backup_files = []
        for file in os.listdir(self.backup_dir):
            if file.startswith('backup_') and (file.endswith('.zip') or file.endswith('.enc')):
                file_path = os.path.join(self.backup_dir, file)
                backup_files.append((file_path, os.path.getctime(file_path)))
        
        backup_files.sort(key=lambda x: x[1], reverse=True)
        
        if len(backup_files) > self.max_backups:
            for file_path, _ in backup_files[self.max_backups:]:
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Failed to delete old backup {file_path}: {e}")
    
    def list_backups(self):
        backups = []
        for file in os.listdir(self.backup_dir):
            if file.startswith('backup_') and (file.endswith('.zip') or file.endswith('.enc')):
                file_path = os.path.join(self.backup_dir, file)
                stats = os.stat(file_path)
                
                backup_info = {
                    'filename': file,
                    'path': file_path,
                    'size_mb': stats.st_size / (1024 * 1024),
                    'created': datetime.fromtimestamp(stats.st_ctime),
                    'encrypted': file.endswith('.enc')
                }
                
                backups.append(backup_info)
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    def auto_backup_check(self):
        current_time = time.time()
        if current_time - self.last_backup_time > self.auto_backup_interval:
            try:
                self.create_backup(description="Automatic scheduled backup")
                self.last_backup_time = current_time
                return True
            except Exception as e:
                print(f"Auto-backup failed: {e}")
                return False
        return None

backup_manager = BackupManager(None)