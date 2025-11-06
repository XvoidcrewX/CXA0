import os
import json
import secrets
from datetime import datetime

class Config:
    APP_NAME = "CXA Cryptographic System"
    VERSION = "1.0.0"
    BUILD_DATE = "2025-11-04"
    
    SECURITY_SETTINGS = {
        "min_password_length": 9,
        "max_key_age_days": 365,
        "auto_backup_interval": 24,
        "max_login_attempts": 10,
        "session_timeout": 900
    }
    
    CRYPTO_SETTINGS = {
        "default_rsa_key_size": 4096,
        "default_aes_key_size": 256,
        "kdf_iterations": 600000,
        "key_rotation_days": 30
    }
    
    UI_SETTINGS = {
        "theme": "dark",
        "language": "en",
        "font_size": 10,
        "auto_save": True
    }
    
    LOGGING_SETTINGS = {
        "log_level": "INFO",
        "max_log_size_mb": 0,
        "backup_count": 5,
        "audit_log_enabled": True
    }
    
    @classmethod
    def load_config(cls, config_file="config.json"):
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                cls._update_settings(user_config)
            except Exception as e:
                print(f"Config load error: {e}")
    
    @classmethod
    def save_config(cls, config_file="config.json"):
        try:
            config_data = {
                "security_settings": cls.SECURITY_SETTINGS,
                "crypto_settings": cls.CRYPTO_SETTINGS,
                "ui_settings": cls.UI_SETTINGS,
                "logging_settings": cls.LOGGING_SETTINGS
            }
            
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Config save error: {e}")
    
    @classmethod
    def _update_settings(cls, user_config):
        for section, settings in user_config.items():
            if hasattr(cls, section.upper()):
                getattr(cls, section.upper()).update(settings)

config = Config()
