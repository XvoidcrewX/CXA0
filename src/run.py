import os
import sys
import tkinter as tk
from tkinter import messagebox
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cxa_system.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    required_packages = [
        'cryptography',
        'numpy', 
        'Pillow',
        'psutil',
        'keyring'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def main():
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        missing_packages = check_dependencies()
        if missing_packages:
            messagebox.showwarning(
                "Missing Dependencies",
                f"The following packages are missing:\n{', '.join(missing_packages)}\n\nPlease install them using:\npip install -r requirements.txt"
            )
            return
        
        from anti_tamper import tamper_system
        tamper_system.start_monitoring()
        
        from main import AdvancedCryptoSystemGUI
        
        root = tk.Tk()
        app = AdvancedCryptoSystemGUI(root)
        
        logger.info("CXA Cryptographic System started successfully")
        
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Application failed to start: {e}")
        messagebox.showerror(
            "Fatal Error",
            f"Failed to start application:\n{str(e)}\n\nPlease check the logs for more details."
        )
    finally:
        if 'tamper_system' in locals():
            tamper_system.stop_monitoring()

if __name__ == "__main__":
    main()