import tkinter as tk
from tkinter import ttk, scrolledtext
import webbrowser

class HelpSystem:
    def __init__(self, parent):
        self.parent = parent
        self.help_data = {
            "Cryptography": {
                "Encryption/Decryption": "Use the Cryptography tab to encrypt and decrypt data using various algorithms including AES-GCM, ChaCha20, and RSA-OAEP.",
                "Key Management": "Generate and manage cryptographic keys with different security levels and expiration dates.",
                "Security Levels": "STANDARD: Basic security\nHIGH: security with longer keys\nULTRA: Maximum security with ultra-resistant keys"
            },
            "Steganography": {
                "Data Hiding": "Hide secret data within text or image files using LSB steganography.",
                "Encrypted Maps": "steganography uses encrypted embedding maps for additional security.",
                "Carrier Files": "Use PNG, JPG images or text files as carriers for hidden data."
            },
            "Key Management": {
                "Key Generation": "Generate RSA, AES, and ED25519 keys with customizable security parameters.",
                "Key Rotation": "Automatically rotate expired keys to maintain security.",
                "Backup & Recovery": "Create encrypted backups of your cryptographic keys."
            },
            "Digital Signatures": {
                "Message Signing": "Create digital signatures to verify message authenticity.",
                "Signature Verification": "Verify signatures to ensure message integrity and sender identity.",
                "Supported Algorithms": "RSA-PSS and Ed25519 signature algorithms are supported."
            },
            "Security Features": {
                "Memory Protection": "Secure memory manager protects sensitive data in memory.",
                "Threat Monitoring": "Real-time monitoring for suspicious activities.",
                "Anti-Tampering": "System integrity checks prevent unauthorized modifications.",
                "Secure Destruction": "Destroy destruction options for complete data eradication."
            }
        }
    
    def show_help_window(self, section=None, topic=None):
        help_window = tk.Toplevel(self.parent)
        help_window.title("CXA Crypto System Help")
        help_window.geometry("800x600")
        help_window.minsize(600, 400)
        
        main_frame = ttk.Frame(help_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_frame = ttk.Frame(main_frame, width=200)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(left_frame)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        for section_name, topics in self.help_data.items():
            section_id = self.tree.insert("", "end", text=section_name, open=True)
            for topic_name in topics.keys():
                self.tree.insert(section_id, "end", text=topic_name)
        
        content_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=60)
        content_area.pack(fill=tk.BOTH, expand=True)
        
        def on_select(event):
            selected = self.tree.selection()
            if selected:
                item_text = self.tree.item(selected[0], "text")
                parent = self.tree.parent(selected[0])
                
                if parent:
                    section_name = self.tree.item(parent, "text")
                    content = self.help_data.get(section_name, {}).get(item_text, "Help content not found.")
                else:
                    content = f"# {item_text}\n\nSelect a topic to view help content."
                
                content_area.delete(1.0, tk.END)
                content_area.insert(1.0, content)
        
        self.tree.bind("<<TreeviewSelect>>", on_select)
        
        button_frame = ttk.Frame(right_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Online Documentation", 
                  command=lambda: webbrowser.open("https://github.com/your-repo/docs")).pack(side=tk.LEFT)
        
        ttk.Button(button_frame, text="Close", 
                  command=help_window.destroy).pack(side=tk.RIGHT)
        
        if section and topic:
            self._navigate_to_topic(section, topic)
    
    def _navigate_to_topic(self, section, topic):
        for child in self.tree.get_children():
            if self.tree.item(child, "text") == section:
                for subchild in self.tree.get_children(child):
                    if self.tree.item(subchild, "text") == topic:
                        self.tree.selection_set(subchild)
                        self.tree.focus(subchild)
                        break
                break
    
    def show_quick_tip(self, message):
        tip_window = tk.Toplevel(self.parent)
        tip_window.title("Quick Tip")
        tip_window.geometry("400x200")
        tip_window.transient(self.parent)
        tip_window.grab_set()
        
        ttk.Label(tip_window, text=message, wraplength=380, justify=tk.LEFT).pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        ttk.Button(tip_window, text="Got it", command=tip_window.destroy).pack(pady=10)

help_system = HelpSystem(None)