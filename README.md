# 🛡️ CXA Cryptographic System

> **Advanced, OpSec-conscious cryptographic toolkit for data protection, steganography, and secure key management.**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-green)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/OpSec-Security-red)](docs/security.md)
[![Build Status](https://github.com/XvoidcrewX/CXA0/actions/workflows/build-linux.yml/badge.svg)](https://github.com/XvoidcrewX/CXA/actions/runs/19082993655)
[![Build Status](https://github.com/XvoidcrewX/CXA0/actions/workflows/build-macos.yml/badge.svg)](https://github.com/XvoidcrewX/CXA/actions/runs/19083091137)
[![Build Status](https://github.com/XvoidcrewX/CXA0/actions/workflows/build-windows.yml/badge.svg)](https://github.com/XvoidcrewX/CXA/actions/runs/19083391266)
[![CXA BANNER](https://img.shields.io/badge/BANNER-PINK.svg)](docs/announcement.md)

---

Don't forget to read this because it will probably completely change your mind about the project:
[BANNER OF PROJECT](https://github.com/XvoidcrewX/CXA0/blob/main/docs/announcement.md)

---

## 🔐 Overview

CXA is a **zero-trust**, **audit-ready** cryptographic application designed for users who demand **maximum confidentiality** and **operational security**. It integrates awesome-grade encryption, steganography, digital signatures, and tamper-resistant key management — all within a secure-by-default architecture.

> ⚠️ **No telemetry. No auto-updates. No cloud dependencies.**  
> You control everything. Always.

---

## ✨ Key Features

### 🔒 **Advanced Encryption**
- **AES-GCM**: Authenticated symmetric encryption (NIST SP 800-38D)
- **ChaCha20-Poly1305**: Fast, modern stream cipher (RFC 7539)
- **RSA-OAEP**: Secure asymmetric encryption (2048–4096 bit) (PKCS#1 v2.2)

### 🖼️ **Steganography**
- Hide data in **images** (PNG/JPG) or **text** using **LSB**
- Optional **AES encryption** of hidden payload
- **Error correction** (Reed-Solomon) + **Zstandard compression**
- Embedding metadata map for reliable extraction

### 📝 **Digital Signatures**
- **RSA-PSS** & **Ed25519** for message authenticity (FIPS 186-4)
- Tamper-proof verification with SHA-256/512 hashing
- Base64-encoded signature output for transport

### 🔑 **Secure Key Management**
- Encrypted keystore with **PBKDF2 + AES-GCM**
- Automatic **key rotation** & **expiry policies**
- **Ultra-Resistance Mode** (4096-bit RSA, 256-bit AES, 1M KDF iterations)
- Password-protected key export with encryption

### 🛡️ **Defense-in-Depth Protections**
- **Secure memory wiping** (3-pass overwrite + `memset`)
- **Anti-tamper integrity checks** (HMAC-SHA256)
- **Encrypted backups** (password-protected ZIP + AES)
- **Comprehensive audit logging** (redacted, append-only)

---

## 💭 Philosophy

CXA isn’t just about encryption — it’s about ownership.  
In an age where every click is monitored, true privacy means taking back control of your data, your tools, and your choices.  
CXA was built for that — not for profit, not for hype, but for those who refuse to surrender autonomy.

---

## 📋 Table of Contents
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Usage](#usage)
- [Security & OpSec](#-security--opsec)
- [Building from Source](#-building-from-source)
- [Donate](#donate--support-future-development--keep-cxa-evolving-)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## 💻 System Requirements

| Component       | Minimum                     |
|-----------------|-----------------------------|
| **OS**          | Windows 10/11, Linux, macOS |
| **Python**      | 3.10+                        |

> 💡 **Note**: Python must be installed with Tkinter support for GUI interface

---

## 🚀 Installation
### 🧪 Method: From Source
```bash
https://github.com/XvoidcrewX/CXA.git
cd CXA
python -m venv venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

🔒 Never run unverified code. Always inspect sources.

---

## 🖥️ Usage

| Tab             | Functionality                                      |
|-----------------|----------------------------------------------------|
| Dashboard       | Real-time stats, key status, memory usage          |
| Cryptography    | Encrypt/decrypt with AES, ChaCha20, or RSA         |
| Steganography   | Embed/extract hidden data in images or text        |
| Key Management  | Generate, rotate, export, or securely destroy keys |
| Signatures      | Sign messages or verify authenticity               |
| Settings        | Toggle Ultra Mode, audit logging, memory protection|

🧩 **Pro Tip**: Use ULTRA security level only when necessary — it impacts performance.

---

## 🔐 Security & OpSec

### 🛑 Critical Policies
- ❌ NO automatic updates  
- ❌ NO internet connectivity  
- ✅ Manual verification required for all files  
- ✅ All logs redact secrets (keys, passwords, tokens)

### ⚠️ Memory Security Notice
> This application uses Python, which cannot guarantee complete memory erasure due to garbage collection and memory management limitations.  
> While `SecureMemoryManager` attempts to encrypt and overwrite sensitive buffers, **residual data may persist in RAM or swap files**.  
> For high-risk environments, consider:  
> - Running on a live OS with no swap  
> - Using hardware security modules (HSMs)  
> - Avoiding virtualized environments  
> This tool enhances operational security but **does not replace physical or hardware-level protections**.

### 📜 Best Practices
- Rotate keys every 30–365 days (configurable)
- Backup keys offline (encrypted USB)
- Wipe memory after sensitive operations (built-in)
- Verify file integrity using `anti_tamper.py`

> 🕵️ Remember: The strongest crypto is useless without strong OpSec.

---

## 🔨 Building from Source

**Windows**
```cmd
build.bat
```

**Linux**
```bash
chmod +x build_linux.sh
./build_linux.sh
```

**macOS**
```bash
chmod +x build-macos.sh
./build-macos.sh
```

📦 Outputs go to `dist/`. Icons and assets are bundled automatically.

---

## Donate 🧠&❤️ Support Future Development — Keep CXA Evolving 🔐

CXA is built to grow stronger each year, with continuous upgrades in cryptography, security, and OpSec tooling — without sponsors or corporate backing.
Your support ensures that future releases stay open-source, independent, and technically advanced.

BITCOIN:
```bash
bc1qk7hp6vxa5sd00sw3ma7la0cj7fdpkflvjrwq9g
```



MONERO:
```bash
42uEgsLYHHgXwDdcs991anU12CZpS9m2dCAgtqw1MR9T4Hjs3CReQnJar8x1D1LjUAaWP5hAH77j9bXX3nJUxbXaE6GGvqD
```

☕ Buy me a coffee... or a cold beer 🍺 — every sip funds the next evolution.


---

## 🤝 Contributing

All PRs undergo manual security review.  
Please follow the project’s OpSec principles: no telemetry, no convenience-over-control compromises.

---

## 📄 License

Distributed under the MIT License.  
See [LICENSE](LICENSE) for details.

⚖️ **No warranty. Use at your own risk.**

---

## 🆘 Support

- 🐞 **Bugs**: Open an Issue  
- 💬 **Questions**: Discussions  
- 🚨 **Security Vulnerabilities**: DO NOT POST PUBLICLY  
  → Contact via secure,(PGP preferred) in [contacts.md](https://github.com/XvoidcrewX/CXA/blob/main/author%26contact/contacts.md)

---

🔐 Built for those who operate in the shadows — and prefer to stay there.  
Version: 1.0.0 | Last Updated: 2025-11-04

---

🗓️ Annual roadmap updates: each new version drops every year — powered by community support.
