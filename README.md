# Nivora

**Secure, portable and open-source key vault for structured secrets.**  
Nivora stores encrypted SQLite databases in a custom ASN.1-structured binary format – hardened with Argon2 and file-path-based key derivation.

![License](https://img.shields.io/github/license/frequency403/nivora)
![Platform](https://img.shields.io/badge/platform-.NET-blueviolet)
![Status](https://img.shields.io/badge/status-early%20alpha-orange)

---

## 🔐 What is Nivora?

Nivora is a lightweight, cross-platform CLI & GUI application for encrypted data storage and secure vault serialization.

> Think of it as a zero-trust, file-based secret container – built with performance and cryptographic hygiene in mind.

---

## 🧱 Features

- 🔒 **Encryption** using:
    - Argon2id-based key derivation
    - AES-256 in GCM mode
- 📦 **Portable**: Single file = fully contained vault
- 🛠️ Built with **.NET Core 9.0**

---

## 📁 File Format Overview

The encrypted vault file has the following layout:

```
[ MagicNumber ]
[ Version ]
[ Argon2_Params_1 ]
[ Argon2_Params_2 ]
[ Argon2_Params_3 ]
[ Encrypted_SQLite_Database ]
→ Final structure is encrypted with a key derived from file path
```

---

## 🚀 Getting Started

> ⚠️ Nivora is in active development – You cannot use it right now.

---

## 📦 Planned Subprojects

- `nivora-cli` – Command-line utility for vault management
- `nivora-gui` – Cross-platform UI (WPF or Avalonia)
- `nivora-agent` – Background agent for secrets injection

---

## 📄 License

MIT License — see [`LICENSE`](./LICENSE) for details.  
Open to contributions, forks, and feedback!

---

## 💬 Community

- 💡 Issues & ideas → [GitHub Issues](https://github.com/frequency403/nivora/issues)
- 🛠️ Contributing → [CONTRIBUTING.md](CONTRIBUTING.md) _(coming soon)_

---

## ✨ Acknowledgements

- [BouncyCastle](https://www.bouncycastle.org/csharp/) – cryptographic primitives
- [sqlcipher](https://www.zetetic.net/sqlcipher/) – optional SQLite encryption backend

---

> _Secure by design. Portable by default. Built with care._ 🛡️
