# 🔐 Secure Chat – Post-Quantum E2EE Messaging System

A command-line secure messaging system built to withstand both classical and quantum cryptographic attacks. This project integrates hybrid cryptography to ensure **forward secrecy**, **message confidentiality**, **authentication**, and **integrity**, even in the presence of quantum-capable adversaries.

> ⚠️ Note: This is a CLI-based prototype, not yet a full-fledged GUI application.

---

## 🧠 Motivation

Current messaging apps (like Signal and WhatsApp) use Elliptic Curve Cryptography (ECC), which is secure for now but **vulnerable to quantum attacks**. This project addresses that risk by combining classical ECC with post-quantum cryptography to establish **quantum-resistant communication channels**.

---

## 🔐 Key Features

- **Hybrid Key Exchange**: Combines `ECDH` (classical) and `Kyber512` (post-quantum KEM) to derive a shared AES key.
- **End-to-End Encryption**: Uses `AES-256-GCM` and `HMAC-SHA256` for confidentiality and message integrity.
- **Authentication**: Implements `ECDSA` digital signatures to verify sender identity.
- **Forward Secrecy**: Past messages remain secure even if long-term keys are compromised.
- **Real-time Communication**: Built on `TCP socket` communication with secure encryption modules.

---

## 🛠 Technologies Used

- **Programming Language**: Python
- **Networking**: TCP Sockets
- **Cryptography**:
  - AES-256-GCM (Authenticated Encryption)
  - HMAC-SHA256 (Message Integrity)
  - ECDH (Elliptic Curve Diffie-Hellman)
  - Kyber512 (Post-Quantum KEM)
  - ECDSA (Digital Signatures)

---

## 📂 Project Structure

```
Secure_Chat/
├── client.py                 # CLI client interface
├── server.py                 # CLI server interface
├── generate_keys.py         # Generates ECDH/Kyber key pairs
├── key_exchange.py          # Hybrid key negotiation (ECDH + Kyber512)
├── message_encryption.py    # AES-GCM & HMAC message encryption
├── digital_signature.py     # ECDSA signing and verification
├── hmac_utils.py            # HMAC-SHA256 helper functions
├── key_management.py        # Key serialization and storage utilities
├── Oscar.py                 # (Test or demo script)
├── Oscar_Jr.py              # (Test or demo script)
├── private_keys/            # Stored private key files (should be ignored in repo)
├── verified_public_keys/    # Known trusted public keys
├── Report.pdf               # Project report containing design & contributions
```

---

## 📈 Future Improvements

- 🔐 Session Key Management
- 🗝️ Secure Local Private Key Storage
- 📜 Encrypted Chat History Logging
- 📱 GUI-Based Chat Application (Web/Desktop)

---

## 📘 References

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
- [Kyber KEM Medium Article](https://medium.com/@hwupathum/crystals-kyber-the-key-to-post-quantum-encryption-3154b305e7bd)
- [AES-GCM Explained](https://medium.com/@pierrephilip/aes256-gcm-key-rotation-in-c-2be80c03cac2)

---

## 🧑‍💻 Author

**Karthikeya Mittapalli**  
B.Tech CSE @ NIT Warangal  
[GitHub](https://github.com/Karthikeya-Mittapalli) · [LinkedIn](https://www.linkedin.com/in/mittapalli-karthikeya-04sf0405)

---

## 📄 License

MIT License
