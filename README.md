# Encryption_project

# 🔐 Multi-Algorithm Encryption CLI

This project is a simple command-line tool to demonstrate symmetric and asymmetric encryption using **AES**, **DES**, and **RSA** algorithms in Python.

## 📦 Features

- 🔑 AES encryption & decryption with 128-bit keys
- 🧱 DES encryption & decryption with 64-bit keys
- 🛡️ RSA encryption & decryption with automatic key generation (2048 bits)
- 🔁 Encrypt and decrypt input from the user
- 💾 Automatically saves and loads RSA keys (`.pem` files)

## 🗂️ File Structure

```
├── main.py                # Main script to run encryption/decryption
├── encryption.py          # Encryption/decryption logic (AES, DES, RSA)
├── rsa_key_management.py  # RSA key generation, saving, and loading
├── private.pem            # RSA private key (auto-generated)
├── public.pem             # RSA public key (auto-generated)
```

## 🚀 Getting Started

### Prerequisites

- Python 3.6+
- `pycryptodome` library

Install it via pip:

```bash
pip install pycryptodome
```

### Running the Program

```bash
python main.py
```

Follow the prompts to encrypt and decrypt your text using AES, DES, and RSA.

## 📄 Example Output

```bash
Enter the text to encrypt: HelloWorld

AES Ciphertext: <ciphertext>
DES Ciphertext: <ciphertext>
RSA Ciphertext: <ciphertext>

Decrypting...
AES Decrypted: HelloWorld
DES Decrypted: HelloWorld
RSA Decrypted: HelloWorld
```

## 📌 Notes

- Keys are generated using secure random values (`get_random_bytes`).
- RSA keys are stored in `private.pem` and `public.pem` in the working directory.
- RSA encryption is performed on strings directly (limited by key size).

## 🛠️ License

This project is open-source and free to use under the [MIT License](LICENSE).

---

Let me know if you’d like a version with GitHub badges, contribution guidelines, or setup instructions for packaging it as a module.
