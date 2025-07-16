# AES-256 Encryption GUI

A dark-themed Python GUI app for encrypting and decrypting text and files using AES-256 in CBC mode with HMAC authentication.

## Features
- AES-256 CBC mode with secure PKCS7 padding
- HMAC-SHA256 for integrity/authentication
- Encrypted output in Base64
- Secure file encryption with optional secure deletion
- Password strength validation (12+ chars, mixed case, digits)
- Show/hide password toggle
- Dark mode styling
- GUI built with Tkinter

## Requirements
- Python 3.8+
- Install dependencies:
  ```bash
  pip install pycryptodome
  ```

## Usage
```bash
python aes_gui.py
```

## Security Disclaimer
This software is provided for educational and demonstration purposes. While it uses secure cryptographic practices (AES-256-CBC, PBKDF2, HMAC-SHA256), users are responsible for proper use, including strong password selection and secure key management. The author is not liable for any data loss or security breach resulting from use or misuse.

## Export Control
This software includes cryptographic functionality and may be subject to export control regulations in certain jurisdictions. Users are responsible for complying with local and international laws.

## Dependencies
- [PyCryptodome](https://www.pycryptodome.org/) (BSD License): Used for AES encryption, PBKDF2 key derivation, and HMAC.

## Contributions
Contributions are welcome! Please audit cryptographic logic for correctness and submit issues or pull requests to improve security, performance, or usability.
