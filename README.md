# Cryptography Portfolio

Welcome to my **Cryptography Portfolio** — a curated collection of cryptographic projects, educational implementations, and secure systems designed to demonstrate deep technical understanding of cryptographic principles, algorithms, and security protocols.

> This repository is part of a larger security portfolio and is continuously updated as new modules are completed.

---

## Purpose

This portfolio serves as both a **learning tool** and a **showcase** of applied cryptography. Each module is built from the ground up using Python, focusing on clarity, correctness, and educational value. While not intended for production use, each project reinforces concepts vital to modern cryptography.

---

## Completed Modules

### [`rsa_from_scratch`](./rsa_from_scratch)
A full RSA implementation written in pure Python, featuring:
- Prime generation using the Miller-Rabin test
- RSA keypair creation (default: 2048-bit)
- PKCS#1 v1.5 padding for improved security
- Block-based encryption and decryption
- CLI support for user input and file encryption
- Fully documented and unit tested  
[Explore RSA →](./rsa_from_scratch)

---

### [`aes_simulator`](./aes_simulator)
A detailed simulator for AES-128, built step-by-step with:
- SubBytes, ShiftRows, MixColumns, AddRoundKey
- Key expansion and full round logic
- Educational focus with visualization and debug output  
[Explore AES Simulator →](./aes_simulator)

---

### [`aes_cbc_encryptor`](./symmetric_aes/aes_cbc_encryptor)
A secure AES-256 encryption GUI with file support:
- AES-256 in CBC mode with PKCS#7 padding
- HMAC-SHA256 authentication (Encrypt-then-MAC)
- File encryption with streamed chunking support
- GUI (Tkinter) with dark mode, password validation, password visibility toggle
- CLI fallback for quick encryption/decryption  
[Explore AES-CBC GUI →](./symmetric_aes/aes_cbc_encryptor)

---

---

### [`lorenz_cipher`](./lorenz_cipher)
A historically accurate simulator of the WWII-era **Lorenz SZ42 cipher machine**, featuring:
- χ (chi), ψ (psi), and μ (mu) wheels with correct wheel lengths
- XOR-based stream cipher logic with parity-based keystream bits
- CLI for message encryption/decryption with reproducible seeds
- Wheel configuration save/load system (JSON) to simulate key sheets
- Informational report included: cryptanalysis history, Colossus, and modern relevance  
[Explore Lorenz Cipher →](./lorenz_cipher)


## Upcoming Modules

| Module                      | Description                                      | Status     |
|-----------------------------|--------------------------------------------------|------------|
| `password_hashing_benchmarks` | Compare Argon2, bcrypt, PBKDF2                   | 🔜 Planned |
| `crypta_msg_protocol`       | Design a secure custom messaging protocol        | 🔜 Planned |
| `pqc_playground`            | Play with post-quantum schemes (Kyber, NTRU, etc.) | 🔜 Planned |
| `math_theory_demos`         | ECC, Finite Fields, Lattices, Number Theory      | 🔜 Planned |

---

## Why Build from Scratch?

- Reinforce cryptographic math (modular arithmetic, number theory)
- Demystify black-box libraries by rebuilding core primitives
- Security certifications like **ECES**, **OSCE3**
- Showcase technical depth to potential employers

---

## License

This repository is licensed under the [MIT License](./rsa_from_scratch/LICENSE). Feel free to use and modify the code with proper attribution.

---

## Contact

Feel free to connect via [LinkedIn](https://www.linkedin.com/in/robert-gravelle-27a10a6a/) or check out the full [Security Projects Index](https://github.com/Rob-Gravelle).

---

Stay tuned — more cryptographic modules coming soon...
