markdown
Copy
Edit
# RSA From Scratch

This project implements RSA public-key cryptography from the ground up using Python, designed for educational purposes to demonstrate the core mechanics of RSA encryption, decryption, and key generation.

---

##  Features

- **Miller-Rabin Primality Test**: Efficiently generates large prime numbers using a probabilistic algorithm.
- **Key Generation**: Creates RSA public and private keypairs with a default 512-bit key size.
- **Encryption/Decryption**: Implements textbook RSA for encrypting and decrypting messages.
- **Demo Script**: Includes a simple script to showcase the full RSA workflow.

---

##  Installation

1. Clone the repository:
   ```bash
   git clone <github address when complete>

## Navigate to the project directory:

bash
Copy
Edit
cd rsa-from-scratch

## Ensure Python 3.6+ is installed.
No external libraries are required (uses only the Python standard library).

## Usage
Run the demo script to see RSA in action:

bash
Copy
Edit
python encrypt_decrypt.py
This will:

Generate a 512-bit RSA keypair

Encrypt a sample message ("Hello RSA!")

Decrypt and print the original message

To use a custom message, simply modify the message variable inside encrypt_decrypt.py.

## Files
keygen.py: Implements prime number generation using Miller-Rabin and RSA keypair generation.

rsa.py: Contains encryption and decryption logic for RSA.

encrypt_decrypt.py: Demonstrates the RSA workflow with a sample message.

## Design Choices
Miller-Rabin Primality Test: Chosen for its efficiency in generating large primes, with 5 iterations for a low false-positive probability (< 4⁻⁵).

Public Exponent: Uses e = 65537, a standard choice for balancing security and performance.

Key Size: Defaults to 512 bits for demonstration, but can be adjusted in keygen.py.

## Security Notes
This is an educational implementation of textbook RSA and should not be used in production. Limitations include:

 No Padding: Lacks secure padding schemes like OAEP, making it vulnerable to chosen-ciphertext attacks.

 Character-by-Character Encryption: Encrypts each character individually, which is inefficient and leaks plaintext structure.

 Small Key Size: 512-bit keys are insecure by modern standards. Use 2048+ bits in real-world applications.

