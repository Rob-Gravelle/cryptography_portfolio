#!/usr/bin/env python3
"""
RSA encryption and decryption module.
Implements textbook RSA with block-based encryption and PKCS#1 v1.5 padding for educational purposes.
Note: Suitable for learning but not production due to limited side-channel protections.
"""
import sys
import random


def pad_pkcs1_v15(message_bytes, block_size):
    """
    Apply PKCS#1 v1.5 padding to the message.
    
    Args:
        message_bytes (bytes): The message to pad.
        block_size (int): The key size in bytes (e.g., 256 for 2048-bit key).
    
    Returns:
        bytes: Padded message.
    
    Raises:
        ValueError: If the message is too long for padding.
    """
    if len(message_bytes) > block_size - 11:  # 11 bytes for padding overhead
        raise ValueError("Message too long for PKCS#1 v1.5 padding")
    padding_length = block_size - len(message_bytes) - 3
    padding = bytes([random.randint(1, 255) for _ in range(padding_length)])  # Non-zero random bytes
    return b'\x00\x02' + padding + b'\x00' + message_bytes


def unpad_pkcs1_v15(padded_bytes, block_size):
    """
    Remove PKCS#1 v1.5 padding from the message.
    
    Args:
        padded_bytes (bytes): The padded message.
        block_size (int): The key size in bytes.
    
    Returns:
        bytes: Unpadded message.
    
    Raises:
        ValueError: If the padding is invalid.
    """
    if len(padded_bytes) != block_size or padded_bytes[:2] != b'\x00\x02':
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    separator_index = padded_bytes.find(b'\x00', 2)
    if separator_index < 10:  # At least 8 bytes of random padding
        raise ValueError("Invalid PKCS#1 v1.5 padding: no separator or insufficient padding")
    return padded_bytes[separator_index + 1:]


def encrypt(plaintext, public_key):
    """
    Encrypt a plaintext string using RSA public key with PKCS#1 v1.5 padding.
    Converts the message to a single number using UTF-8 encoding.
    
    Args:
        plaintext (str): The message to encrypt (up to ~245 bytes for 2048-bit keys with padding).
        public_key (tuple): (e, n) where e is the public exponent and n is the modulus.
    
    Returns:
        str: The ciphertext as a hexadecimal string.
    
    Raises:
        ValueError: If the plaintext is empty, too large, or contains non-encodable characters.
        TypeError: If the public key is invalid.
    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty")

    # Validate public key
    try:
        e, n = public_key
        if not (isinstance(e, int) and isinstance(n, int) and e > 0 and n > 0):
            raise TypeError("Public key must contain positive integers (e, n)")
    except (TypeError, ValueError):
        raise TypeError("Invalid public key format; expected tuple (e, n)")

    # Convert plaintext to bytes
    try:
        plaintext_bytes = plaintext.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError("Plaintext contains non-encodable characters")

    # Apply PKCS#1 v1.5 padding
    block_size = (n.bit_length() + 7) // 8
    try:
        padded_bytes = pad_pkcs1_v15(plaintext_bytes, block_size)
    except ValueError as e:
        raise ValueError(f"Padding error: {e}")

    # Convert padded bytes to number
    plaintext_num = int.from_bytes(padded_bytes, 'big')

    # Ensure plaintext number is less than modulus n
    if plaintext_num >= n:
        raise ValueError(f"Padded plaintext too large for {n.bit_length()}-bit key")

    # Encrypt: c = m^e mod n
    try:
        ciphertext = pow(plaintext_num, e, n)
    except ValueError:
        raise ValueError("Encryption failed; invalid public key parameters")

    # Return ciphertext as hex
    return hex(ciphertext)[2:]  # Strip '0x' prefix


def decrypt(ciphertext, private_key):
    """
    Decrypt a ciphertext using RSA private key with PKCS#1 v1.5 padding.
    Converts the decrypted number back to a string using UTF-8 decoding.
    
    Args:
        ciphertext (str): The ciphertext as a hexadecimal string.
        private_key (tuple): (d, n) where d is the private exponent and n is the modulus.
    
    Returns:
        str: The decrypted plaintext.
    
    Raises:
        ValueError: If the ciphertext or private key is invalid, or decryption fails.
        TypeError: If the private key is invalid.
    """
    # Validate private key
    try:
        d, n = private_key
        if not (isinstance(d, int) and isinstance(n, int) and d > 0 and n > 0):
            raise TypeError("Private key must contain positive integers (d, n)")
    except (TypeError, ValueError):
        raise TypeError("Invalid private key format; expected tuple (d, n)")

    # Convert hex ciphertext to integer
    try:
        ciphertext_int = int(ciphertext, 16)
    except (TypeError, ValueError):
        raise ValueError("Invalid ciphertext: must be a valid hexadecimal string")

    # Validate ciphertext range
    if ciphertext_int < 0 or ciphertext_int >= n:
        raise ValueError("Invalid ciphertext: must be between 0 and n-1")

    # Decrypt: m = c^d mod n
    try:
        plaintext_num = pow(ciphertext_int, d, n)
    except ValueError:
        raise ValueError("Decryption failed; invalid private key or ciphertext")

    # Convert number to bytes
    block_size = (n.bit_length() + 7) // 8
    try:
        padded_bytes = plaintext_num.to_bytes(block_size, 'big')
        plaintext_bytes = unpad_pkcs1_v15(padded_bytes, block_size)
        plaintext = plaintext_bytes.decode('utf-8')
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Decryption or unpadding failed: {e}")

    return plaintext


if __name__ == "__main__":
    # Demo for testing (requires keygen.py)
    from keygen import generate_keypair
    
    try:
        message = "Cryptography Sample for RSA"
        pub_key, priv_key = generate_keypair(2048)
        print(f"Original message: {message}")
        encrypted = encrypt(message, pub_key)
        print(f"Encrypted (hex): {encrypted}")
        decrypted = decrypt(encrypted, priv_key)
        print(f"Decrypted: {decrypted}")
        assert decrypted == message, "Decryption failed"
        print("Success: Decrypted message matches original!")
    except (ValueError, TypeError) as e:
        print(f"Error: {e}")
        sys.exit(1)