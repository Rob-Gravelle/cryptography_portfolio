#!/usr/bin/env python3
"""
Unit tests for RSA implementation.
Verifies key generation, encryption, decryption, and edge cases.
Run with: python -m unittest tests.py
"""
import unittest
from keygen import generate_keypair
from rsa import encrypt, decrypt, pad_pkcs1_v15, unpad_pkcs1_v15


class TestRSA(unittest.TestCase):
    def setUp(self):
        """Set up a keypair for tests."""
        print("Setting up test environment...")
        self.bits = 512  # Small key for fast tests
        self.pub_key, self.priv_key = generate_keypair(self.bits)
        self.message = "Test message"
        print("Setup complete.")

    def test_key_generation(self):
        """Test that keypair is valid by checking encryption/decryption."""
        print("Running test_key_generation...")
        e, n = self.pub_key
        d, _ = self.priv_key
        # Verify keypair by encrypting/decrypting a small message
        test_message = "Key test"
        encrypted = encrypt(test_message, self.pub_key)
        decrypted = decrypt(encrypted, self.priv_key)
        self.assertEqual(decrypted, test_message, "Keypair invalid: encryption/decryption failed")
        self.assertTrue(isinstance(e, int) and e > 0, "Invalid public exponent")
        self.assertTrue(isinstance(n, int) and n > 0, "Invalid modulus")
        self.assertTrue(isinstance(d, int) and d > 0, "Invalid private exponent")

    def test_encryption_decryption(self):
        """Test that decryption recovers the original message."""
        print("Running test_encryption_decryption...")
        encrypted = encrypt(self.message, self.pub_key)
        decrypted = decrypt(encrypted, self.priv_key)
        self.assertEqual(decrypted, self.message, "Decryption failed")

    def test_empty_message(self):
        """Test that empty message raises ValueError."""
        print("Running test_empty_message...")
        with self.assertRaises(ValueError):
            encrypt("", self.pub_key)

    def test_oversized_message(self):
        """Test that oversized message raises ValueError."""
        print("Running test_oversized_message...")
        max_bytes = self.bits // 8 - 11  # Account for PKCS#1 v1.5 padding
        oversized_message = "a" * (max_bytes + 1)
        with self.assertRaises(ValueError):
            encrypt(oversized_message, self.pub_key)

    def test_invalid_ciphertext(self):
        """Test that invalid ciphertext raises ValueError."""
        print("Running test_invalid_ciphertext...")
        with self.assertRaises(ValueError):
            decrypt("invalid_hex", self.priv_key)  # Invalid hex string
        with self.assertRaises(ValueError):
            decrypt(hex(self.pub_key[1] + 1)[2:], self.priv_key)  # Ciphertext >= n

    def test_invalid_key(self):
        """Test that invalid keys raise TypeError or ValueError."""
        print("Running test_invalid_key...")
        with self.assertRaises(TypeError):
            encrypt(self.message, (0, -1))  # Invalid public key
        with self.assertRaises(TypeError):
            decrypt("0", (0, -1))  # Invalid private key

    def test_padding_unpadding(self):
        """Test that PKCS#1 v1.5 padding and unpadding work correctly."""
        print("Running test_padding_unpadding...")
        block_size = self.bits // 8
        padded = pad_pkcs1_v15(self.message.encode('utf-8'), block_size)
        unpadded = unpad_pkcs1_v15(padded, block_size)
        self.assertEqual(unpadded.decode('utf-8'), self.message)


if __name__ == "__main__":
    unittest.main()