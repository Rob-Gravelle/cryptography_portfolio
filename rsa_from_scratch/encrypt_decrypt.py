"""Test RSA Key Generation and Encryption/Decryption"""
from keygen import generate_keypair
from rsa import encrypt, decrypt

if __name__ == '__main__':
    pub_key, priv_key = generate_keypair(512)
    print("Public Key:", pub_key)
    print("Private Key:", priv_key)

    message = "Hello RSA!"
    encrypted = encrypt(message, pub_key)
    print("Encrypted:", encrypted)

    decrypted = decrypt(encrypted, priv_key)
    print("Decrypted:", decrypted)
