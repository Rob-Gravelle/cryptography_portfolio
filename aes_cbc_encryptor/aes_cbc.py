from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import os


BLOCK_SIZE = AES.block_size
KEY_SIZE = 32  # AES-256 = 32 bytes

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    if pad_len > BLOCK_SIZE or pad_len == 0:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def derive_keys(password: str, salt: bytes, iterations: int = 100000) -> tuple:
    full_key = PBKDF2(password, salt, dkLen=64, count=iterations, hmac_hash_module=SHA256)
    return full_key[:32], full_key[32:]  # (AES_key, HMAC_key)


def encrypt_file(in_filename: str, out_filename: str, password: str):
    salt = get_random_bytes(16)
    aes_key, hmac_key = derive_keys(password, salt)
    iv = get_random_bytes(BLOCK_SIZE)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(in_filename, 'rb') as f:
        plaintext = f.read()
    padded = pad(plaintext)
    ciphertext = cipher.encrypt(padded)

    # Compute HMAC
    data_to_auth = salt + iv + ciphertext
    mac = HMAC.new(hmac_key, data_to_auth, SHA256).digest()

    with open(out_filename, 'wb') as f:
        f.write(data_to_auth + mac)


def decrypt_file(in_filename: str, out_filename: str, password: str):
    with open(in_filename, 'rb') as f:
        file_data = f.read()

    if len(file_data) < 48:  # salt + iv + HMAC
        raise ValueError("Invalid file format.")

    salt = file_data[:16]
    iv = file_data[16:32]
    mac = file_data[-32:]
    ciphertext = file_data[32:-32]

    aes_key, hmac_key = derive_keys(password, salt)

    # Verify HMAC
    data_to_auth = salt + iv + ciphertext
    expected_mac = HMAC.new(hmac_key, data_to_auth, SHA256).digest()
    if not HMAC.compare_digest(mac, expected_mac):
        raise ValueError("Invalid MAC – file may have been tampered with.")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded)

    with open(out_filename, 'wb') as f:
        f.write(plaintext)

