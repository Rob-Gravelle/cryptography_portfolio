#!/usr/bin/env python3
"""
RSA key generation module implementing prime number generation and keypair creation.
Uses the Miller-Rabin primality test for efficient prime generation.
Supports PKCS#1 v1.5 padding in rsa.py for educational purposes.
Note: For educational purposes only, not suitable for production use.
"""
import random
from math import gcd


def is_prime(n, k=40):
    """
    Miller-Rabin primality test to determine if n is prime.
    Args:
        n: Integer to test for primality.
        k: Number of iterations (default: 40, suitable for 2048-bit keys).
    Returns:
        bool: True if n is likely prime, False otherwise.
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """
    Generate a prime number of specified bit length.
    Args:
        bits: Desired bit length of the prime (e.g., 1024 for a 2048-bit keypair).
    Returns:
        int: A prime number of approximately 'bits' length.
    Raises:
        ValueError: If bits is too small (< 8).
    """
    if bits < 8:
        raise ValueError("Bit length must be at least 8")

    min_val = 1 << (bits - 1)
    max_val = (1 << bits) - 1

    while True:
        p = random.randrange(min_val, max_val) | 1
        if is_prime(p):
            return p


def generate_keypair(bits=2048):
    """
    Generate an RSA public and private keypair.
    Args:
        bits: Total bit length of the modulus n (default: 2048).
              Each prime (p, q) is approximately bits/2 bits.
    Returns:
        tuple: ((e, n), (d, n)) where (e, n) is the public key and (d, n) is the private key.
    Raises:
        ValueError: If bits is invalid or key generation fails.
    """
    if bits < 256 or bits % 2 != 0:
        raise ValueError("Bit length must be even and at least 256")

    half_bits = bits // 2

    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        raise ValueError("Public exponent e=65537 is not coprime with phi; try again")

    try:
        d = pow(e, -1, phi)
    except ValueError:
        raise ValueError("Failed to compute private exponent; try again")

    return (e, n), (d, n)


if __name__ == "__main__":
    try:
        pub_key, priv_key = generate_keypair(2048)
        print(f"Public Key: (e={pub_key[0]}, n={pub_key[1]})")
        print(f"Private Key: (d={priv_key[0]}, n={priv_key[1]})")
    except ValueError as e:
        print(f"Error: {e}")