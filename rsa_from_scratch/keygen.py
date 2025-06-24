"""RSA Key Generation"""
import random
from math import gcd

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
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
    """Generate a prime number of 'bits' length"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Ensure MSB and LSB are set
        if is_prime(p):
            return p

def generate_keypair(bits=512):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = pow(e, -1, phi)
    return (e, n), (d, n)
