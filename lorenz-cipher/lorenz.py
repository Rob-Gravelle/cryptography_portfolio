import random

# === Bit Utilities ===
def str_to_bits(text):
    """Convert a string to a binary string (8 bits per character)."""
    if not all(ord(c) < 128 for c in text):
        raise ValueError("Input must be ASCII characters")
    return ''.join(f"{ord(c):08b}" for c in text)

def bits_to_str(bits):
    """Convert a binary string to a text string."""
    if not all(b in '01' for b in bits):
        raise ValueError("Binary string must contain only 0s and 1s")
    if len(bits) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

def xor_bits(a, b):
    """Perform XOR on two binary strings."""
    if len(a) != len(b):
        raise ValueError("Binary strings must have equal length")
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

# === Wheel Class ===
class Wheel:
    """Simulates a single wheel in the Lorenz cipher with a fixed bit sequence."""
    def __init__(self, length, seed):
        """Initialize wheel with given length and random seed.
        
        Args:
            length (int): Number of bits in the wheel.
            seed (int): Seed for random bit generation.
        """
        random.seed(seed)  # For cryptographic security, consider secrets.randbits
        self.bits = [random.randint(0, 1) for _ in range(length)]
        self.position = 0

    def step(self):
        """Advance the wheel's position by one, wrapping around."""
        self.position = (self.position + 1) % len(self.bits)

    def current(self):
        """Return the current bit of the wheel."""
        return self.bits[self.position]

# === Lorenz Cipher with χ, ψ, μ Wheels ===
class LorenzMachine:
    """Simulates the Lorenz SZ42 cipher machine with χ, ψ, and μ wheels."""
    def __init__(self, message_length, seed=42):
        """Initialize the Lorenz machine with historical wheel lengths.
        
        Args:
            message_length (int): Length of the message in bits.
            seed (int): Seed for wheel initialization.
        """
        self.message_length = message_length
        # Historical SZ42 wheel lengths
        chi_lengths = [41, 31, 29, 26, 23]
        psi_lengths = [43, 47, 51, 53, 59]
        mu_lengths = [61, 37]

        # Initialize wheels
        self.chi_wheels = [Wheel(length=l, seed=seed + i) for i, l in enumerate(chi_lengths)]
        self.psi_wheels = [Wheel(length=l, seed=seed + 100 + i) for i, l in enumerate(psi_lengths)]
        self.mu_wheels = [Wheel(length=l, seed=seed + 200 + i) for i, l in enumerate(mu_lengths)]

    def generate_keystream(self):
        """Generate a keystream of length message_length.
        
        Returns:
            str: Binary string representing the keystream.
        """
        keystream = ""

        for _ in range(self.message_length):
            # Step μ wheels
            mu1_bit = self.mu_wheels[0].current()
            for mu in self.mu_wheels:
                mu.step()

            # Step χ wheels
            for chi in self.chi_wheels:
                chi.step()

            # Step ψ wheels only if μ1 == 1
            if mu1_bit == 1:
                for psi in self.psi_wheels:
                    psi.step()

            # Get χ and ψ contributions
            chi_bits = [w.current() for w in self.chi_wheels]
            psi_bits = [w.current() for w in self.psi_wheels] if mu1_bit == 1 else [0] * 5

            # Combine χ and ψ with XOR (historical approach)
            combined = [c ^ p for c, p in zip(chi_bits, psi_bits)]
            # Collapse to 1 bit (using parity for simplicity, could use single bit)
            keystream_bit = sum(combined) % 2
            keystream += str(keystream_bit)

        return keystream

    def encrypt(self, plaintext):
        """Encrypt a plaintext string.
        
        Args:
            plaintext (str): The message to encrypt.
            
        Returns:
            str: Binary string of the ciphertext.
        """
        bits = str_to_bits(plaintext)
        self.message_length = len(bits)
        keystream = self.generate_keystream()
        return xor_bits(bits, keystream)

    def decrypt(self, cipher_bits):
        """Decrypt a binary ciphertext string.
        
        Args:
            cipher_bits (str): Binary string to decrypt.
            
        Returns:
            str: Decrypted plaintext.
        """
        if not all(b in '01' for b in cipher_bits):
            raise ValueError("Ciphertext must be binary")
        if len(cipher_bits) % 8 != 0:
            raise ValueError("Ciphertext length must be a multiple of 8")
        self.message_length = len(cipher_bits)
        keystream = self.generate_keystream()
        return bits_to_str(xor_bits(cipher_bits, keystream))

# === Test Cases ===
def run_tests():
    """Run basic tests for the Lorenz cipher."""
    # Test 1: Basic encryption/decryption
    message = "LORENZ CIPHER"
    bit_length = len(str_to_bits(message))
    lorenz = LorenzMachine(message_length=bit_length, seed=1234)
    encrypted = lorenz.encrypt(message)
    lorenz = LorenzMachine(message_length=len(encrypted), seed=1234)
    decrypted = lorenz.decrypt(encrypted)
    assert decrypted == message, f"Expected {message}, got {decrypted}"
    
    # Test 2: Empty string
    message = ""
    bit_length = len(str_to_bits(message))
    lorenz = LorenzMachine(message_length=bit_length, seed=1234)
    encrypted = lorenz.encrypt(message)
    lorenz = LorenzMachine(message_length=len(encrypted), seed=1234)
    decrypted = lorenz.decrypt(encrypted)
    assert decrypted == message, f"Expected {message}, got {decrypted}"
    
    print("All tests passed!")

# === Example Run ===
if __name__ == "__main__":
    # Run tests
    run_tests()
    
    # Example encryption/decryption
    message = "LORENZ CIPHER"
    bit_length = len(str_to_bits(message))

    # Encryption
    lorenz = LorenzMachine(message_length=bit_length, seed=1234)
    encrypted = lorenz.encrypt(message)
    print("Encrypted Bits (binary):", encrypted)
    print("Encrypted Bits (hex):", hex(int(encrypted, 2)))

    # Decryption
    lorenz = LorenzMachine(message_length=len(encrypted), seed=1234)
    decrypted = lorenz.decrypt(encrypted)
    print("Decrypted Message:", decrypted)# Main Lorenz cipher logic will go here
