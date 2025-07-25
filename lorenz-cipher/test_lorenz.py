from lorenz import LorenzMachine, str_to_bits

def test_encrypt_decrypt():
    msg = "HELLO LORENZ"
    bits = str_to_bits(msg)
    lorenz = LorenzMachine(len(bits), seed=42)
    cipher = lorenz.encrypt(msg)
    lorenz = LorenzMachine(len(cipher), seed=42)
    plain = lorenz.decrypt(cipher)
    assert plain == msg
    print("✅ Test passed")

def test_empty():
    msg = ""
    bits = str_to_bits(msg)
    lorenz = LorenzMachine(len(bits), seed=42)
    cipher = lorenz.encrypt(msg)
    lorenz = LorenzMachine(len(cipher), seed=42)
    plain = lorenz.decrypt(cipher)
    assert plain == msg
    print("✅ Empty string test passed")

if __name__ == "__main__":
    test_encrypt_decrypt()
    test_empty()
