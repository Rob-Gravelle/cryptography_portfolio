from lorenz import LorenzMachine, str_to_bits, bits_to_str
from wheel_config import save_wheel_config, load_wheel_config

# === Original message ===
message = "HELLO"
bits = str_to_bits(message)

# === Encrypt with saved wheel config ===
lorenz = LorenzMachine(len(bits), seed=1943)
save_wheel_config(lorenz, "key_1943_A.json")
print("Wheel configuration saved to 'key_1943_A.json'")

encrypted = lorenz.encrypt(message)
print("Encrypted:", encrypted)

# === Recreate machine with no seed, load wheel config ===
lorenz2 = LorenzMachine(len(bits), seed=0)
load_wheel_config(lorenz2, "key_1943_A.json")
print("Loaded wheel configuration from 'key_1943_A.json'")

decrypted = lorenz2.decrypt(encrypted)
print("Decrypted:", decrypted)
