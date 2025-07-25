#  Lorenz Cipher Simulator (WWII SZ-42)

This project simulates the Lorenz SZ-42 cipher machine used by the German High Command during World War II. It reproduces the wheel-based stream cipher logic using Python with χ (chi), ψ (psi), and μ (mu) wheels — including realistic stepping behavior.

---

##  Historical Context

The Lorenz cipher was more advanced than the Enigma machine, using 12 wheels with irregular stepping to encrypt messages via binary stream cipher logic. It was used for the highest-level communications and famously broken at Bletchley Park.

---

##  Features

-  Full χ, ψ, μ wheel simulation with authentic wheel lengths
-  Irregular stepping using μ wheels (realistic to SZ-42 machine)
-  Bitwise XOR stream cipher logic
-  Command-line interface for encryption & decryption
-  Built-in test suite for reliability
-  Sample plaintext and output files included

---

##  Usage

###  CLI Example

```bash
# Encrypt a message directly
python cli.py --mode encrypt --message "HELLO LORENZ" --seed 1234

# Decrypt binary string
python cli.py --mode decrypt --message "011001..." --seed 1234

# Encrypt a text file
python cli.py --mode encrypt --input-file example.txt --output-file example_encrypted.txt --seed 1234
```

>  Use the same seed for decryption to reproduce the keystream.

---

##  Tests

```bash
python test_lorenz.py
```

---

## 🛠 Project Structure

```
lorenz_cipher/
├── lorenz.py              # Main LorenzMachine class
├── cli.py                 # CLI interface using argparse
├── test_lorenz.py         # Unit tests
├── wheel_config.py        # (Optional) Save/load wheel state
├── README.md              # This file
├── example.txt            # Sample plaintext
├── example_encrypted.txt  # Encrypted result
└── requirements.txt       # Minimal dependencies (Python stdlib only)
```

---

##  Technical Notes

- Each wheel is initialized with a fixed seed using `random.seed()`
- Keystream generation is done bit-by-bit using XOR of χ and ψ wheels
- μ1 controls irregular stepping of the ψ wheels (true to historical model)

---

##  Example Output

```plaintext
Encrypted Bits (binary):
000101110111...

Encrypted Bits (hex):
0x2ee93a...

Decrypted Message:
HELLO LORENZ
```

---

##  License

MIT License — Free for academic, educational, and personal use.

---

##  Acknowledgments

Inspired by the work at Bletchley Park, Alan Turing, and Bill Tutte’s pioneering efforts in cryptanalysis.
