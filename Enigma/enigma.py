class EnigmaMachine:
    def __init__(self, rotors, reflector, ring_settings, initial_pos, plugboard_pairs):
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        # Correct historical wirings (V is now fixed)
        self.wiring = {
            'I':     'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
            'II':    'AJDKSIRUXBLHWTMCQGZNPYFVOE',
            'III':   'BDFHJLCPRTXVZNYEIWGAKMUSQO',
            'IV':    'ESOVPZJAYQUIRHXLNFTGKDCMWB',
            'V':     'VZBRGITYUPSDNHLXAWMJQOFCKE',  # FIXED - was wrong before
            'VI':    'JPGVOUMFYQBENHZRDKASXLICTW',
            'VII':   'NZJHGRCXMYSWBOUFAIVLPEKQDT',
            'VIII':  'FKQHTLXOCBJSPDZRAMEWNIUYGV',
            'Beta':  'LEYJVCNIXWPBQMDRTAKZGFUHOS',
            'Gamma': 'FSOKANUERHMBTIYCWLQPZXVGJD'
        }
        
        self.notches = {
            'I': 'Q',    'II': 'E',   'III': 'V',  'IV': 'J',   'V': 'Z',
            'VI': 'ZM',  'VII': 'ZM', 'VIII': 'ZM',
            'Beta': '',  'Gamma': ''
        }
        
        self.reflectors = {
            'B_Thin': 'ENKQAUYWJICOPBLMDXZVFTHRGS',
            'C_Thin': 'RDOBJNTKVEHMLFCWZAXGYIPSUQ'
        }

        if len(rotors) != 4:
            raise ValueError("M4 requires exactly 4 rotors")
        self.rotor_names = rotors  # [0]=Beta/Gamma (static), [1]=left, [2]=middle, [3]=right
        
        self.reflector = self.reflectors[reflector]
        
        self.ring_settings = [ord(c) - 65 for c in ring_settings.upper()]
        self.positions    = [ord(c) - 65 for c in initial_pos.upper()]

        if len(self.ring_settings) != 4 or len(self.positions) != 4:
            raise ValueError("Need exactly 4 ring settings and 4 starting positions")

        # Plugboard
        self.plugboard = {c: c for c in self.alphabet}
        for pair in plugboard_pairs:
            if len(pair) == 2:
                a, b = pair[0].upper(), pair[1].upper()
                if a in self.alphabet and b in self.alphabet and a != b:
                    self.plugboard[a] = b
                    self.plugboard[b] = a
        
        # Add this validation (prevents future typos)
        for name, wire in self.wiring.items():
            if len(wire) != 26 or sorted(wire) != list(self.alphabet):
                raise ValueError(f"Invalid wiring for rotor {name}: {wire!r} (must be unique A-Z permutation)")


    def _rotate(self):
        # Notch positions BEFORE any stepping
        right_letter  = self.alphabet[self.positions[3]]
        middle_letter = self.alphabet[self.positions[2]]

        notch_right  = self.notches[self.rotor_names[3]]
        notch_middle = self.notches[self.rotor_names[2]]

        # Right rotor always steps
        self.positions[3] = (self.positions[3] + 1) % 26

        # Middle steps if right was on notch OR middle is on notch
        step_middle = (right_letter in notch_right) or (middle_letter in notch_middle)

        if step_middle:
            self.positions[2] = (self.positions[2] + 1) % 26

        # Double stepping: if middle was on notch (before middle step), left also steps
        if middle_letter in notch_middle:
            self.positions[1] = (self.positions[1] + 1) % 26

    def _map_through_rotor(self, idx, rotor_name, ring, pos, forward=True):
        offset = (pos - ring) % 26
        entry = (idx + offset) % 26

        if forward:
            substituted = self.wiring[rotor_name][entry]
            out = self.alphabet.index(substituted)
        else:
            substituted = self.alphabet[entry]
            out = self.wiring[rotor_name].index(substituted)

        return (out - offset) % 26

    def encrypt_char(self, char):
        char = char.upper()
        if char not in self.alphabet:
            return char  # keep spaces etc.

        self._rotate()

        # Plugboard in
        idx = self.alphabet.index(self.plugboard[char])

        # Forward: right → left (3→2→1→0)
        for i in [3, 2, 1, 0]:
            idx = self._map_through_rotor(idx, self.rotor_names[i], self.ring_settings[i], self.positions[i], forward=True)

        # Reflector
        idx = self.alphabet.index(self.reflector[idx])

        # Backward: left → right (0→1→2→3)
        for i in [0, 1, 2, 3]:
            idx = self._map_through_rotor(idx, self.rotor_names[i], self.ring_settings[i], self.positions[i], forward=False)

        # Plugboard out
        return self.plugboard[self.alphabet[idx]]

    def process(self, text):
        # Only process letters, ignore everything else (spaces, punctuation, numbers)
        cleaned = ''.join(c for c in text.upper() if c in self.alphabet)
        return "".join(self.encrypt_char(c) for c in cleaned)
    
    def get_settings_summary(self):
        return (f"Rotors: {', '.join(self.rotor_names)}\n"
                f"Reflector: { [k for k,v in self.reflectors.items() if v == self.reflector][0] }\n"
                f"Ring settings: {''.join(chr(65 + r) for r in self.ring_settings)}\n"
                f"Start position: {''.join(chr(65 + p) for p in self.positions)}\n"
                f"Plugboard: { [f'{k}{v}' for k,v in self.plugboard.items() if k < v] }")
    
def format_enigma_output(s, group_size=4):
    """Groups letters into blocks of 4 or 5, like real Enigma messages"""
    return ' '.join(s[i:i+group_size] for i in range(0, len(s), group_size))

# ────────────────────────────────────────────────
# ────────────────────────────────────────────────
#       Enigma Key Space Complexity & Brute-Force Estimate
# ────────────────────────────────────────────────

import math

def prove_enigma_complexity(num_rotors_used=3, total_rotors_available=5, plug_pairs=10):
    rotor_combos = math.perm(total_rotors_available, num_rotors_used)
    ground_settings = 26 ** num_rotors_used
    
    # Two common choices — pick one
    # ring_settings = 26 ** (num_rotors_used - 1)           # your current → 676 for 3 rotors
    ring_settings = 26 ** num_rotors_used // 26             # alternative → 17,576 / 26 ≈ 676? Wait no:
    # Better: most sources use 26^(3) for positions, 26^(2) for rings → but let's fix to classic
    ring_settings = 26 ** (num_rotors_used - 1)             # keep yours for now

    n = 26
    k = plug_pairs
    plugboard_combos = (
        math.factorial(n) //
        (math.factorial(n - 2*k) * math.factorial(k) * (2 ** k))
        if 2*k <= n else 0
    )

    total = rotor_combos * ground_settings * ring_settings * plugboard_combos

    print("\n" + "═" * 90)
    print("  Approximate Enigma Key Space – late-war naval M4 style")
    print("═" * 90)
    print(f"  Rotor orders                  {rotor_combos:>20,}")
    print(f"  Initial positions             {ground_settings:>20,}")
    print(f"  Ring settings                 {ring_settings:>20,}")
    print(f"  Steckerbrett (10 pairs)       {plugboard_combos:>20,}   ← ~150 trillion")
    print("─" * 90)
    print(f"  TOTAL KEY SPACE               {total:>20,}")
    print(f"  ≈ {total:.3e}")
    print("═" * 90)

    return total


def estimate_brute_force(total_combos):
    checks_per_sec = 1_000_000               # very optimistic modern PC
    secs_per_year = 365.25 * 24 * 3600

    years = total_combos / (checks_per_sec * secs_per_year)

    print("\nBrute-force time estimate (extremely optimistic):")
    print(f"  At {checks_per_sec:,} keys/second")
    print(f"  ≈ {years:,.0f} years")
    print(f"  ≈ {years / 1_000_000:,.1f} million years")
    print(f"  ≈ {years / 1_000_000_000:,.2f} billion years")
    print()
    print("(In reality, cryptanalysts used cribs, Bombe machines, and captured material —")
    print(" never pure brute force.)")
    print("═" * 80)


# ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 80)
    print("  M4 Enigma Machine Simulator   –   Beta + 3 moving rotors + thin reflector")
    print("=" * 80)
    print()

    # Quick test
    machine = EnigmaMachine(
        rotors=['Beta', 'I', 'II', 'III'],
        reflector='B_Thin',
        ring_settings='AAAA',
        initial_pos='AAAA',
        plugboard_pairs=['AZ', 'BY']
    )
    quick_result = machine.process("HELLOWORLD")
    print("Quick test (grouped):")
    print(format_enigma_output(quick_result))
    print()

    # Main demo
    active_rotors = ['Beta', 'V', 'VI', 'VIII']
    active_reflector = 'B_Thin'
    rings = 'AAAV'
    start_pos = 'AJRE'
    plugs = [('A','T'), ('B','S'), ('D','E'), ('F','M')]

    cipher_machine = EnigmaMachine(active_rotors, active_reflector, rings, start_pos, plugs)

    original_text = "THEY HAVE DISCOVERED OUR POSITION LEAVE IMMEDIATELY"
    ciphertext = cipher_machine.process(original_text)

    decipher_machine = EnigmaMachine(active_rotors, active_reflector, rings, start_pos, plugs)
    decrypted_text = decipher_machine.process(ciphertext)

    plain_clean = ''.join(c for c in original_text.upper() if c in cipher_machine.alphabet)

    print("-" * 80)
    print("Settings:")
    print(f"  Rotors:      {', '.join(active_rotors)}")
    print(f"  Reflector:   {active_reflector}")
    print(f"  Rings:       {rings}")
    print(f"  Start pos:   {start_pos}")
    print(f"  Plugboard:   {' '.join(f'{a}{b}' for a,b in sorted(plugs))}")
    print("-" * 80)
    print()

    print("Plaintext (grouped):")
    print(format_enigma_output(plain_clean))
    print()

    print("Ciphertext (grouped):")
    print(format_enigma_output(ciphertext))
    print()

    print("Decrypted (grouped):")
    print(format_enigma_output(decrypted_text))
    print("-" * 80)

    if decrypted_text == plain_clean:
        print("\nSUCCESS: Decryption perfectly matches plaintext!")
    else:
        print("\nWARNING: Decryption does NOT match plaintext")

    # Key space analysis – the part you wanted back
    print("\n" + "═" * 80)
    print("  Key Space Analysis – typical late-war M4 settings")
    print("═" * 80)

    total_keys = prove_enigma_complexity(
        num_rotors_used=3,
        total_rotors_available=5,
        plug_pairs=10
    )

    estimate_brute_force(total_keys)

    print("\nSimulation & analysis complete.")