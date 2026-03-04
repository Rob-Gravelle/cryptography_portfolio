class EnigmaMachine:
    def __init__(self, rotors, reflector, ring_settings, initial_pos, plugboard_pairs):
        self.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        # Correct historical wirings (V is now fixed)
        self.wiring = {
            'I':     'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
            'II':    'AJDKSIRUXBLHWTMCQGZNPYFVOE',
            'III':   'BDFHJLCPRTXVZNYEIWGAKMUSQO',
            'IV':    'ESOVPZJAYQUIRHXLNFTGKDCMWB',
            'V':     'VZBRGITYUPSDNHLXAWMJQOFCKE', 
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
#       UNIT 2: CRYPTANALYSIS TOOLS
# ────────────────────────────────────────────────

class BombeFitness:
    def __init__(self):
        # Standard bigram weights
        self.bigrams = {
            'TH': 3.56, 'HE': 3.07, 'IN': 2.43, 'ER': 2.05, 'RE': 1.85,
            'ON': 1.76, 'AN': 1.99, 'AT': 1.49, 'EN': 1.45, 'ND': 1.35
        }
        
        # HEAVILY weighted trigrams (The "English Fingerprints")
        # We increase these by a factor of 5-10 to ensure they dominate the score
        self.trigrams = {
            'THE': 15.0, 'AND': 10.0, 'ING': 8.0, 'ION': 7.0, 'ENT': 6.0,
            'FOR': 5.0,  'TIO': 5.0,  'ERE': 5.0, 'HER': 5.0, 'ATE': 5.0
        }

    def get_score(self, text):
        score = 0
        # Check Bigrams
        for i in range(len(text) - 1):
            score += self.bigrams.get(text[i:i+2], 0)
            
        # Check Trigrams (The primary signal)
        for i in range(len(text) - 2):
            score += self.trigrams.get(text[i:i+3], 0)
            
        return score
    
class CriblessBombe:
    def __init__(self, ciphertext, rotors, reflector, rings):
        self.ciphertext = ciphertext
        self.rotors = rotors
        self.reflector = reflector
        self.rings = rings
        self.fitness = BombeFitness()

    def attack_plugboard(self, best_pos):
        """Solves the 150 trillion combinations in seconds using Hill Climbing."""
        current_plugs = []
        best_overall_score = 0
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        
        print(f"\n[Unit 2] Attacking Plugboard at position {best_pos}...")

        # Attempt to find up to 10 plug pairs
        for _ in range(10):
            best_pair = None
            
            for i in range(26):
                for j in range(i + 1, 26):
                    char_a, char_b = alphabet[i], alphabet[j]
                    
                    # Skip if letters are already plugged
                    if any(char_a in p or char_b in p for p in current_plugs):
                        continue
                    
                    test_plugs = current_plugs + [(char_a, char_b)]
                    test_machine = EnigmaMachine(self.rotors, self.reflector, self.rings, best_pos, test_plugs)
                    
                    decrypted = test_machine.process(self.ciphertext)
                    score = self.fitness.get_score(decrypted)
                    
                    if score > best_overall_score:
                        best_overall_score = score
                        best_pair = (char_a, char_b)
            
            if best_pair:
                current_plugs.append(best_pair)
                print(f"   Success! Found Plug: {best_pair[0]}-{best_pair[1]} | Fitness: {best_overall_score:.2f}")
            else:
                break # No more improvements found
                
        return current_plugs
    def find_top_rotor_positions(self, top_n=5):
        """Scans all 17,576 positions and returns the top N likely starting points."""
        candidates = [] # This will store tuples of (score, position)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        total_positions = 26 * 26 * 26
        count = 0

        print(f"\n[Unit 2] Scanning 17,576 Positions for Top {top_n} Candidates...")
        
        for r1 in range(26):
            for r2 in range(26):
                for r3 in range(26):
                    count += 1
                    # Progress indicator
                    if count % 1000 == 0:
                        print(f"   Progress: {count}/{total_positions} positions checked...")

                    # We assume Rotor 0 (Beta) is fixed as the first char of our rotors list
                    test_pos = f"{self.rotors[0][0]}{alphabet[r1]}{alphabet[r2]}{alphabet[r3]}"
                    
                    # Create a temporary machine with NO plugs
                    machine = EnigmaMachine(self.rotors, self.reflector, self.rings, test_pos, [])
                    text = machine.process(self.ciphertext)
                    score = self.fitness.get_score(text)
                    
                    # Add to candidates and keep only the top_n
                    candidates.append((score, test_pos))
                    candidates.sort(key=lambda x: x[0], reverse=True)
                    candidates = candidates[:top_n]
                        
        print("\nScan Complete. Top Candidates found:")
        for s, p in candidates:
            print(f"   Pos: {p} | Score: {s:.2f}")
            
        return candidates

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

    original_text = (
        "THEY HAVE DISCOVERED OUR POSITION LEAVE IMMEDIATELY "
        "REPORT BACK TO BASE ON CHANNEL NINER FOUR ZERO ZERO "
        "EXPECT HEAVY RESISTANCE UPON ARRIVAL OVER"
    )
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


    fitness = BombeFitness()
    print(f"English Score: {fitness.get_score('THEYHAVEDISCOVERED')}")
    print(f"Gibberish Score: {fitness.get_score('ILYDZZMTZA')}")

    print("\nSimulation & analysis complete.")

if __name__ == "__main__":
    # ... (Your Quick Test and Setup code remains the same) ...

    # ────────────────────────────────────────────────
    #             AUTOMATED BOMBE ATTACK
    # ────────────────────────────────────────────────
    
    # Initialize the Bombe with the intercepted ciphertext
    bombe = CriblessBombe(ciphertext, active_rotors, active_reflector, rings)

    # 1. Run the "Top N" scanner to get candidates
    candidates = bombe.find_top_rotor_positions(top_n=20)

    print("\n" + "═" * 80)
    print("  PHASE 2: PLUGBOARD HILL-CLIMBING (Multi-Candidate Hunt)")
    print("═" * 80)

    success = False
    final_text = ""
    discovered_plugs = []
    found_pos = ""
    
    # 2. Iterate through the best rotor settings found
    for score, pos in candidates:
        print(f"\n>>> Testing Candidate Position: {pos}")
        
        # Run the hill-climbing plugboard attack
        discovered_plugs = bombe.attack_plugboard(pos)
        
        # Generate the text with the discovered settings
        final_machine = EnigmaMachine(active_rotors, active_reflector, rings, pos, discovered_plugs)
        final_text = final_machine.process(ciphertext)
        
        # --- INSERT THE DENSITY CHECK HERE ---
        common_words = ["THE", "AND", "ING", "THAT", "REPORT", "POSITION"]
        found_count = sum(1 for word in common_words if word in final_text)

        if found_count >= 2: # If we see at least two strong English markers
            print(f"\n TARGET CRACKED! (Found {found_count} English markers)")
            found_pos = pos
            success = True
            break 
        else:
            print(f"   [!] Candidate {pos} yielded gibberish. Moving to next candidate...")

    # 3. Final Report
    if success:
        print("\n" + "═" * 80)
        print("   FINAL BOMBE DECRYPTION REPORT")
        print("═" * 80)
        print(f"Found Rotor Pos:  {found_pos}")
        print(f"Original Plugs:   {sorted(plugs)}")
        print(f"Discovered:       {sorted(discovered_plugs)}")
        print("-" * 80)
        print(f"DECRYPTED MESSAGE:\n{format_enigma_output(final_text)}")
        print("═" * 80)
    else:
        print("\n" + "═" * 80)
        print("   [X] ATTACK FAILED")
        print("═" * 80)
        print("The Bombe could not find a setting that produced recognizable English.")
        print("Try increasing top_n in find_top_rotor_positions() or using a longer message.")
        print("═" * 80)



    print("\nSimulation & Cryptanalysis complete.")
        
    print(f"\nDecrypted Message: {format_enigma_output(final_text)}")

    print("\n" + "═" * 80)
    print("  FINAL BOMBE RESULT")
    print("═" * 80)
    print(f"Original Plugs:   {sorted(plugs)}")
    print(f"Discovered:       {sorted(discovered_plugs)}")
    print(f"\nDecrypted Message: {format_enigma_output(final_text)}")
    print("═" * 80)