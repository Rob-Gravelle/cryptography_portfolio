# ch_aes.py

from ch_utils import bytes2matrix, matrix2bytes, print_state
from sbox import sbox, inv_sbox  # ensure sbox.py is present
# If sbox is part of ch_utils, adjust the import accordingly

Nb = 4
Nk = 4
Nr = 10

Rcon = [
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]

class AES:
    def __init__(self, master_key):
        assert len(master_key) == 16
        self.round_keys = self.key_expansion(master_key)

    def key_expansion(self, key):
        key_columns = [list(key[i:i+4]) for i in range(0, len(key), 4)]
        i = Nk
        while len(key_columns) < Nb * (Nr + 1):
            word = list(key_columns[-1])
            if i % Nk == 0:
                word = self.sub_word(self.rot_word(word))
                word[0] ^= Rcon[i // Nk - 1]
            word = [x ^ y for x, y in zip(word, key_columns[-Nk])]
            key_columns.append(word)
            i += 1
        return [[list(col) for col in zip(*key_columns[i:i + Nb])] for i in range(0, len(key_columns), Nb)]

    def sub_word(self, word):
        return [sbox[b] for b in word]

    def rot_word(self, word):
        return word[1:] + word[:1]

    def add_round_key(self, state, key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]
        return state

    def sub_bytes(self, state):
        return [[sbox[b] for b in row] for row in state]

    def inv_sub_bytes(self, state):
        return [[inv_sbox[b] for b in row] for row in state]

    def shift_rows(self, state):
        return [state[0],
                state[1][1:] + state[1][:1],
                state[2][2:] + state[2][:2],
                state[3][3:] + state[3][:3]]

    def inv_shift_rows(self, state):
        return [state[0],
                state[1][-1:] + state[1][:-1],
                state[2][-2:] + state[2][:-2],
                state[3][-3:] + state[3][:-3]]

    def mix_columns(self, state):
        for i in range(4):
            a = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = self.gmul(a[0], 2) ^ self.gmul(a[1], 3) ^ a[2] ^ a[3]
            state[1][i] = a[0] ^ self.gmul(a[1], 2) ^ self.gmul(a[2], 3) ^ a[3]
            state[2][i] = a[0] ^ a[1] ^ self.gmul(a[2], 2) ^ self.gmul(a[3], 3)
            state[3][i] = self.gmul(a[0], 3) ^ a[1] ^ a[2] ^ self.gmul(a[3], 2)
        return state

    def inv_mix_columns(self, state):
        for i in range(4):
            a = state[0][i], state[1][i], state[2][i], state[3][i]
            state[0][i] = self.gmul(a[0], 0x0e) ^ self.gmul(a[1], 0x0b) ^ self.gmul(a[2], 0x0d) ^ self.gmul(a[3], 0x09)
            state[1][i] = self.gmul(a[0], 0x09) ^ self.gmul(a[1], 0x0e) ^ self.gmul(a[2], 0x0b) ^ self.gmul(a[3], 0x0d)
            state[2][i] = self.gmul(a[0], 0x0d) ^ self.gmul(a[1], 0x09) ^ self.gmul(a[2], 0x0e) ^ self.gmul(a[3], 0x0b)
            state[3][i] = self.gmul(a[0], 0x0b) ^ self.gmul(a[1], 0x0d) ^ self.gmul(a[2], 0x09) ^ self.gmul(a[3], 0x0e)
        return state

    def gmul(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        state = bytes2matrix(plaintext)
        state = self.add_round_key(state, self.round_keys[0])

        for r in range(1, Nr):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[r])

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[Nr])
        return matrix2bytes(state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        state = bytes2matrix(ciphertext)
        state = self.add_round_key(state, self.round_keys[Nr])
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)

        for r in range(Nr - 1, 0, -1):
            state = self.add_round_key(state, self.round_keys[r])
            state = self.inv_mix_columns(state)
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)

        state = self.add_round_key(state, self.round_keys[0])
        return matrix2bytes(state)

    def encrypt_block_verbose(self, plaintext):
        assert len(plaintext) == 16
        state = bytes2matrix(plaintext)
        print_state(state, "Initial Plaintext")

        state = self.add_round_key(state, self.round_keys[0])
        print_state(state, "Round 0 - After AddRoundKey")

        for r in range(1, Nr):
            state = self.sub_bytes(state)
            print_state(state, f"Round {r} - After SubBytes")

            state = self.shift_rows(state)
            print_state(state, f"Round {r} - After ShiftRows")

            state = self.mix_columns(state)
            print_state(state, f"Round {r} - After MixColumns")

            state = self.add_round_key(state, self.round_keys[r])
            print_state(state, f"Round {r} - After AddRoundKey")

        state = self.sub_bytes(state)
        print_state(state, "Final Round - After SubBytes")

        state = self.shift_rows(state)
        print_state(state, "Final Round - After ShiftRows")

        state = self.add_round_key(state, self.round_keys[Nr])
        print_state(state, "Final Round - After AddRoundKey")

        return matrix2bytes(state)


    def decrypt_block_verbose(self, ciphertext):
        assert len(ciphertext) == 16
        state = bytes2matrix(ciphertext)
        print_state(state, "Initial Ciphertext")

        state = self.add_round_key(state, self.round_keys[Nr])
        print_state(state, f"Round {Nr} - After AddRoundKey")

        state = self.inv_shift_rows(state)
        print_state(state, f"Round {Nr} - After InvShiftRows")

        state = self.inv_sub_bytes(state)
        print_state(state, f"Round {Nr} - After InvSubBytes")

        for r in range(Nr - 1, 0, -1):
            state = self.add_round_key(state, self.round_keys[r])
            print_state(state, f"Round {r} - After AddRoundKey")

            state = self.inv_mix_columns(state)
            print_state(state, f"Round {r} - After InvMixColumns")

            state = self.inv_shift_rows(state)
            print_state(state, f"Round {r} - After InvShiftRows")

            state = self.inv_sub_bytes(state)
            print_state(state, f"Round {r} - After InvSubBytes")

        state = self.add_round_key(state, self.round_keys[0])
        print_state(state, "Final Round - After AddRoundKey")

        return matrix2bytes(state)



if __name__ == "__main__":
    key = b'Thats my Kung Fu'
    plaintext = b'Two One Nine Two'

    aes = AES(key)

    print("\n[🔐 VERBOSE AES ENCRYPTION DEMO]")
    ciphertext = aes.encrypt_block_verbose(plaintext)
    print(f"\n🧾 Final Ciphertext (hex): {ciphertext.hex()}")

    print("\n[🔓 VERBOSE AES DECRYPTION DEMO]")
    recovered = aes.decrypt_block_verbose(ciphertext)
    print(f"\n🧾 Final Decrypted Plaintext: {recovered}")

    if recovered == plaintext:
        print("\n✅ AES roundtrip decryption successful!")
    else:
        print("\n❌ AES decryption failed.")

