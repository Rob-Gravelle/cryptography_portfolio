# utils.py

def bytes2matrix(b):
    # Convert 16-byte array into 4x4 matrix (column-major)
    return [list(b[i::4]) for i in range(4)]

def matrix2bytes(matrix):
    # Convert 4x4 matrix back into 16-byte array (column-major)
    return bytes([matrix[i][j] for j in range(4) for i in range(4)])

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def print_state(state, label="State"):
    print(f"\n🔍 {label}")
    for row in state:
        print(' '.join(f'{b:02x}' for b in row))

