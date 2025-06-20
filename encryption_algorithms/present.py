
SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
]

SBOX_INV = [SBOX.index(x) for x in range(16)]

PBOX = [
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
]

PBOX_INV = [PBOX.index(x) for x in range(64)]

def generate_round_keys(key, rounds=32):
    round_keys = []
    for i in range(rounds):
        round_keys.append(key >> 16)
        key = ((key & (2**19 - 1)) << 61) | (key >> 19)
        key = (SBOX[(key >> 76) & 0xF] << 76) | (key & ~(0xF << 76))
        key ^= (i + 1) << 15
    return round_keys

def add_round_key(state, round_key):
    return state ^ round_key

def sbox_layer(state):
    return sum(SBOX[(state >> 4*i) & 0xF] << 4*i for i in range(16))

def sbox_layer_inv(state):
    return sum(SBOX_INV[(state >> 4*i) & 0xF] << 4*i for i in range(16))

def pbox_layer(state):
    output = 0
    for i in range(64):
        if (state >> i) & 1:
            output |= 1 << PBOX[i]
    return output

def pbox_layer_inv(state):
    output = 0
    for i in range(64):
        if (state >> i) & 1:
            output |= 1 << PBOX_INV[i]
    return output

def present_encrypt_block(block, key, rounds=32):
    state = block
    round_keys = generate_round_keys(key, rounds)
    for i in range(rounds - 1):
        state = add_round_key(state, round_keys[i])
        state = sbox_layer(state)
        state = pbox_layer(state)
    state = add_round_key(state, round_keys[-1])
    return state

def present_decrypt_block(block, key, rounds=32):
    state = block
    round_keys = generate_round_keys(key, rounds)
    state = add_round_key(state, round_keys[-1])
    for i in range(rounds - 2, -1, -1):
        state = pbox_layer_inv(state)
        state = sbox_layer_inv(state)
        state = add_round_key(state, round_keys[i])
    return state

def present_encrypt(data, key=0x00000000000000000000):
    padded = data + b'\x00' * ((8 - len(data) % 8) % 8)
    out = bytearray()
    for i in range(0, len(padded), 8):
        block = int.from_bytes(padded[i:i+8], 'big')
        cipher = present_encrypt_block(block, key)
        out.extend(cipher.to_bytes(8, 'big'))
    return bytes(out)

def present_decrypt(data, key=0x00000000000000000000):
    out = bytearray()
    for i in range(0, len(data), 8):
        block = int.from_bytes(data[i:i+8], 'big')
        plain = present_decrypt_block(block, key)
        out.extend(plain.to_bytes(8, 'big'))
    return bytes(out).rstrip(b'\x00')

# present.py - Full Python implementation of PRESENT cipher (64-bit block, 80-bit key)
# Reference: PRESENT Lightweight Block Cipher