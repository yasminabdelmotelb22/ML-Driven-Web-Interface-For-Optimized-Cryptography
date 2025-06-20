
# hummingbird2.py – Stream cipher simulation for Hummingbird-2 style encryption

def keystream_generator(seed, length):
    stream = bytearray()
    state = seed
    for _ in range(length):
        state = ((state << 5) ^ (state >> 3)) & 0xFFFFFFFF
        stream.append((state ^ (state >> 8)) & 0xFF)
    return stream

def hummingbird2_encrypt(data, key=0xA5A5A5A5):
    stream = keystream_generator(key, len(data))
    return bytes([b ^ stream[i] for i, b in enumerate(data)])

def hummingbird2_decrypt(data, key=0xA5A5A5A5):
    # Symmetric (same as encryption)
    stream = keystream_generator(key, len(data))
    return bytes([b ^ stream[i] for i, b in enumerate(data)])
