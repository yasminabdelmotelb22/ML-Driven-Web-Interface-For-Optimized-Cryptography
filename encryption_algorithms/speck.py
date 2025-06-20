def speck_encrypt(data, key=b"thisisakey123456"):
    # Simplified Speck encryption (128-bit block, 128-bit key)
    # In practice, implement the full Speck algorithm
    key_int = int.from_bytes(key, byteorder='big') % 2**32
    encrypted = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16].ljust(16, b'\x00')
        block_int = int.from_bytes(block, byteorder='big')
        # Dummy encryption: XOR with key (not secure, for demo only)
        encrypted_block = (block_int ^ key_int) % 2**128
        encrypted.extend(encrypted_block.to_bytes(16, byteorder='big'))
    return bytes(encrypted)

def speck_decrypt(encrypted_data, key=b"thisisakey123456"):
    # Simplified Speck decryption
    key_int = int.from_bytes(key, byteorder='big') % 2**32
    decrypted = bytearray()
    for i in range(0, len(encrypted_data), 16):
        block = encrypted_data[i:i+16]
        block_int = int.from_bytes(block, byteorder='big')
        # Dummy decryption: XOR with key
        decrypted_block = (block_int ^ key_int) % 2**128
        decrypted.extend(decrypted_block.to_bytes(16, byteorder='big'))
    return bytes(decrypted).rstrip(b'\x00')
