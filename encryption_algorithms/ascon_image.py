#!/usr/bin/env python3
import time
from memory_profiler import memory_usage
import cProfile
import pstats
import io
from PIL import Image
import os

# Wrapper for memory profiling
def profile_memory(func, *args, **kwargs):
    mem_usage = memory_usage((func, args, kwargs), interval=0.1, retval=True)
    print(f"Peak memory usage for {func.__name__}: {max(mem_usage[0]):.2f} MiB")
    return mem_usage[1]  # Return the result of the function

"""
Implementation of Ascon-AEAD128, an authenticated cipher
NIST SP 800-232
https://ascon.iaik.tugraz.at/
"""

debug = False
debugpermutation = False

# === Ascon AEAD encryption and decryption ===

def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-AEAD128"): 
    """
    Ascon encryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    plaintext: a bytes object of arbitrary length
    variant: "Ascon-AEAD128"
    returns a bytes object of length len(plaintext)+16 containing the ciphertext and tag
    """
    assert variant == "Ascon-AEAD128"
    assert len(key) == 16 and len(nonce) == 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8   # bits
    a = 12   # rounds
    b = 8    # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, 1, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ciphertext + tag

def ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-AEAD128"):
    """
    Ascon decryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    ciphertext: a bytes object of arbitrary length (also contains tag)
    variant: "Ascon-AEAD128"
    returns a bytes object containing the plaintext or None if verification fails
    """
    assert variant == "Ascon-AEAD128"
    assert len(key) == 16 and len(nonce) == 16 and len(ciphertext) >= 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8 # bits
    a = 12  # rounds
    b = 8   # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, 1, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])
    tag = ascon_finalize(S, rate, a, key)
    if tag == ciphertext[-16:]:
        return plaintext
    else:
        return None

# === Ascon AEAD building blocks ===

def ascon_initialize(S, k, rate, a, b, version, key, nonce):
    """
    Ascon initialization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    k: key size in bits
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    b: number of intermediate rounds for permutation
    version: 1 (for Ascon-AEAD128)
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16
    returns nothing, updates S
    """
    taglen = 128
    iv = to_bytes([version, 0, (b << 4) + a]) + int_to_bytes(taglen, 2) + to_bytes([rate, 0, 0])
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv + key + nonce)
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, a)

    zero_key = bytes_to_state(zero_bytes(40 - len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]
    if debug: printstate(S, "initialization:")

def ascon_process_associated_data(S, b, rate, associateddata):
    """
    Ascon associated data processing phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    associateddata: a bytes object of arbitrary length
    returns nothing, updates S
    """
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])

            ascon_permutation(S, b)

    S[4] ^= 1 << 63
    if debug: printstate(S, "process associated data:")

def ascon_process_plaintext(S, b, rate, plaintext):
    """
    Ascon plaintext processing phase (during encryption) - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    plaintext: a bytes object of arbitrary length
    returns the ciphertext (without tag), updates S
    """
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate - p_lastlen - 1)
    p_padded = plaintext + p_padding

    # first t-1 blocks
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
        ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))
        ascon_permutation(S, b)

    # last block t
    block = len(p_padded) - rate
    S[0] ^= bytes_to_int(p_padded[block:block + 8])
    S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
    ciphertext += (int_to_bytes(S[0], 8)[:min(8, p_lastlen)] + int_to_bytes(S[1], 8)[:max(0, p_lastlen - 8)])
    if debug: printstate(S, "process plaintext:")
    return ciphertext

def ascon_process_ciphertext(S, b, rate, ciphertext):
    """
    Ascon ciphertext processing phase (during decryption) - internal helper function. 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    ciphertext: a bytes object of arbitrary length
    returns the plaintext, updates S
    """
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    # first t-1 blocks
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        Ci = (bytes_to_int(c_padded[block:block + 8]), bytes_to_int(c_padded[block + 8:block + 16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
        S[0] = Ci[0]
        S[1] = Ci[1]
        ascon_permutation(S, b)

    # last block t
    block = len(c_padded) - rate
    c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
    c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
    Ci = (bytes_to_int(c_padded[block:block + 8]), bytes_to_int(c_padded[block + 8:block + 16]))
    plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
    S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ Ci[0] ^ bytes_to_int(c_padx[0:8])
    S[1] = (S[1] & bytes_to_int(c_mask[8:16])) ^ Ci[1] ^ bytes_to_int(c_padx[8:16])
    if debug: printstate(S, "process ciphertext:")
    return plaintext

def ascon_finalize(S, rate, a, key):
    """
    Ascon finalization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    returns the tag, updates S
    """
    assert len(key) == 16
    S[rate // 8 + 0] ^= bytes_to_int(key[0:8])
    S[rate // 8 + 1] ^= bytes_to_int(key[8:16])

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag

# === Ascon permutation ===

def ascon_permutation(S, rounds=1):
    """
    Ascon core permutation for the sponge construction - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rounds: number of rounds to perform
    returns nothing, updates S
    """
    assert rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")
    for r in range(12 - rounds, 12):
        S[2] ^= (0xf0 - r * 0x10 + r * 0x1)
        if debugpermutation: printwords(S, "round constant addition:")
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF
        if debugpermutation: printwords(S, "substitution layer:")
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1) ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7) ^ rotr(S[4], 41)
        if debugpermutation: printwords(S, "linear diffusion layer:")

# === helper functions ===

def get_random_bytes(num):
    import os
    return to_bytes(os.urandom(num))

def zero_bytes(n):
    return n * b"\x00"

def ff_bytes(n):
    return n * b"\xFF"

def to_bytes(l):
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << (i * 8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8 * w:8 * (w + 1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> (i * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return (val >> r) | ((val & (1 << r) - 1) << (64 - r))

def printstate(S, description=""):
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S, description=""):
    printstate(S, description)

# === demo if called directly ===

def demo_aead(variant="Ascon-AEAD128"):
    assert variant == "Ascon-AEAD128"
    print(f"=== demo for encrypting an image using {variant} ===")

    # Prompt user for image path
    while True:
        input_image_path = input("Enter the path to the input image (e.g., image.png): ").strip()
        if not os.path.exists(input_image_path):
            print(f"Error: File '{input_image_path}' does not exist. Please try again.")
            continue
        try:
            with Image.open(input_image_path) as img:
                img.verify()  # Verify it's a valid image
            break
        except Exception as e:
            print(f"Error: '{input_image_path}' is not a valid image file. Please try again. ({e})")

    # Generate key and nonce
    key = get_random_bytes(16)
    nonce = get_random_bytes(16)
    associateddata = b"ASCON_IMAGE"

    # Read image as bytes
    try:
        with open(input_image_path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        print(f"Error reading image: {e}")
        return

    # Measure encryption time
    start_time = time.time()
    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext, variant)
    encryption_time = time.time() - start_time

    # Save encrypted data to a file
    encrypted_file_path = "encrypted_image.bin"
    try:
        with open(encrypted_file_path, "wb") as f:
            f.write(ciphertext)
        print(f"Encrypted image data saved as '{encrypted_file_path}'")
    except Exception as e:
        print(f"Error saving encrypted image data: {e}")
        return

    # Measure decryption time
    start_time = time.time()
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext, variant)
    decryption_time = time.time() - start_time

    # Profile memory for encryption
    profile_memory(ascon_encrypt, key, nonce, associateddata, plaintext, variant)

    # Profile memory for decryption
    profile_memory(ascon_decrypt, key, nonce, associateddata, ciphertext, variant)

    # Verify decryption
    if receivedplaintext is None:
        print("Verification failed!")
        return

    # Save decrypted image
    output_image_path = "decrypted_image.png"
    try:
        with open(output_image_path, "wb") as f:
            f.write(receivedplaintext)
        # Verify the output is a valid image
        Image.open(output_image_path).verify()
        print(f"Decrypted image saved as '{output_image_path}'")
    except Exception as e:
        print(f"Error saving or verifying decrypted image: {e}")
        return

    # Print details
    print("Key:                    ", key.hex())
    print("Nonce:                  ", nonce.hex())
    print("Associated Data:        ", associateddata.hex())
    print("Encrypted image data (first 32 bytes):", ciphertext[:-16][:32].hex(), "...")
    print("Tag:                    ", ciphertext[-16:].hex())
    print("Original image data length:   ", len(plaintext), "bytes")
    print("Decrypted image data length:  ", len(receivedplaintext), "bytes")
    print(f"Encryption time: {encryption_time:.6f} seconds")
    print(f"Decryption time: {decryption_time:.6f} seconds")

if __name__ == "__main__":
    demo_aead("Ascon-AEAD128")
