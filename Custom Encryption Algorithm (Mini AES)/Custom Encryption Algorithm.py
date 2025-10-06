# toy_feistel.py
# Toy Feistel cipher (for learning). Block size = 16 bits.
# Not secure. Demonstrates Feistel rounds and reversible encryption.
#
# Usage: run as script to see example.

from typing import Tuple

def rotate_left(n, bits, width):
    return ((n << bits) & ((1 << width) - 1)) | (n >> (width - bits))

def round_function(right: int, subkey: int) -> int:
    # Simple non-linear-ish function: rotate, xor, small S-box style mixing
    x = rotate_left(right ^ subkey, 3, 8)  # work on 8-bit right
    # small S-like mixing (byte-level)
    x = ((x * 0x5A) ^ 0xC3) & 0xFF
    return x

def key_schedule(master_key: int, rounds: int) -> list:
    # master_key is <= 32 bits (we'll slice into 8-bit subkeys)
    subkeys = []
    for r in range(rounds):
        # simple schedule: rotate master_key and take low 8 bits
        mk = rotate_left(master_key, r+1, 32)
        subkeys.append(mk & 0xFF)
    return subkeys

def feistel_encrypt_block(block: int, subkeys: list) -> int:
    # block: 16-bit integer
    left = (block >> 8) & 0xFF
    right = block & 0xFF
    rounds = len(subkeys)
    for k in subkeys:
        new_left = right
        new_right = left ^ round_function(right, k)
        left, right = new_left, new_right
    return ((left << 8) | right) & 0xFFFF

def feistel_decrypt_block(block: int, subkeys: list) -> int:
    # reverse rounds using subkeys in reverse
    left = (block >> 8) & 0xFF
    right = block & 0xFF
    for k in reversed(subkeys):
        new_right = left
        new_left = right ^ round_function(left, k)
        left, right = new_left, new_right
    return ((left << 8) | right) & 0xFFFF

# ECB helper (pad with zero bytes)
def encrypt_bytes_ecb(plaintext: bytes, master_key: int, rounds=8) -> bytes:
    if len(plaintext) % 2 != 0:
        plaintext = plaintext + b'\x00'
    subkeys = key_schedule(master_key, rounds)
    out = bytearray()
    for i in range(0, len(plaintext), 2):
        block = (plaintext[i] << 8) | plaintext[i+1]
        c = feistel_encrypt_block(block, subkeys)
        out.append((c >> 8) & 0xFF)
        out.append(c & 0xFF)
    return bytes(out)

def decrypt_bytes_ecb(ciphertext: bytes, master_key: int, rounds=8) -> bytes:
    subkeys = key_schedule(master_key, rounds)
    out = bytearray()
    for i in range(0, len(ciphertext), 2):
        block = (ciphertext[i] << 8) | ciphertext[i+1]
        p = feistel_decrypt_block(block, subkeys)
        out.append((p >> 8) & 0xFF)
        out.append(p & 0xFF)
    return bytes(out)

if __name__ == "__main__":
    key = 0xDEADBEEF  # example 32-bit key
    msg = b"HELLO"    # 5 bytes -> padded to 6 bytes
    print("Plaintext:", msg)
    enc = encrypt_bytes_ecb(msg, key, rounds=8)
    print("Encrypted (hex):", enc.hex())
    dec = decrypt_bytes_ecb(enc, key, rounds=8)
    print("Decrypted (bytes):", dec)
    # remove 0 padding if added
    dec = dec.rstrip(b'\x00')
    print("Decrypted (clean):", dec)
    assert dec == msg, "Decryption failed!"
