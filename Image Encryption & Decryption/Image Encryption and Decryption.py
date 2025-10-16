# image_encryptor.py
# Usage:
#   python3 image_encryptor.py encrypt input.png output.enc
#   python3 image_encryptor.py decrypt output.enc recovered.png
#
# Uses AES-GCM with PBKDF2 to derive the key from a password.

import sys
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import getpass

SALT_SIZE = 16
KEY_LEN = 32
PBKDF2_ITERS = 200000

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=PBKDF2_ITERS)

def encrypt_file(in_path, out_path, password):
    with open(in_path, "rb") as f:
        data = f.read()
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(data)
    with open(out_path, "wb") as f:
        # store: salt | nonce | tag | ciphertext
        f.write(salt + cipher.nonce + tag + ct)
    print(f"Encrypted {in_path} -> {out_path} (size: {len(ct)} bytes)")

def decrypt_file(enc_path, out_path, password):
    with open(enc_path, "rb") as f:
        raw = f.read()
    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE+16]
    tag = raw[SALT_SIZE+16:SALT_SIZE+32]
    ct = raw[SALT_SIZE+32:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        pt = cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        print("Decryption failed: wrong password or tampered file.")
        return
    with open(out_path, "wb") as f:
        f.write(pt)
    print(f"Decrypted {enc_path} -> {out_path} (size: {len(pt)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt","decrypt"):
        print("Usage: python3 image_encryptor.py encrypt input.png output.enc")
        print("       python3 image_encryptor.py decrypt input.enc output.png")
        sys.exit(1)

    mode = sys.argv[1]
    inp = sys.argv[2]
    out = sys.argv[3]
    pw = getpass.getpass("Enter password: ")

    if mode == "encrypt":
        encrypt_file(inp, out, pw)
    else:
        decrypt_file(inp, out, pw)
