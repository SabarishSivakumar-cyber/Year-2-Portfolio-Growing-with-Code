from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import json, base64

def derive_key(master_pass, salt, iterations=200000):
    return PBKDF2(master_pass, salt, dkLen=32, count=iterations)

def encrypt_vault(vault_dict, master_pass):
    salt = get_random_bytes(16)
    key = derive_key(master_pass.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)
    data = json.dumps(vault_dict).encode()
    ct, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ct).decode()

def decrypt_vault(b64data, master_pass):
    raw = base64.b64decode(b64data)
    salt, nonce, tag, ct = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = derive_key(master_pass.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return json.loads(cipher.decrypt_and_verify(ct, tag))
