import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
PASSPHRASE = "sulawesi"
FILENAME = "flag.txt.bunakencrypted"
def solve():
    # 1. Setup Key & IV
    key = hashlib.sha256(PASSPHRASE.encode()).digest()[:16]
    
    with open(FILENAME, "r") as f:
        data = base64.b64decode(f.read().strip())


    iv = data[:16]
    ciphertext = data[16:]
    
    print(f"Key used (Hex): {key.hex()}")
    print(f"IV used (Hex) : {iv.hex()}")


    # 2. Force Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    raw_plaintext = decryptor.update(ciphertext)
    print("\n--- RAW DECRYPTED OUTPUT (HEX) ---")
    print(raw_plaintext.hex())
    print("\n--- RAW DECRYPTED OUTPUT (ASCII PREVIEW) ---")
    preview = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_plaintext])
    print(preview)


    if b"C2C" in raw_plaintext:
        print("\n[!] SUCCESS! Flag detected inside output.")
    else:
        print("\n[?] Flag format 'C2C' not detected. Key might be wrong.")


if __name__ == "__main__":
    solve()
