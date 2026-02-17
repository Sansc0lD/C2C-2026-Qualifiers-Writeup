import struct
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

def derive_key_iv(password, salt):
    """Implements OpenSSL's legacy EVP_BytesToKey (MD5)"""
    d = d_i = b''
    while len(d) < 32 + 16:
        d_i = MD5.new(d_i + password + salt).digest()
        d += d_i
    return d[:32], d[32:48]

def solve():
    password = b"4_g00d_fr13nD_in_n33D"
    
    # 1. Read and Decrypt (AES-256-CBC)
    try:
        with open("dist/whatisthis.enc", "rb") as f:
            data = f.read()
            
        salt = data[8:16] # Extract salt from header
        key, iv = derive_key_iv(password, salt)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Decrypt and strip the 'Salted__' header block logic implicitly
        decrypted_od = unpad(cipher.decrypt(data[16:]), AES.block_size)
        
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return

    # 2. Reverse Octal Dump (od) format to Text
    # The decrypted content is text like "0000000 042503 ..."
    print("[+] Decrypted! Extracting flag from dump...")
    
    flag_bytes = bytearray()
    for line in decrypted_od.splitlines():
        parts = line.split()
        if len(parts) > 1:
            # Skip offset (index 0), process data chunks
            for octal_str in parts[1:]:
                try:
                    val = int(octal_str, 8)
                    # 'od' on Linux usually outputs 2-byte shorts (Little Endian)
                    flag_bytes += struct.pack('<H', val)
                except: pass

    # 3. Print Flag
    print("-" * 40)
    print(flag_bytes.decode(errors='ignore').strip())
    print("-" * 40)

if __name__ == "__main__":
    solve()
