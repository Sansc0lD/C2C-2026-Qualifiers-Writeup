import json
import jwt
import requests
import time
from urllib.parse import urlparse
from utils.url_parser import validate_jku_url

jwks_cache = {}
CACHE_TTL = 3600

def fetch_jwks(jku_url):
    try:
        if jku_url in jwks_cache:
            cached_data, cached_time = jwks_cache[jku_url]
            if time.time() - cached_time < CACHE_TTL:
                return cached_data
        
        if not validate_jku_url(jku_url):
            return None
        
        response = requests.get(jku_url, timeout=5, allow_redirects=False)
        
        if response.status_code != 200:
            return None
        
        content_type = response.headers.get('Content-Type', '')
        if content_type != 'application/json':
            return None
        
        if not response.url.endswith('jwks.json'):
            return None
        
        jwks_data = response.json()
        jwks_cache[jku_url] = (jwks_data, time.time())
        
        return jwks_data
    except Exception:
        return None

def verify_token(token):
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        if 'jku' not in unverified:
            return None
        
        jku_url = unverified['jku']
        
        jwks_data = fetch_jwks(jku_url)
        if not jwks_data or 'keys' not in jwks_data:
            return None
        
        for key_data in jwks_data['keys']:
            try:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
                decoded = jwt.decode(token, public_key, algorithms=['RS256'])
                return decoded
            except:
                continue
        
        return None
    except Exception:
        return None
