import os
import secrets
import string
import base64
from flask import Flask, render_template, send_from_directory, jsonify, request, redirect
from routes.auth import auth_bp
from routes.game import game_bp
from routes.admin import admin_bp
from utils.db import init_db
from utils.jwt_utils import verify_token

app = Flask(__name__)

if not os.environ.get('SECRET_KEY'):
    random_secret = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(64))
    app.config['SECRET_KEY'] = random_secret
else:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['DATABASE'] = 'data/game.db'
app.config['MAX_CONTENT_LENGTH'] = int(1.5 * 1024 * 1024)
app.config['UPLOAD_FOLDER'] = 'static'

app.register_blueprint(auth_bp)
app.register_blueprint(game_bp)
app.register_blueprint(admin_bp)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/game')
def game():
    return render_template('game.html')

@app.route('/admin')
def admin_panel():
    token = request.cookies.get('token')
    if not token:
        return redirect('/')
    payload = verify_token(token)
    if not payload or not payload.get('is_admin'):
        return redirect('/')
    return render_template('admin.html')

@app.route('/jwks.json')
def jwks():
    public_key_path = 'public_key.pem'
    with open(public_key_path, 'r') as f:
        public_key = f.read()
    
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    public_key_obj = serialization.load_pem_public_key(
        public_key.encode(),
        backend=default_backend()
    )
    
    public_numbers = public_key_obj.public_numbers()
    
    def int_to_base64(n):
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')
    
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
    
    return jsonify(jwks_data), 200

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    if not os.path.exists('private_key.pem'):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open('private_key.pem', 'wb') as f:
            f.write(private_pem)
        
        with open('public_key.pem', 'wb') as f:
            f.write(public_pem)
    
    os.makedirs('static', exist_ok=True)
    admin_password = init_db()
    
    if admin_password:
        print("=" * 60)
        print("ADMIN CREDENTIALS")
        print("=" * 60)
        print(f"Username: admin")
        print(f"Password: {admin_password}")
        print("=" * 60)
        print()
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
