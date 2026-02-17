import hashlib
import sqlite3
import jwt
from flask import Blueprint, request, jsonify, make_response
from datetime import datetime, timedelta
from utils.db import get_db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    if len(username) < 3 or len(password) < 6:
        return jsonify({'message': 'Username must be at least 3 characters and password at least 6 characters'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    db = get_db()
    try:
        cursor = db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                           (username, password_hash))
        user_id = cursor.lastrowid
        db.execute('INSERT INTO clicks (user_id, click_count) VALUES (?, 0)', (user_id,))
        db.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 400
    finally:
        db.close()

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                     (username, password_hash)).fetchone()
    db.close()
    
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    payload = {
        'user_id': user['id'],
        'username': user['username'],
        'is_admin': bool(user['is_admin']),
        'exp': datetime.utcnow() + timedelta(hours=24),
        'jku': 'http://localhost:5000/jwks.json'
    }
    
    private_key_path = 'private_key.pem'
    with open(private_key_path, 'r') as f:
        private_key = f.read()
    
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': 'key1'})
    
    resp = make_response(jsonify({
        'token': token,
        'username': user['username'],
        'is_admin': bool(user['is_admin'])
    }), 200)
    resp.set_cookie('token', token, path='/', httponly=False)
    return resp
