from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from ..db import get_db
from ..auth import generate_token

bp = Blueprint('auth', __name__)

@bp.route('/')
def index():
    if request.cookies.get('token'):
        return redirect(url_for('user.inbox'))
    return redirect(url_for('auth.login'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if len(username) < 3 or len(username) > 30:
            flash('Username must be 3-30 characters', 'error')
            return render_template('register.html')
        
        if not username.replace('_', '').replace('.', '').replace('-', '').isalnum():
            flash('Username can only contain letters, numbers, dots, underscores and hyphens', 'error')
            return render_template('register.html')
        
        if '@' not in email or '.' not in email:
            flash('Invalid email format', 'error')
            return render_template('register.html')
        
        db = get_db()
        try:
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (username, email, password, signature) VALUES (?, ?, ?, ?)',
                       (username, email, hashed_password, ''))
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            token = generate_token(user['id'], user['username'], user['is_admin'])
            
            resp = make_response(redirect(url_for('user.inbox')))
            resp.set_cookie('token', token, httponly=True, max_age=86400)
            return resp
        
        flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@bp.route('/logout')
def logout():
    resp = make_response(redirect(url_for('auth.login')))
    resp.set_cookie('token', '', expires=0)
    flash('Logged out successfully', 'success')
    return resp
