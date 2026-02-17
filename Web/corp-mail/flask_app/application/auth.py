from functools import wraps
from datetime import datetime, timedelta
import jwt
from flask import request, redirect, url_for, flash, g, current_app

def generate_token(user_id, username, is_admin):
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm=current_app.config['JWT_ALGORITHM'])

def verify_token(token):
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=[current_app.config['JWT_ALGORITHM']])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Please login first', 'error')
            return redirect(url_for('auth.login'))
        
        payload = verify_token(token)
        if not payload:
            flash('Session expired, please login again', 'error')
            return redirect(url_for('auth.login'))
        
        g.user = payload
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Please login first', 'error')
            return redirect(url_for('auth.login'))
        
        payload = verify_token(token)
        if not payload:
            flash('Session expired', 'error')
            return redirect(url_for('auth.login'))
        
        if not payload.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect(url_for('user.inbox'))
        
        g.user = payload
        return f(*args, **kwargs)
    return decorated_function
