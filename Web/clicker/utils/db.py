import sqlite3
import hashlib
import secrets
import string
import os

def get_db(db_path='game.db'):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

def init_db(db_path='game.db'):
    db = get_db(db_path)
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS clicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        click_count INTEGER DEFAULT 0,
        last_click TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    existing_admin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    
    admin_password = None
    if not existing_admin:
        admin_password_plain = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        admin_password = admin_password_plain
        admin_password_hash = hashlib.sha256(admin_password_plain.encode()).hexdigest()
        try:
            db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                       ('admin', admin_password_hash, 1))
        except sqlite3.IntegrityError:
            pass
    
    default_settings = [
        ('image_url', '/static/mambo.jpg'),
        ('audio_url', '/static/mambo.mp3')
    ]
    
    for key, value in default_settings:
        try:
            db.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, value))
        except sqlite3.IntegrityError:
            pass
    
    demo_users = [
        ('beluga', 15420),
        ('ano sensei', 12350),
        ('pewdiepie', 9870),
        ('linz is here', 7654),
        ('sawit enjoyer', 5432)
    ]
    
    for username, clicks in demo_users:
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not existing:
            fake_plain_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            try:
                cursor = db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                           (username, hashlib.sha256(fake_plain_password.encode()).hexdigest()))
                user_id = cursor.lastrowid
                db.execute('INSERT INTO clicks (user_id, click_count) VALUES (?, ?)', (user_id, clicks))
            except sqlite3.IntegrityError:
                pass
    
    db.commit()
    db.close()
    
    return admin_password
