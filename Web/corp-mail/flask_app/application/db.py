import sqlite3
import os
import fcntl
from flask import g, current_app
from werkzeug.security import generate_password_hash
from .utils import generate_random_password

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database and seed with initial data."""
    lock_file = '/app/data/.init_lock'
    os.makedirs('/app/data', exist_ok=True)
    
    with open(lock_file, 'w') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            
            db = get_db()
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    signature TEXT DEFAULT '',
                    is_admin INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )
            ''')
            db.commit()
            
            existing = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            if existing > 0:
                return
            
            _seed_database(db)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

def _seed_database(db):
    """Seed the database with initial test data."""
    flag = os.environ.get('FLAG', 'C2C{fake_flag_for_local_testing}')
    
    admin_password = generate_random_password()
    admin_creds_path = '/app/data/.admin_creds'
    with open(admin_creds_path, 'w') as f:
        f.write(f"admin:{admin_password}")
    
    admin_hash = generate_password_hash(admin_password)
    db.execute('''INSERT INTO users (username, email, password, signature, is_admin) 
                  VALUES (?, ?, ?, ?, 1)''',
               ('admin', 'admin@corpmail.local', admin_hash, 
                'Best regards,\nIT Administration\nCorpMail System'))
    
    users_data = [
        ('john.doe', 'john.doe@corpmail.local', 'Development Team'),
        ('jane.smith', 'jane.smith@corpmail.local', 'HR Department'),
        ('mike.wilson', 'mike.wilson@corpmail.local', 'Security Team'),
        ('sarah.jones', 'sarah.jones@corpmail.local', 'Finance Department'),
    ]
    
    user_passwords = {}
    for username, email, dept in users_data:
        password = generate_random_password()
        user_passwords[username] = password
        pwd_hash = generate_password_hash(password)
        signature = f"Best regards,\n{username.replace('.', ' ').title()}\n{dept}"
        db.execute('INSERT INTO users (username, email, password, signature) VALUES (?, ?, ?, ?)',
                   (username, email, pwd_hash, signature))
    
    db.commit()
    
    admin_id = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()[0]
    john_id = db.execute('SELECT id FROM users WHERE username = ?', ('john.doe',)).fetchone()[0]
    jane_id = db.execute('SELECT id FROM users WHERE username = ?', ('jane.smith',)).fetchone()[0]
    mike_id = db.execute('SELECT id FROM users WHERE username = ?', ('mike.wilson',)).fetchone()[0]
    sarah_id = db.execute('SELECT id FROM users WHERE username = ?', ('sarah.jones',)).fetchone()[0]
    
    test_emails = [
        (john_id, jane_id, "Meeting Tomorrow", 
         "Hi Jane,\n\nJust wanted to confirm our meeting tomorrow at 10 AM.\n\nThanks!"),
        
        (jane_id, john_id, "Re: Meeting Tomorrow",
         "Hi John,\n\nYes, that works for me. See you then!\n\nBest,\nJane"),
        
        (sarah_id, mike_id, "Q4 Budget Review",
         "Hi Mike,\n\nPlease review the attached Q4 budget projections when you have a chance.\n\nRegards,\nSarah"),
        
        (mike_id, admin_id, "Security Audit Complete",
         "Hi Admin,\n\nThe quarterly security audit has been completed. No major issues found.\n\nBest,\nMike"),
        
        (admin_id, mike_id, "Confidential: System Credentials",
         f"Hi Mike,\n\nAs requested, here are the backup system credentials for the security audit:\n\nSystem: Backup Server\nAccess Code: {flag}\n\nPlease keep this information secure and delete this email after noting the details.\n\nBest regards,\nIT Administration"),
        
        (admin_id, john_id, "Welcome to CorpMail",
         "Dear John,\n\nWelcome to the CorpMail system. Please remember to set up your email signature in Settings.\n\nBest regards,\nIT Administration"),
        
        (jane_id, sarah_id, "Lunch Plans",
         "Hey Sarah!\n\nWant to grab lunch today? The new cafe opened downstairs.\n\nJane"),
        
        (sarah_id, jane_id, "Re: Lunch Plans",
         "Sounds great! Let's meet at 12:30.\n\nSarah"),
    ]
    
    for sender_id, receiver_id, subject, body in test_emails:
        db.execute('INSERT INTO emails (sender_id, receiver_id, subject, body) VALUES (?, ?, ?, ?)',
                   (sender_id, receiver_id, subject, body))
    
    db.commit()
    print("[+] Database initialized with test data")

