from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from ..db import get_db
from ..auth import login_required
from ..utils import format_signature

bp = Blueprint('user', __name__)

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
    
    if request.method == 'POST':
        signature_template = request.form.get('signature', '')
        
        if len(signature_template) > 500:
            flash('Signature too long (max 500 characters)', 'error')
            return render_template('settings.html', user=user, current_user=g.user)
        
        formatted_signature = format_signature(signature_template, g.user['username'])
        
        db.execute('UPDATE users SET signature = ? WHERE id = ?',
                   (formatted_signature, g.user['user_id']))
        db.commit()
        
        flash('Signature updated successfully', 'success')
        
        user = db.execute('SELECT * FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
        return render_template('settings.html', user=user, current_user=g.user)
    
    return render_template('settings.html', user=user, current_user=g.user)

@bp.route('/inbox')
@login_required
def inbox():
    if g.user.get('is_admin'):
        return redirect(url_for('admin.inbox'))
    
    db = get_db()
    
    emails = db.execute('''
        SELECT e.*, u.username as sender_name, u.email as sender_email
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        WHERE e.receiver_id = ?
        ORDER BY e.created_at DESC
    ''', (g.user['user_id'],)).fetchall()
    
    unread_count = db.execute(
        'SELECT COUNT(*) FROM emails WHERE receiver_id = ? AND is_read = 0',
        (g.user['user_id'],)
    ).fetchone()[0]
    
    return render_template('inbox.html', 
                         emails=emails, 
                         unread_count=unread_count,
                         current_user=g.user)

@bp.route('/sent')
@login_required
def sent():
    if g.user.get('is_admin'):
        return redirect(url_for('admin.sent'))
    
    db = get_db()
    
    emails = db.execute('''
        SELECT e.*, u.username as receiver_name, u.email as receiver_email
        FROM emails e
        JOIN users u ON e.receiver_id = u.id
        WHERE e.sender_id = ?
        ORDER BY e.created_at DESC
    ''', (g.user['user_id'],)).fetchall()
    
    return render_template('sent.html', emails=emails, current_user=g.user)

@bp.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    if g.user.get('is_admin'):
        if request.method == 'POST':
            return redirect(url_for('admin.compose'))
        return redirect(url_for('admin.compose'))
    
    db = get_db()
    
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        
        if not receiver_id or not subject or not body:
            flash('All fields are required', 'error')
            users = db.execute('SELECT id, username, email FROM users WHERE id != ?', 
                             (g.user['user_id'],)).fetchall()
            return render_template('compose.html', users=users, current_user=g.user)
        
        try:
            receiver_id = int(receiver_id)
        except ValueError:
            flash('Invalid recipient', 'error')
            return redirect(url_for('user.compose'))
        
        receiver = db.execute('SELECT id FROM users WHERE id = ?', (receiver_id,)).fetchone()
        if not receiver:
            flash('Recipient not found', 'error')
            return redirect(url_for('user.compose'))
        
        if receiver_id == g.user['user_id']:
            flash('Cannot send email to yourself', 'error')
            return redirect(url_for('user.compose'))
        
        sender = db.execute('SELECT signature FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
        if sender and sender['signature']:
            body = body + '\n\n--\n' + sender['signature']
        
        db.execute(
            'INSERT INTO emails (sender_id, receiver_id, subject, body) VALUES (?, ?, ?, ?)',
            (g.user['user_id'], receiver_id, subject, body)
        )
        db.commit()
        
        flash('Email sent successfully', 'success')
        return redirect(url_for('user.sent'))
    
    users = db.execute('SELECT id, username, email FROM users WHERE id != ?', 
                      (g.user['user_id'],)).fetchall()
    
    user = db.execute('SELECT signature FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
    
    return render_template('compose.html', users=users, current_user=g.user,
                         signature=user['signature'] if user else '')

@bp.route('/email/<int:email_id>')
@login_required
def view_email(email_id):
    if g.user.get('is_admin'):
        return redirect(url_for('admin.view_email', email_id=email_id))
    
    db = get_db()
    
    email = db.execute('''
        SELECT e.*, 
               sender.username as sender_name, sender.email as sender_email,
               receiver.username as receiver_name, receiver.email as receiver_email
        FROM emails e
        JOIN users sender ON e.sender_id = sender.id
        JOIN users receiver ON e.receiver_id = receiver.id
        WHERE e.id = ? AND (e.sender_id = ? OR e.receiver_id = ?)
    ''', (email_id, g.user['user_id'], g.user['user_id'])).fetchone()
    
    if not email:
        flash('Email not found', 'error')
        return redirect(url_for('user.inbox'))
    
    if email['receiver_id'] == g.user['user_id'] and not email['is_read']:
        db.execute('UPDATE emails SET is_read = 1 WHERE id = ?', (email_id,))
        db.commit()
    
    return render_template('email.html', email=email, current_user=g.user)
