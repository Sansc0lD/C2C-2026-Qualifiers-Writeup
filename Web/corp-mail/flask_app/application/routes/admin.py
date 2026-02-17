from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from ..db import get_db
from ..auth import admin_required

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/')
@admin_required
def panel():
    db = get_db()
    users = db.execute('SELECT id, username, email, signature, is_admin, created_at FROM users ORDER BY id ASC').fetchall()
    
    stats = {
        'total_users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_emails': db.execute('SELECT COUNT(*) FROM emails').fetchone()[0],
        'emails_today': db.execute(
            "SELECT COUNT(*) FROM emails WHERE date(created_at) = date('now')"
        ).fetchone()[0]
    }
    
    return render_template('admin.html', users=users, stats=stats, current_user=g.user)

@bp.route('/user/<int:user_id>/emails')
@admin_required
def user_emails(user_id):
    db = get_db()
    
    user = db.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.panel'))
    
    emails = db.execute('''
        SELECT e.*, 
               sender.username as sender_name,
               receiver.username as receiver_name
        FROM emails e
        JOIN users sender ON e.sender_id = sender.id
        JOIN users receiver ON e.receiver_id = receiver.id
        WHERE e.sender_id = ? OR e.receiver_id = ?
        ORDER BY e.created_at DESC
    ''', (user_id, user_id)).fetchall()
    
    return render_template('admin_emails.html', user=user, emails=emails, current_user=g.user)

@bp.route('/email/<int:email_id>')
@admin_required
def view_email(email_id):
    db = get_db()
    
    email = db.execute('''
        SELECT e.*, 
               sender.username as sender_name, sender.email as sender_email,
               receiver.username as receiver_name, receiver.email as receiver_email
        FROM emails e
        JOIN users sender ON e.sender_id = sender.id
        JOIN users receiver ON e.receiver_id = receiver.id
        WHERE e.id = ?
    ''', (email_id,)).fetchone()
    
    if not email:
        flash('Email not found', 'error')
        return redirect(url_for('admin.panel'))
    
    return render_template('email.html', email=email, current_user=g.user, is_admin_view=True)

@bp.route('/inbox')
@admin_required
def inbox():
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
@admin_required
def sent():
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
@admin_required
def compose():
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
            return redirect(url_for('admin.compose'))
        
        receiver = db.execute('SELECT id FROM users WHERE id = ?', (receiver_id,)).fetchone()
        if not receiver:
            flash('Recipient not found', 'error')
            return redirect(url_for('admin.compose'))
        
        if receiver_id == g.user['user_id']:
            flash('Cannot send email to yourself', 'error')
            return redirect(url_for('admin.compose'))
        
        sender = db.execute('SELECT signature FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
        if sender and sender['signature']:
            body = body + '\n\n--\n' + sender['signature']
        
        db.execute(
            'INSERT INTO emails (sender_id, receiver_id, subject, body) VALUES (?, ?, ?, ?)',
            (g.user['user_id'], receiver_id, subject, body)
        )
        db.commit()
        
        flash('Email sent successfully', 'success')
        return redirect(url_for('admin.sent'))
    
    users = db.execute('SELECT id, username, email FROM users WHERE id != ?', 
                      (g.user['user_id'],)).fetchall()
    
    user = db.execute('SELECT signature FROM users WHERE id = ?', (g.user['user_id'],)).fetchone()
    
    return render_template('compose.html', users=users, current_user=g.user,
                         signature=user['signature'] if user else '')

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == g.user['user_id']:
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('admin.panel'))
    
    db = get_db()
    user = db.execute('SELECT username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin.panel'))
    
    if user['is_admin']:
        flash('Cannot delete admin users', 'error')
        return redirect(url_for('admin.panel'))
    
    db.execute('DELETE FROM emails WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    
    flash(f'User {user["username"]} deleted', 'success')
    return redirect(url_for('admin.panel'))
