import os
import subprocess
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from utils.db import get_db
from utils.auth import token_required, admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/api/admin/settings', methods=['GET'])
@token_required
@admin_required
def get_settings():
    db = get_db()
    settings = db.execute('SELECT key, value FROM settings').fetchall()
    db.close()
    
    settings_dict = {s['key']: s['value'] for s in settings}
    return jsonify(settings_dict), 200

@admin_bp.route('/api/admin/settings', methods=['POST'])
@token_required
@admin_required
def update_settings():
    data = request.get_json()
    
    db = get_db()
    for key, value in data.items():
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (value, key))
    db.commit()
    db.close()
    
    return jsonify({'message': 'Settings updated successfully'}), 200

@admin_bp.route('/api/admin/files', methods=['GET'])
@token_required
@admin_required
def get_files():
    file_type = request.args.get('type')
    
    db = get_db()
    if file_type:
        files = db.execute('SELECT * FROM files WHERE file_type = ? ORDER BY created_at DESC', (file_type,)).fetchall()
    else:
        files = db.execute('SELECT * FROM files ORDER BY created_at DESC').fetchall()
    db.close()
    
    files_list = [dict(f) for f in files]
    return jsonify(files_list), 200

@admin_bp.route('/api/admin/select-file', methods=['POST'])
@token_required
@admin_required
def select_file():
    data = request.get_json()
    file_id = data.get('file_id')
    file_type = data.get('type')
    
    if not file_id or not file_type:
        return jsonify({'message': 'File ID and type required'}), 400
    
    db = get_db()
    file_record = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        db.close()
        return jsonify({'message': 'File not found'}), 404
    
    if file_type == 'image':
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (file_record['file_path'], 'image_url'))
    elif file_type == 'audio':
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (file_record['file_path'], 'audio_url'))
    
    db.commit()
    db.close()
    
    return jsonify({'message': 'File selected successfully', 'path': file_record['file_path']}), 200

@admin_bp.route('/api/admin/download', methods=['POST'])
@token_required
@admin_required
def download_file():
    data = request.get_json()
    url = data.get('url')
    filename = data.get('filename')
    title = data.get('title')
    file_type = data.get('type')
    
    if not url or not filename or not title:
        return jsonify({'message': 'URL, filename, and title required'}), 400
    
    # Make sure only http/s are allowed
    blocked_protocols = [
        'dict', 'file', 'ftp', 'ftps', 'gopher', 'gophers',
        'imap', 'imaps', 'ipfs', 'ipns', 'ldap', 'ldaps',
        'mqtt', 'pop3', 'pop3s', 'rtmp', 'rtsp', 'scp',
        'sftp', 'smb', 'smbs', 'smtp', 'smtps', 'telnet',
        'tftp', 'ws', 'wss',
    ]

    url_lower = url.lower().strip()

    for proto in blocked_protocols:
        if url_lower.startswith(proto) or (proto + ':') in url_lower:
            return jsonify({'message': f'Blocked protocol: {proto}'}), 400
    
    filename = secure_filename(filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    try:
        output_path = os.path.join('static', filename)
        result = subprocess.run(['curl', '-o', output_path, '--', url], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            file_size = os.path.getsize(output_path)
            if file_size > int(1.5 * 1024 * 1024):
                os.remove(output_path)
                return jsonify({'message': 'File too large (max 1.5MB)'}), 400
            
            file_path = f'/static/{filename}'
            
            db = get_db()
            db.execute('INSERT INTO files (title, filename, file_type, file_path) VALUES (?, ?, ?, ?)',
                      (title, filename, file_type, file_path))
            db.commit()
            db.close()
            
            return jsonify({
                'message': f'File downloaded successfully',
                'path': file_path,
                'type': file_type
            }), 200
        else:
            return jsonify({'message': 'Download failed', 'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'message': 'Download failed', 'error': str(e)}), 500

@admin_bp.route('/api/admin/upload', methods=['POST'])
@token_required
@admin_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    
    file = request.files['file']
    file_type = request.form.get('type')
    title = request.form.get('title')
    
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    if not title:
        return jsonify({'message': 'Title required'}), 400
    
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'message': 'Invalid filename'}), 400
    
    try:
        file_path_disk = os.path.join('static', filename)
        file.save(file_path_disk)
        
        file_size = os.path.getsize(file_path_disk)
        if file_size > int(1.5 * 1024 * 1024):
            os.remove(file_path_disk)
            return jsonify({'message': 'File too large (max 1.5MB)'}), 400
        
        static_path = f'/static/{filename}'
        
        db = get_db()
        db.execute('INSERT INTO files (title, filename, file_type, file_path) VALUES (?, ?, ?, ?)',
                  (title, filename, file_type, static_path))
        db.commit()
        db.close()
        
        return jsonify({
            'message': 'File uploaded successfully',
            'path': static_path,
            'type': file_type
        }), 200
    except Exception as e:
        return jsonify({'message': 'Upload failed', 'error': str(e)}), 500
