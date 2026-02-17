from flask import Blueprint, request, jsonify
from datetime import datetime
from utils.db import get_db
from utils.auth import token_required

game_bp = Blueprint('game', __name__)

@game_bp.route('/api/click', methods=['POST'])
@token_required
def record_click():
    user_id = request.current_user['user_id']
    
    db = get_db()
    db.execute('UPDATE clicks SET click_count = click_count + 1, last_click = ? WHERE user_id = ?',
               (datetime.utcnow(), user_id))
    db.commit()
    
    clicks = db.execute('SELECT click_count FROM clicks WHERE user_id = ?', (user_id,)).fetchone()
    db.close()
    
    return jsonify({'clicks': clicks['click_count']}), 200

@game_bp.route('/api/stats', methods=['GET'])
@token_required
def get_stats():
    user_id = request.current_user['user_id']
    
    db = get_db()
    clicks = db.execute('SELECT click_count, last_click FROM clicks WHERE user_id = ?',
                       (user_id,)).fetchone()
    db.close()
    
    return jsonify({
        'clicks': clicks['click_count'] if clicks else 0,
        'last_click': clicks['last_click'] if clicks else None
    }), 200

@game_bp.route('/api/game-config', methods=['GET'])
@token_required
def get_game_config():
    db = get_db()
    image_url = db.execute('SELECT value FROM settings WHERE key = ?', ('image_url',)).fetchone()
    audio_url = db.execute('SELECT value FROM settings WHERE key = ?', ('audio_url',)).fetchone()
    db.close()
    
    return jsonify({
        'image_url': image_url['value'] if image_url else '/static/mambo.jpg',
        'audio_url': audio_url['value'] if audio_url else '/static/mambo.mp3'
    }), 200

@game_bp.route('/api/leaderboard', methods=['GET'])
@token_required
def get_leaderboard():
    db = get_db()
    leaderboard = db.execute('''
        SELECT u.username, c.click_count 
        FROM users u 
        JOIN clicks c ON u.id = c.user_id 
        WHERE u.is_admin = 0
        ORDER BY c.click_count DESC 
        LIMIT 10
    ''').fetchall()
    db.close()
    
    leaderboard_data = [{'username': row['username'], 'clicks': row['click_count']} for row in leaderboard]
    return jsonify(leaderboard_data), 200
