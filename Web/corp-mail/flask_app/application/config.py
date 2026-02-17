import os

def configure_app(app):
    """Configure the Flask application."""
    app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_only_for_local_testing')
    app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'dev_jwt_secret_only_for_local_testing')
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['DATABASE'] = '/app/data/corporate.db'
