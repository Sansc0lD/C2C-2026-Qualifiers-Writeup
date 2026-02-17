from flask import Flask
from .config import configure_app
from .db import init_db, close_db
from .routes import auth, user, admin

def create_app():
    app = Flask(__name__)
    configure_app(app)
    
    app.teardown_appcontext(close_db)
    
    # Register blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(user.bp)
    app.register_blueprint(admin.bp)
    
    with app.app_context():
        init_db()
        
    import os
    os.environ.pop('FLAG', None)
    os.environ.pop('GZCTF_FLAG', None)
        
    return app
