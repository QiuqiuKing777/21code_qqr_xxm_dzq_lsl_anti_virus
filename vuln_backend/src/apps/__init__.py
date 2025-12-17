from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from src.config import Config
# from src.apps.utils.db_trigggers import create_triggers

db = SQLAlchemy()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    from src.apps.routes.main import main as main_bp
    app.register_blueprint(main_bp)

    return app