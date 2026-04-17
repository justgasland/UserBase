from flask import Flask


app=Flask(__name__)


# DATABASE SETUP

from sqlalchemy import  create_engine
from sqlalchemy.ext.declarative import declarative_base

Base= declarative_base()
engine= create_engine('sqlite:///keyvent.db')


# Extentions
from sqlalchemy import SQLAlchemy
from Migrate
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()


from flask import Flask
from config import Config
from extensions import db, migrate, bcrypt

from models.user import User
from models.refresh_token import RefreshToken
from models.reset_token import PasswordResetToken

from routes.auth import auth_bp
from routes.users import users_bp
from routes.admin import admin_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)

    app.register_blueprint(auth_bp, url_prefix='/api/v1')
    app.register_blueprint(users_bp, url_prefix='/api/v1')
    app.register_blueprint(admin_bp, url_prefix='/api/v1')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)