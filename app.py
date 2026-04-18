from flask import Flask
from config import Config

from sqlalchemy import  create_engine
from sqlalchemy.ext.declarative import declarative_base



from routes.auth import authBlueprint
from routes.users import usersBlueprint
from routes.admin import adminBlueprint




def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)


    Base= declarative_base()
    engine= create_engine('sqlite:///keyvent.db')


    app.register_blueprint(authBlueprint, url_prefix='/api/v1')
    app.register_blueprint(usersBlueprint, url_prefix='/api/v1')
    app.register_blueprint(adminBlueprint, url_prefix='/api/v1')

    @app.route('/health')
    def health():
        return {"success": True, "message": "UserBase API is running"}

    return app





if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)