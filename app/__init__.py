from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
import redis


# Carga las variables desde .env
load_dotenv()

# Inicializar extensiones (sin asociarlas a la app todavía
mail = Mail()
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
redis_client = None

def create_app(config_class='config.DevelopmentConfig'):
    app = Flask(__name__)
    app.config.from_object(config_class)  # Cargar configuración desde config.py

    # Depuración: Imprimir configuraciones cargadas
    print(f"Cargando configuración: {app.config}")

    # Inicializar extensiones y blueprints
    global redis_client
    redis_client = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)
    migrate.init_app(app, db)
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    # Configurar LoginManager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

    with app.app_context():
        from .routes import main
        from app.auth.routes import auth
        from .models import User

        app.register_blueprint(main)
        app.register_blueprint(auth, url_prefix="/auth")
        return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    # Cargar el usuario por ID
    return User.get_user_by_id(user_id)