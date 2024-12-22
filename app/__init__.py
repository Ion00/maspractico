from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os
import redis

# Carga las variables desde .env
load_dotenv()

# Inicializar extensiones (sin asociarlas a la app todavía)
mail = Mail()
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
redis_client = None
limiter = None  # Inicialización de Flask-Limiter

def create_app(config_class='config.DevelopmentConfig'):
    app = Flask(__name__)
    app.config.from_object(config_class)  # Cargar configuración desde config.py

    # Depuración: Imprimir configuraciones cargadas
    print(f"Cargando configuración: {app.config}")

    # Inicializar extensiones
    global redis_client, limiter

    redis_client = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)
    migrate.init_app(app, db)
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    # Configurar LoginManager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

    # Configurar Flask-Limiter con Redis como backend
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[app.config["DEFAULT_RATE_LIMIT"]],  # Cargar límite desde config
        storage_uri=app.config["REDIS_URI"],  # Usar URI desde config.py
        storage_options={
            "socket_connect_timeout": app.config["REDIS_SOCKET_TIMEOUT"]  # Timeout desde config.py
        },
    )

    # Registrar Blueprints
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
