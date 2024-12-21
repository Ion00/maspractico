from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os


# Carga las variables desde .env
load_dotenv()

# Inicializar extensiones (sin asociarlas a la app todavía)
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Configurar la clave secreta
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['ENV'] = os.getenv('ENV', 'development')

    # Configurar SQLAlchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DEV_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    migrate.init_app(app, db)  # Vincula Flask-Migrate con tu aplicación y base de datos

    # Asociar las extensiones a la aplicación
    db.init_app(app)
    bcrypt.init_app(app)
    
    # Inicializar LoginManager con la aplicación
    login_manager.init_app(app)
    # Establecer la vista de inicio de sesión (redirección automática)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

    with app.app_context():
        from .routes import main  # Importar el Blueprint main
        from .auth import auth
        from .models import User  # Modelo de usuario

        #Registra los blueprints
        app.register_blueprint(main)  # Registrar el Blueprint main
        app.register_blueprint(auth, url_prefix="/auth")
        return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User
    # Cargar el usuario por ID
    return User.get_user_by_id(user_id)