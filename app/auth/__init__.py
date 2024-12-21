from flask import Blueprint

auth = Blueprint('auth', __name__)

# Almacenar un límite de intentos fallidos
MAX_LOGIN_ATTEMPTS = 5  # Máximo número de intentos antes de bloquear temporalmente al usuario

# Importar las rutas del módulo `routes`
from app.auth import routes
