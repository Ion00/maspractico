from flask import Blueprint

auth = Blueprint('auth', __name__)

# Importar las rutas del módulo `routes`
from app.auth import routes
