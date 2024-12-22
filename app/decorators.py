from functools import wraps
from flask import request, redirect, url_for, current_app, flash, session
from datetime import datetime

# Importar Auth desde el lugar correcto
from app.auth.routes import Auth
from app.models import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')  # Usa la cookie en lugar del header
        session['next'] = request.url  # Guardar la URL actual

        if not token:
            flash('No tienes autorización para acceder a esta página.', 'danger')
            return redirect(url_for('auth.login'))

        # Decodificar el token
        result = Auth.decode_token(token)
        if not result["valid"]:
            flash(result["error"], 'danger')  # Usa el error del diccionario
            return redirect(url_for('auth.login'))

        user = User.query.get(result["payload"].get('user_id'))
        if not user:
            flash('Usuario no encontrado.', 'danger')
            return redirect(url_for('auth.login'))

        # Inyectar al usuario en `kwargs` para uso posterior
        kwargs['current_user'] = user
        return f(*args, **kwargs)
    return decorated

