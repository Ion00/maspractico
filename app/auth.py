from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session, make_response
from flask_login import login_user, logout_user
from .models import User
import jwt
from datetime import datetime, timedelta
from app import db, bcrypt  # Asegúrate de que bcrypt esté importado desde __init__.py

auth = Blueprint('auth', __name__)

# Almacenar un límite de intentos fallidos
MAX_LOGIN_ATTEMPTS = 5  # Máximo número de intentos antes de bloquear temporalmente al usuario

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(correo_e=email).first()

        # Verificar si excedió el máximo de intentos fallidos
        if user.login_failures is not None and user.login_failures >= MAX_LOGIN_ATTEMPTS:
            flash('Demasiados intentos fallidos. Por favor, intenta más tarde o recupera tu contraseña.', 'warning')
            return redirect(url_for('auth.recover_password'))

        # Incrementar intentos fallidos en la base de datos
        if not user or not bcrypt.check_password_hash(user.clave, password):
            user.login_failures += 1
            db.session.commit()
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('auth.login'))

        # Reiniciar intentos fallidos si el login es exitoso
        user.login_failures = 0
        db.session.commit()

        # Verificar si el usuario ya tiene un token y si es válido
        if user.token and Auth.is_valid_token(user, user.token):
            token = user.token
        else:
            # Generar un nuevo token
            token = Auth.generate_token(user.id)

        # Almacena el token en la base de datos si ha cambiado
        if user.token != token:
            user.token = token
            user.token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

        # Crear la respuesta con la cookie del token
        response = make_response(redirect(url_for('main.list_users')))  # Redirigir al listado de usuarios
        response.set_cookie(
            'auth_token',
            token,
            httponly=True,
            secure=current_app.config['ENV'] == 'production',  # Sólo en producción
            samesite='Lax'
        )

        flash('Inicio de sesión exitoso.', 'success')
        return response

    return render_template('login.html')


@auth.route('/logout', methods=['GET', 'POST'])
def logout():
    response = make_response(redirect(url_for('auth.login')))
    response.set_cookie('auth_token', '', expires=0)
    flash('Has cerrado sesión correctamente.', 'success')
    return response

@auth.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form.get('email')
        # Aquí implementa la lógica para manejar el correo
        if email:  # Validar el correo y enviar instrucciones
            flash('Se han enviado las instrucciones a tu correo.', 'success')
        else:
            flash('Por favor, introduce un correo válido.', 'error')
        return redirect(url_for('auth.recover_password'))
    
    return render_template('recover_password.html')

class Auth:
    @staticmethod
    def generate_token(user_id, expiration_hours=1):
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expiration_hours)
        }
        return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            # Caso exitoso: payload válido, sin error
            return payload, None
        except jwt.ExpiredSignatureError:
            # Token expirado
            return None, "El token ha expirado"
        except jwt.InvalidTokenError:
            # Token inválido
            return None, "El token no es válido"

    @staticmethod
    def is_valid_token(user, token):
        if not token:
            return False, "El usuario no tiene un token"

        # Llamar a decode_token (retorna (payload, error))
        decoded, error = Auth.decode_token(token)
        if not decoded:  
            # Significa que es None, hay un error
            return False, error

        # Verificar la expiración adicionalmente, si deseas
        # (Aunque 'jwt.decode' ya lanza un error en jwt.ExpiredSignatureError,
        #  esto te permite un control más granular)
        if datetime.utcnow() > datetime.utcfromtimestamp(decoded.get('exp', 0)):
            return False, "El token ha expirado"

        # Verificar que el token pertenece al usuario
        if user.token != token:
            return False, "El token no coincide con el usuario"

        # Token válido
        return True, "El token es válido"

