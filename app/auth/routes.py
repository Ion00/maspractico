from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session, make_response
from flask_login import login_user, logout_user
from app.models import User
from app import redis_client
import jwt
from datetime import datetime, timedelta
from app import db, bcrypt, limiter
from app.auth import auth
from app.auth.utils import generate_recovery_token, verify_token, send_recovery_email


@auth.route('/login', methods=['GET', 'POST'])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"])  # Límite específico
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(correo_e=email).first()

        # Validar usuario y contraseña
        if not user or not bcrypt.check_password_hash(user.clave, password):
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('auth.login'))

        # Verificar si el usuario ya tiene un token
        if not user.token or not Auth.is_valid_token(user, user.token)[0]:
            # Generar un nuevo token si no existe o es inválido
            token = Auth.generate_auth_token(user.id)
            user.token = token
            user.token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

        # Crear la respuesta con la cookie del token
        response = make_response(redirect(url_for('main.list_users')))
        response.set_cookie(
            'auth_token',
            user.token,
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
        user = User.query.filter_by(email=email).first()

        # Registrar el intento de recuperación
        redis_client.incr(f"recover_attempts:{request.remote_addr}")
        redis_client.expire(f"recover_attempts:{request.remote_addr}", 3600)  # Expira en 1 hora

        if user:
            token = generate_recovery_token(user.email)
            recovery_url = url_for('auth.reset_password', token=token, _external=True)
            send_recovery_email(user.email, recovery_url)
            flash('Si el correo está registrado recibirás un email.', 'success')
        else:
            flash('Si el correo está registrado recibirás un email.', 'error')

        return redirect(url_for('auth.recover_password'))

    return render_template('recover_password.html')


@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if not email:
        flash('El enlace de recuperación es inválido o ha caducado.', 'error')
        return redirect(url_for('auth.recover_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_password)  # Asegúrate de tener este método en tu modelo User
            flash('Tu contraseña ha sido cambiada con éxito.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('reset_password.html')

class Auth:
    @staticmethod
    def generate_auth_token(user_id, expiration_hours=1):
        """
        Genera un token JWT para autenticación de usuario.
        
        :param user_id: ID del usuario.
        :param expiration_hours: Duración del token en horas.
        :return: Token JWT codificado.
        """
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expiration_hours)
        }
        return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            return {"valid": True, "payload": payload, "error": None}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "payload": None, "error": "El token ha expirado"}
        except jwt.InvalidTokenError:
            return {"valid": False, "payload": None, "error": "El token no es válido"}

    @staticmethod
    def is_valid_token(user, token):
        result = Auth.decode_token(token)  # Centraliza la decodificación y manejo de errores

        if not result["valid"]:
            return False, result["error"]  # Retorna directamente el mensaje de error

        payload = result["payload"]

        # Verifica si el token pertenece al usuario
        if user.token != token:
            return False, "El token no coincide con el usuario"

        return True, "El token es válido"


