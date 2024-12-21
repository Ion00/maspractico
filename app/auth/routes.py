from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session, make_response
from flask_login import login_user, logout_user
from app.models import User
from app import redis_client
import jwt
from datetime import datetime, timedelta
from app import db, bcrypt  # Asegúrate de que bcrypt esté importado desde __init__.py
from app.auth import auth, MAX_LOGIN_ATTEMPTS
from app.auth.utils import generate_token, send_recovery_email

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 3600  # 1 hora en segundos


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        client_ip = request.remote_addr  # Obtener la IP del cliente

        # Verificar intentos fallidos por IP
        ip_attempts_key = f"failed_attempts_ip:{client_ip}"
        ip_attempts = redis_client.get(ip_attempts_key)  # Obtener el valor actual

        if ip_attempts and int(ip_attempts) >= MAX_LOGIN_ATTEMPTS:
            flash('Demasiados intentos fallidos desde esta IP. Por favor, intenta más tarde.', 'danger')
            return redirect(url_for('auth.login'))

        # Verificar intentos fallidos por correo
        email_attempts_key = f"failed_attempts_email:{email}"
        email_attempts = redis_client.get(email_attempts_key)  # Obtener el valor actual

        if email_attempts and int(email_attempts) >= MAX_LOGIN_ATTEMPTS:
            flash('Demasiados intentos fallidos para este correo. Por favor, intenta más tarde.', 'danger')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(correo_e=email).first()

        # Validar usuario y contraseña
        if not user or not bcrypt.check_password_hash(user.clave, password):
            # Incrementar intentos fallidos en Redis
            redis_client.incr(ip_attempts_key)
            redis_client.expire(ip_attempts_key, LOCKOUT_TIME)  # Establecer tiempo de bloqueo

            redis_client.incr(email_attempts_key)
            redis_client.expire(email_attempts_key, LOCKOUT_TIME)

            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('auth.login'))

        # Reiniciar intentos fallidos al iniciar sesión con éxito
        redis_client.delete(ip_attempts_key)
        redis_client.delete(email_attempts_key)

        # Registrar ultima ip de logeo TODO
        if user:
            user.login_failures = 0
            db.session.commit()

        # Verificar si el usuario ya tiene un token y si es válido
        if user.token:
            # Validar si el token es válido
            is_valid, error_message = Auth.is_valid_token(user, user.token)

            if not is_valid:
                # El token no es válido (expirado o incorrecto)
                flash(error_message, 'warning')
                # Generar un nuevo token
                token = Auth.generate_token(user.id)
            else:
                # Token válido
                token = user.token
        else:
            # No hay token, generar uno nuevo
            token = Auth.generate_token(user.id)

        # Almacenar el nuevo token en la base de datos
        if user.token != token:
            user.token = token
            user.token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

        # Mensaje coherente para el flujo exitoso
        flash('Inicio de sesión exitoso.', 'success')

        # Crear la respuesta con la cookie del token
        response = make_response(redirect(url_for('main.list_users')))
        response.set_cookie(
            'auth_token',
            token,
            httponly=True,
            secure=current_app.config['ENV'] == 'production',  # Sólo en producción
            samesite='Lax'
        )

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

        if user:
            token = generate_token(user.email)
            recovery_url = url_for('auth.reset_password', token=token, _external=True)
            send_recovery_email(user.email, recovery_url)
            flash('Se ha enviado un enlace de recuperación a tu correo.', 'success')
        else:
            flash('El correo no está registrado.', 'error')

        return redirect(url_for('auth.recover_password'))

    return render_template('recover_password.html')


@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Validar el token y permitir el cambio de contraseña
    from app.auth.utils import verify_token

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

