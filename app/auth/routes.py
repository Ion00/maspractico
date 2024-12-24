from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, session, make_response
from flask_login import login_user, logout_user
from app import db, bcrypt, limiter, redis_client, authorization
from app.models import User, OAuth2Client
from app.auth import auth
from app.auth.utils import generate_recovery_token, verify_token, send_recovery_email
from datetime import datetime, timedelta
import jwt, json

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

        # Guardar el user_id en la sesión
        session['user_id'] = user.id

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


@auth.route('/authorize', methods=['GET', 'POST'])
def authorize():
    client_id = request.args.get('client_id')
    response_type = request.args.get('response_type')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')

    # Validar el cliente
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if not client:
        return jsonify({'error': 'Cliente no encontrado'}), 400

    if isinstance(client.client_metadata, str):
        client_metadata = json.loads(client.client_metadata)
    else:
        client_metadata = client.client_metadata

    # **Deserializar `client_metadata` y `redirect_uris`**
    try:
        redirect_uris = json.loads(client.redirect_uris)
    except json.JSONDecodeError as e:
        return jsonify({
        'error': f"Error en con redireCTS URI: "
                 f"client_metadata: {client.client_metadata}, "
                 f"redirect_uris: {client.redirect_uris}"
    }), 500

    # Validar redirect_uri
    if redirect_uri not in redirect_uris:
        return jsonify({'error': 'URI de redirección no válida'}), 400

    # Validar response_type
    supported_response_types = client_metadata.get('response_types', [])
    if response_type not in supported_response_types:
        return jsonify({'error': 'unsupported_response_type'}), 400

    # Obtener el usuario autenticado
    user_id = session.get('user_id')
    if not user_id:
        session['next_url'] = request.url
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    if request.method == 'GET':
        return render_template(
            'authorize.html',
            client_id=client_id,
            scope=scope,
            redirect_uri=redirect_uri
        )

    if request.form.get('confirm') == 'yes':
        # Crear la respuesta de autorización para el flujo implícito
        if response_type == 'token':
            return authorization.create_authorization_response(grant_user=user)

    return jsonify({'error': 'Autorización denegada'}), 403



@auth.route('/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


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


