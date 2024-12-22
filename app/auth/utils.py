from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_mail import Message
from app import mail  # Asegúrate de inicializar Flask-Mail en app/__init__.py

# En utils.py
def generate_recovery_token(email):
    """
    Genera un token seguro para recuperación de contraseña.
    
    :param email: Correo electrónico del usuario.
    :return: Token seguro codificado.
    """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-recovery-salt')


def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-recovery-salt', max_age=expiration)
        return email
    except Exception:
        return None

def send_recovery_email(user_email, recovery_url):
    msg = Message('Recuperación de Contraseña',
                  sender=current_app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'Haz clic en el siguiente enlace para recuperar tu contraseña: {recovery_url}'
    mail.send(msg)
