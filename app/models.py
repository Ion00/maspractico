from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from app import db, bcrypt
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import relationship
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    correo_e = db.Column(db.String(120), unique=True, nullable=False)
    clave = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(500), nullable=True)  # Token de autenticación
    token_expiration = db.Column(db.DateTime, nullable=True)  # Fecha de expiración del token
    active = db.Column(db.Boolean(), nullable=True, default=True)
    login_failures = db.Column(db.Integer, nullable=False, default=0)

    @staticmethod
    def create_user(email, password):
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(correo_e=email, clave=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return new_user
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error al crear el usuario: {str(e)}")


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Clave primaria
    client_id = db.Column(db.String(40), unique=True, nullable=False)  # ID único del cliente
    client_secret = db.Column(db.String(55), nullable=False)  # Secreto del cliente
    redirect_uris = db.Column(db.Text, nullable=False)  # URI de redirección permitido
    scope = db.Column(db.String(255), default='')  # Alcances solicitados
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id', ondelete='CASCADE'))


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'o_auth2_token'  # Define el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Agrega una clave primaria
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id', ondelete='CASCADE'))
    user = relationship('User')

