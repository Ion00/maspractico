from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from app import db, bcrypt
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import relationship
from datetime import datetime
import json

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

    def get_user_id(self):
        """
        Devuelve el ID único del usuario.
        """
        return self.id


class OAuth2Client(db.Model):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(255), nullable=False, unique=True)
    client_secret = db.Column(db.String(255), nullable=True)
    redirect_uris = db.Column(db.Text, nullable=False)
    scope = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    client_id_issued_at = db.Column(db.Integer, default=lambda: int(datetime.utcnow().timestamp()), nullable=False)
    client_secret_expires_at = db.Column(db.Integer, nullable=True)
    _client_metadata = db.Column("client_metadata", db.Text, nullable=True)
    
    # Propiedad para manejar client_metadata
    @property
    def client_metadata(self):
        return json.loads(self._client_metadata)

    @client_metadata.setter
    def client_metadata(self, value):
        self._client_metadata = json.dumps(value)

    def check_endpoint_auth_method(self, method, endpoint):
        """
        Valida si el cliente soporta el método de autenticación especificado.
        :param method: Método de autenticación (por ejemplo, "client_secret_basic").
        :param endpoint: Endpoint donde se verifica el método (por ejemplo, "token").
        :return: True si es compatible, False en caso contrario.
        """
        # Obtenemos los métodos soportados desde client_metadata
        client_auth_methods = self.client_metadata.get("client_auth_methods", ["none"])
        
        # Si no se define explícitamente, se asume que soporta "none" para el flujo implícito
        return method in client_auth_methods

    def check_redirect_uri(self, redirect_uri):
        """
        Verifica si la URI de redirección proporcionada es válida para este cliente.
        :param redirect_uri: URI de redirección proporcionada en la solicitud.
        :return: True si la URI es válida, False en caso contrario.
        """
        # Deserializar las URIs registradas
        registered_uris = json.loads(self.redirect_uris)

        # Verificar si la URI proporcionada está en las URIs registradas
        return redirect_uri in registered_uris

    def check_response_type(self, response_type):
        """
        Verifica si el tipo de respuesta proporcionado es compatible con el cliente.
        :param response_type: Tipo de respuesta (por ejemplo, 'token', 'code').
        :return: True si es compatible, False en caso contrario.
        """
        # Deserializar client_metadata para obtener los tipos de respuesta admitidos
        metadata = json.loads(self._client_metadata) if self._client_metadata else {}
        supported_response_types = metadata.get('response_types', [])
        return response_type in supported_response_types

    def get_allowed_scope(self, scope):
        """
        Valida y filtra los scopes solicitados en función de los permisos del cliente.
        
        :param scope: Scopes solicitados (cadena de texto separada por espacios).
        :return: Scopes permitidos (cadena de texto separada por espacios).
        """
        # Obtener los scopes permitidos para este cliente
        allowed_scopes = set(self.scope.split()) if self.scope else set()
        # Obtener los scopes solicitados
        requested_scopes = set(scope.split()) if scope else set()

        # Determinar la intersección de los scopes solicitados y permitidos
        valid_scopes = requested_scopes & allowed_scopes

        # Retornar los scopes permitidos como una cadena separada por espacios
        return " ".join(valid_scopes)



class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'o_auth2_token'  # Define el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Agrega una clave primaria
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id', ondelete='CASCADE'))
    user = relationship('User')

