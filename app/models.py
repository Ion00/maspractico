from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from app import db, bcrypt
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

class User(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    correo_e = db.Column(db.String(120), unique=True, nullable=False)
    clave = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(500), nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean(), nullable=True)
    login_failures = db.Column(db.Integer, nullable=False, default=0)

    # Crear un nuevo usuario
    @staticmethod
    def create_user(email, password):
        try:
            # Verificar si el correo electrónico ya existe
            if User.query.filter_by(correo_e=email).first():
                raise ValueError("El correo electrónico ya está registrado.")
            
            # Hashear la contraseña
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(correo_e=email, clave=hashed_password)
            
            # Agregar el usuario a la base de datos dentro de una transacción
            db.session.add(new_user)
            db.session.commit()
            return new_user
        except IntegrityError:
            db.session.rollback()
            raise ValueError("Error de integridad en la base de datos. El correo ya puede estar registrado.")
        except SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError(f"Error en la base de datos: {str(e)}")
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error al crear el usuario: {str(e)}")

    # Leer un usuario por ID
    @staticmethod
    def get_user_by_id(user_id):
        try:
            user = User.query.get(user_id)
            if user is None:
                raise ValueError("Usuario no encontrado.")
            return user
        except SQLAlchemyError as e:
            raise ValueError(f"Error al consultar la base de datos: {str(e)}")


    # Leer todos los usuarios
    @staticmethod
    def get_all_users():
        try:
            return User.query.all()
        except SQLAlchemyError as e:
            raise ValueError(f"Error al consultar la base de datos: {str(e)}")

    # Actualizar un usuario
    def update_user(self, email=None, password=None):
        try:
            if email:
                self.email = email
            if password:
                self.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            return self
        except IntegrityError:
            db.session.rollback()
            raise ValueError("Error de integridad en la base de datos.")
        except SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError(f"Error al actualizar la base de datos: {str(e)}")
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error al actualizar el usuario: {str(e)}")

    # Eliminar un usuario
    def delete_user(self):
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError(f"Error al eliminar el usuario en la base de datos: {str(e)}")
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error al eliminar el usuario: {str(e)}")
