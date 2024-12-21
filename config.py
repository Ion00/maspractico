import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_LOGIN_ATTEMPTS = 5  # Número máximo de intentos fallidos
    LOCKOUT_TIME = 3600  # Tiempo de bloqueo en segundos (1 hora)

class DevelopmentConfig(Config):
    # Configuración específica para desarrollo
    DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DATABASE_URI')
    MAX_LOGIN_ATTEMPTS = 10  # Más permisivo en desarrollo
    LOCKOUT_TIME = 600  # Tiempo de bloqueo reducido (10 minutos)

class ProductionConfig(Config):
    # Configuración específica para producción
    DEBUG = False
    ENV = 'production'
    SQLALCHEMY_DATABASE_URI = os.getenv('PROD_DATABASE_URI')
    MAX_LOGIN_ATTEMPTS = 3  # Más restrictivo en producción
    LOCKOUT_TIME = 7200  # Tiempo de bloqueo extendido (2 horas)

class TestingConfig(Config):
    # Configuración específica para pruebas
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URI')
    MAX_LOGIN_ATTEMPTS = 2
    LOCKOUT_TIME = 300  # Tiempo de bloqueo reducido (5 minutos)
