import os

class Config:
    DEBUG = True # Debug false por defecto
    # Claves sensibles y configuración común
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')  # Valor por defecto para desarrollo
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Configuración de Flask-Limiter (común)
    REDIS_URI = os.getenv('REDIS_URI', 'redis://localhost:6379')
    REDIS_SOCKET_TIMEOUT = int(os.getenv('REDIS_SOCKET_TIMEOUT', 30))
    # Intentos de login y bloqueo
    DEFAULT_RATE_LIMIT = "100 per hour"  # Límite global
    LOGIN_RATE_LIMIT = "5 per minute"  # Límite específico para login
    REGISTER_RATE_LIMIT = "10 per minute"  # Límite específico para registro

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DATABASE_URI', 'sqlite:///dev.db')
    DEFAULT_RATE_LIMIT = "10 per minute"  # Límite más permisivo para desarrollo

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'
    SQLALCHEMY_DATABASE_URI = os.getenv('PROD_DATABASE_URI')
    DEFAULT_RATE_LIMIT = "5 per minute"  # Límite más restrictivo para producción

class TestingConfig(Config):
    TESTING = True
    ENV = 'testing'
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URI', 'sqlite:///test.db')
    DEFAULT_RATE_LIMIT = "20 per minute"  # Límite más relajado para pruebas
