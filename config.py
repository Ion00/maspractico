import os

class Config:
	SECRET_KEY = os.getenv('SECRET_KEY', '6lNzmdht9oK5E0sLk_3mout2ISn0OZjq-wSHNCFYvCUl8pMqxGNP_kg4nyMLWWUCz_Y6B8-8ItXLQgeQdmwnqBOWek2bSA4VTdlwR6U6nLClvOmePmi-N-ly8vWGJibmPPVIh5D_9F9GIeUePoza10W_3ypCXpXVwMPbNJws40UuGbYnoKp8YVr3o1NFpXKNbRZqTvvNKiePQBwjnZJG7VnG4iI4rbPeQcDNscZ6hhim1mcPVaYUQ0_J3XSAQLTv8zGUuDvwyZLNQs8Ys3qkZ7BBGI6ebEJl8fiE13RJ-rj6GKpW_yNIdWgCkhos2uWlwr7vs8OvRsaf-K9Sf6SlOw')
	SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://maspractico_tiendas:STfkZKnB8!Mdi(on@34.225.83.253/maspractico_tiendas'
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	ENV = 'development'
	DEBUG = True