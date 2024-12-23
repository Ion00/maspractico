import json
from app import db
from app.models import OAuth2Client

def register_client(client_id, client_secret, redirect_uris, scope, grant_types, response_types, user_id=None):
    """
    Registra un nuevo cliente OAuth2 en la base de datos.

    :param client_id: Identificador único del cliente.
    :param client_secret: Secreto del cliente (puede ser None si no es necesario).
    :param redirect_uris: Lista de URIs de redirección permitidas.
    :param scope: Alcance (scopes) permitidos.
    :param grant_types: Lista de grant types soportados.
    :param response_types: Lista de response types soportados.
    :param user_id: ID del usuario asociado al cliente (opcional).
    :return: Diccionario con el resultado del registro.
    """
    try:
        # Serializar los valores como JSON
        redirect_uris_json = json.dumps(redirect_uris)
        client_metadata = json.dumps({
            "redirect_uris": redirect_uris,
            "scope": scope,
            "grant_types": grant_types,
            "response_types": response_types
        })

        # Crear una instancia del cliente OAuth2
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=redirect_uris_json,
            client_metadata=client_metadata,
            user_id=user_id
        )

        # Guardar en la base de datos
        db.session.add(client)
        db.session.commit()

        return {
            "success": True,
            "message": "Cliente registrado exitosamente.",
            "client_id": client_id
        }
    except Exception as e:
        db.session.rollback()
        return {
            "success": False,
            "message": f"Error al registrar el cliente: {str(e)}"
        }
