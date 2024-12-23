from flask import Blueprint, request, jsonify
from app.models import OAuth2Client, db

admin = Blueprint('admin', __name__)

@admin.route('/register_client', methods=['POST'])
def register_client():
    data = request.json
    client = OAuth2Client(
        client_id=data['client_id'],
        client_secret=data.get('client_secret', 'super_secret_key'),
        redirect_uris=data['redirect_uris'],
        scope=data.get('scope', 'openid profile email'),
        user_id=data.get('user_id', 1)
    )
    db.session.add(client)
    db.session.commit()
    return jsonify({'message': f"Cliente {client.client_id} registrado exitosamente."}), 201
