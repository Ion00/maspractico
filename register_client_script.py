from app.models import OAuth2Client
from app import db, create_app
import json
from datetime import datetime, timedelta

app = create_app()

with app.app_context():
    try:
        current_time = int(datetime.utcnow().timestamp())
        new_client = OAuth2Client(
            client_id="soldelluvia-1357",
            client_secret=None,
            redirect_uris=json.dumps(["https://901a22ddb9dbdb8.maspracti.co/auth_oauth/signin"]),
            scope="openid profile email",
            user_id=1,
            client_id_issued_at=current_time,
            client_secret_expires_at=current_time + int(timedelta(days=365).total_seconds())  # Expira en 1 año
        )
        new_client.client_metadata = {
            "response_types": ["token"],
            "grant_types": ["implicit"],
            "client_auth_methods": ["none"]
        }
        db.session.add(new_client)
        db.session.commit()
        print("Cliente registrado exitosamente.")
    except Exception as e:
        print(f"Error al registrar el cliente: {e}")
