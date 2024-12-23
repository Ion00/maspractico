from app import create_app, db
from app.utils import register_client

app = create_app()

with app.app_context():
    result = register_client(
        client_id="example-client",
        client_secret="example-secret",
        redirect_uris=["https://example.com/auth/callback"],
        scope="openid profile email",
        grant_types=["implicit"],
        response_types=["token"],
        user_id=1
    )
    print(result)

